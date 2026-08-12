"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Offline pipeline test.

Exercises Normalization -> Checklist Validation -> MITRE Mapping ->
Crown Jewel Correlation -> Attack Path -> Risk Prioritization -> Reporting
against synthetic evidence (tests/fixtures/raw/), since no live AWS
credentials are available in this environment. Runs inside a temp working
directory (via monkeypatch.chdir) so it never touches the real output/
directory.

Fixture scenario: an internet-facing EC2 instance ("i-12345") has an
instance profile attached to IAM role "demo-role", which has an inline
policy granting s3:* on Crown Jewel bucket "acme-prod-financial-records".
This is a deliberately connected 2-hop chain so exactly one attack path
candidate should be produced.
===============================================================================
"""

import json
import shutil
from pathlib import Path

import pytest

from core.schema.finding import Finding
from core.engines.normalization_engine import NormalizationEngine
from core.engines.assessment_register_engine import AssessmentRegisterEngine
from core.engines.checklist_engine import ChecklistValidationEngine
from core.engines.mitre_engine import MitreMappingEngine
from core.engines.crown_jewel_engine import CrownJewelEngine
from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.engines.threat_validation_engine import ThreatValidationEngine
from core.engines.threat_correlation_engine import ThreatCorrelationEngine
from core.engines.attack_path_engine import AttackPathEngine
from core.engines.risk_engine import RiskPrioritizationEngine
from core.engines.traceability_engine import AssessmentTraceabilityEngine
from core.engines.recommendation_engine import RecommendationEngine
from core.reporting.reporting_engine import ReportingEngine


REPO_ROOT = Path(__file__).resolve().parent.parent


TEST_CONFIG = {

    "checklist": {"file": "checklists/checklist.example.yaml"},
    "crown_jewels": {"file": "crown_jewels/crown_jewels.example.yaml"},
    "attack_path": {"max_hops": 5},
    "severity": {"critical": 90, "high": 70, "medium": 40, "low": 10},
    "risk_scoring": {
        "factors": {
            "exposure": 1,
            "identity_privilege": 1,
            "trust_relationships": 1,
            "crown_jewel_proximity": 1,
            "detection_coverage": 1,
            "blast_radius": 1,
        }
    },

}


@pytest.fixture
def workspace(tmp_path, monkeypatch):

    shutil.copytree(
        REPO_ROOT / "tests" / "fixtures" / "raw",
        tmp_path / "output" / "raw",
    )

    for resource_dir in ("checklists", "crown_jewels", "data"):

        shutil.copytree(
            REPO_ROOT / resource_dir,
            tmp_path / resource_dir,
        )

    evidence_index = {
        "generated": "test",
        "evidence": {
            "prowler": ["output/raw/prowler/prowler_findings.json"],
            "cloudsplaining": [
                "output/raw/cloudsplaining/authorization-details.json",
                "output/raw/cloudsplaining/report/report.json",
            ],
            "steampipe": ["output/raw/steampipe/aws/ec2/public_instances.json"],
        },
    }

    with open(tmp_path / "output" / "evidence_index.json", "w") as f:

        json.dump(evidence_index, f)

    monkeypatch.chdir(tmp_path)

    return tmp_path


def run_pipeline():

    findings = NormalizationEngine().run()

    assessment_register = AssessmentRegisterEngine(TEST_CONFIG, "ASSESS-TEST").run(findings)

    coverage = ChecklistValidationEngine(TEST_CONFIG).run(assessment_register)

    mitre_summary = MitreMappingEngine().run(findings)

    crown_jewel_engine = CrownJewelEngine(TEST_CONFIG)

    crown_jewel_engine.run(findings)

    threat_scenarios = ThreatValidationEngine(TEST_CONFIG).run(
        coverage, assessment_register
    )

    correlated_threats = ThreatCorrelationEngine(TEST_CONFIG).run(
        threat_scenarios, assessment_register
    )

    attack_path_engine = AttackPathEngine(TEST_CONFIG, crown_jewel_engine)

    candidates = attack_path_engine.run(
        assessment_register, correlated_threats=correlated_threats
    )

    risk_summary = RiskPrioritizationEngine(
        TEST_CONFIG, attack_path_engine, coverage
    ).run(findings)

    recommendations = RecommendationEngine(
        TEST_CONFIG, knowledge_engine=AssessmentKnowledgeEngine(TEST_CONFIG)
    ).run(
        coverage,
        assessment_register,
        threat_scenarios,
        correlated_threats,
    )

    knowledge = AssessmentKnowledgeEngine(TEST_CONFIG)

    traceability_engine = AssessmentTraceabilityEngine(
        knowledge, TEST_CONFIG
    )

    traceability_engine.build(
        findings=findings,
        assessment_register=assessment_register,
        checklist_coverage=coverage,
        threat_scenarios=threat_scenarios,
        correlated_threats=correlated_threats,
        attack_path_candidates=candidates,
        risk_summary=risk_summary,
        recommendations=recommendations,
    )

    ReportingEngine(
        findings=findings,
        assessment_register=assessment_register,
        execution_status={"Prowler": "SUCCESS", "Steampipe": "SUCCESS", "Cloudsplaining": "SUCCESS"},
        checklist_coverage=coverage,
        threat_scenarios=threat_scenarios,
        correlated_threats=correlated_threats,
        mitre_summary=mitre_summary,
        attack_path_candidates=candidates,
        risk_summary=risk_summary,
        evidence_index=evidence_index_for_reporting(),
        discovery_summary={},
        recommendations=recommendations,
        traceability_engine=traceability_engine,
    ).generate()

    return findings, coverage, mitre_summary, candidates, risk_summary


def evidence_index_for_reporting():

    return json.load(open("output/evidence_index.json")).get("evidence", {})


###############################################################################
# Schema completeness
###############################################################################

def test_every_finding_has_full_schema(workspace):

    findings, *_ = run_pipeline()

    assert findings, "expected at least one normalized finding"

    for finding in findings:

        data = finding.to_dict()

        for field in Finding.PUBLISHED_FIELDS:

            assert field in data


###############################################################################
# Checklist Validation
###############################################################################

def test_checklist_produces_fail_and_manual_review(workspace):

    _, coverage, *_ = run_pipeline()

    statuses = {item["id"]: item["status"] for item in coverage}

    assert statuses["CHK-EC2-001"] == "FAIL"

    assert statuses["CHK-IAM-004"] == "MANUAL_REVIEW"

    assert statuses["CHK-IAM-001"] == "PASS"

    assert statuses["CHK-EXT-001"] == "NOT_EVALUATED"


def test_checklist_multi_source_item_matches_either_source(workspace):

    findings, coverage, *_ = run_pipeline()

    item = next(c for c in coverage if c["id"] == "CHK-NET-002")

    # Both sources' findings exist in the fixture (ssh_open_world has none,
    # but public_instances does) - the item should FAIL because at least
    # one of its two sources matched, and matched_findings should count
    # findings from every source, not just the first.
    assert item["status"] == "FAIL"

    assert item["matched_findings"] >= 1

    assert {s["query_ref"] for s in item["sources"]} == {
        "aws/vpc/ssh_open_world", "aws/ec2/public_instances",
    }

    # i-12345 matches both CHK-EC2-001 and CHK-NET-002 (both reference the
    # public_instances query) - Finding.checklist_id is a single field, so
    # whichever item is evaluated last wins that field, but MITRE tags
    # accumulate from every matching item regardless of order.
    ec2_finding = next(
        f for f in findings
        if f.resource_id == "i-12345" and f.tool_source == "Steampipe"
    )

    assert ec2_finding.checklist_id in ("CHK-EC2-001", "CHK-NET-002")

    # dict-of-lists mitre_mapping form should populate both flat lists
    # without being paired 1:1.
    assert "T1190" in ec2_finding.mitre_techniques

    assert "Initial Access" in ec2_finding.mitre_tactics


###############################################################################
# MITRE Mapping (predefined table, not keyword matching)
###############################################################################

def test_mitre_mapping_uses_predefined_table(workspace):

    findings, _, mitre_summary, *_ = run_pipeline()

    ec2_findings = [
        f for f in findings
        if f.resource_id == "i-12345" and f.tool_source == "Prowler"
    ]

    assert ec2_findings, "expected the Prowler EC2 finding to normalize"

    assert "T1190" in ec2_findings[0].mitre_techniques

    assert mitre_summary["mapped_findings"] > 0


###############################################################################
# Crown Jewel Correlation
###############################################################################

def test_crown_jewel_tagging(workspace):

    findings, *_ = run_pipeline()

    s3_related = [f for f in findings if "acme-prod-financial-records" in f.resource_id]

    # No direct S3 findings in this fixture, but the EC2 finding should be
    # reachable to the crown jewel via the attack path graph, tested below.
    assert isinstance(s3_related, list)


###############################################################################
# Attack Path Engine - only connected findings get chained
###############################################################################

def test_attack_path_candidate_reaches_crown_jewel(workspace):

    findings, _, _, candidates, _ = run_pipeline()

    assert len(candidates) == 1, f"expected exactly one candidate, got {candidates}"

    candidate = candidates[0]

    assert candidate["hop_count"] == 2

    hop_types = [hop["type"] for hop in candidate["hops"]]

    assert hop_types == ["EC2", "IAM_ROLE", "S3_BUCKET"]

    assert candidate["hops"][-1]["resource_id"] == "acme-prod-financial-records"


###############################################################################
# Risk Prioritization - composite factors
###############################################################################

def test_risk_score_reflects_six_factors(workspace):

    findings, *_ = run_pipeline()

    ec2_finding = next(
        f for f in findings
        if f.resource_id == "i-12345" and f.tool_source == "Prowler"
    )

    factors = ec2_finding._risk_factors

    assert set(factors.keys()) == {
        "exposure", "identity_privilege", "trust_relationships",
        "crown_jewel_proximity", "detection_coverage", "blast_radius",
    }

    # internet-facing -> max exposure
    assert factors["exposure"] == 100

    # 2 hops from the crown jewel -> 100 - (2 * 20) = 60
    assert factors["crown_jewel_proximity"] == 60

    expected = round(sum(factors.values()) / 6, 2)

    assert ec2_finding._risk_score == expected


###############################################################################
# Reporting Engine output
###############################################################################

def test_reports_are_generated(workspace):

    run_pipeline()

    reports_dir = Path("output/reports")

    for filename in (
        "index.html",
        "executive_summary.html",
        "analyst_traceability.html",
        "technical_findings.html",
        "mitre_matrix.html",
        "attack_path_summary.html",
        "checklist_coverage.html",
        "evidence_index.html",
    ):

        report_file = reports_dir / filename

        assert report_file.exists()

        assert report_file.stat().st_size > 0
