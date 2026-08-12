"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Risk Prioritization Engine

Methodology step: Risk Prioritization.

Purpose
-------
Risk is not severity alone. Every Finding gets a composite 0-100 risk score
built from six factors, each independently 0-100 and combined via
configurable weights (config.yaml -> risk_scoring.factors):

  Exposure            is the resource internet-facing (Finding.internet_facing)
  Identity Privilege   how dangerous is the IAM privilege involved
                       (Cloudsplaining-sourced findings score highest)
  Trust Relationships   ASSUME_ROLE / CAN_ACCESS edge count on the resource's
                       Attack Path graph node
  Crown Jewel Proximity graph distance to the nearest Crown Jewel
                       (from the Attack Path Engine)
  Detection Coverage    account/assessment-wide gap in logging/monitoring
                       controls (CloudTrail/GuardDuty/Config checklist
                       results) - a systemic property, not per-resource
  Blast Radius          out-degree of the resource's Attack Path graph node
                       (how many other resources it can reach)

The composite score is stored on the Finding as an internal field
(_risk_score / _risk_factors) rather than overwriting the tool-assigned
`severity` - Risk Prioritization is an additional triage signal layered on
top of, not a replacement for, the finding's native severity.

READ ONLY

===============================================================================
"""

import json
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine


console = Console()

DEFAULT_WEIGHTS = {

    "exposure": 1,
    "identity_privilege": 1,
    "trust_relationships": 1,
    "crown_jewel_proximity": 1,
    "detection_coverage": 1,
    "blast_radius": 1,

}

CLOUDSPLAINING_PRIVILEGE_SCORES = {

    "PrivilegeEscalation": 100,
    "CredentialsExposure": 100,
    "DataExfiltration": 90,
    "ServiceWildcard": 85,
    "ResourceExposure": 70,

}

STEAMPIPE_PRIVILEGE_SCORES = {

    "aws/iam/wildcard_permissions": 90,
    "aws/iam/admin_users": 80,
    "aws/iam/roles_without_mfa": 60,
    "aws/iam/mfa_disabled_users": 60,
}


class RiskPrioritizationEngine:

    def __init__(self, config, attack_path_engine, checklist_coverage=None, knowledge_engine=None):

        self.config = config

        self.attack_path_engine = attack_path_engine
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)

        self.checklist_coverage = checklist_coverage or []

        self.weights = {
            **DEFAULT_WEIGHTS,
            **config.get("risk_scoring", {}).get("factors", {}),
        }

        self.severity_thresholds = config.get("severity", {
            "critical": 90, "high": 70, "medium": 40, "low": 10
        })

        self.output_directory = Path("output/risk")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.detection_gap_score = self.knowledge.detection_gap_score(self.checklist_coverage)

    ###########################################################################
    # Detection Coverage (assessment-wide)
    ###########################################################################

    def compute_detection_gap(self):
        return self.knowledge.detection_gap_score(self.checklist_coverage)

    ###########################################################################
    # Per-finding graph lookups
    ###########################################################################

    def graph_node(self, finding):

        graph = self.attack_path_engine.graph

        index = self.attack_path_engine.resource_index

        node_id = index.get(finding.resource_id) or index.get(finding.resource_name)

        if node_id and graph.has_node(node_id):

            return node_id

        return None

    def trust_relationship_score(self, finding):

        node_id = self.graph_node(finding)

        if not node_id:

            return 0

        graph = self.attack_path_engine.graph

        count = 0

        for _, _, data in graph.out_edges(node_id, data=True):

            if data.get("relationship") in ("ASSUME_ROLE", "CAN_ACCESS"):

                count += 1

        for _, _, data in graph.in_edges(node_id, data=True):

            if data.get("relationship") in ("ASSUME_ROLE", "CAN_ACCESS"):

                count += 1

        return min(100, count * 25)

    def blast_radius_score(self, finding):

        node_id = self.graph_node(finding)

        if not node_id:

            return 0

        out_degree = self.attack_path_engine.graph.out_degree(node_id)

        return min(100, out_degree * 20)

    ###########################################################################
    # Factor scoring
    ###########################################################################

    def exposure_score(self, finding):

        if finding.internet_facing == "Yes":

            return 100

        if finding.internet_facing == "No":

            return 10

        return 40

    def identity_privilege_score(self, finding):

        check_id = getattr(finding, "_tool_check_id", None)

        if finding.tool_source == "Cloudsplaining":

            return CLOUDSPLAINING_PRIVILEGE_SCORES.get(check_id, 60)

        if finding.tool_source == "Steampipe" and check_id in STEAMPIPE_PRIVILEGE_SCORES:

            return STEAMPIPE_PRIVILEGE_SCORES[check_id]

        return 20

    def crown_jewel_proximity_score(self, finding):

        proximity = finding._crown_jewel_proximity

        if proximity is None:

            return 0

        return max(0, 100 - (proximity * 20))

    ###########################################################################
    # Composite score
    ###########################################################################

    def score_finding(self, finding):

        factors = {

            "exposure": self.exposure_score(finding),
            "identity_privilege": self.identity_privilege_score(finding),
            "trust_relationships": self.trust_relationship_score(finding),
            "crown_jewel_proximity": self.crown_jewel_proximity_score(finding),
            "detection_coverage": self.detection_gap_score,
            "blast_radius": self.blast_radius_score(finding),

        }

        total_weight = sum(self.weights.values()) or 1

        composite = sum(
            factors[name] * self.weights.get(name, 1)
            for name in factors
        ) / total_weight

        finding._risk_factors = factors
        finding._risk_score = round(composite, 2)

        return finding

    def risk_severity(self, score):

        if score >= self.severity_thresholds.get("critical", 90):

            return "CRITICAL"

        if score >= self.severity_thresholds.get("high", 70):

            return "HIGH"

        if score >= self.severity_thresholds.get("medium", 40):

            return "MEDIUM"

        if score >= self.severity_thresholds.get("low", 10):

            return "LOW"

        return "INFO"

    ###########################################################################
    # Summary
    ###########################################################################

    def build_summary(self, findings):

        summary = {

            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "detection_gap_score": self.detection_gap_score,

        }

        total = 0

        for finding in findings:

            bucket = self.risk_severity(finding._risk_score).lower()

            summary[bucket] += 1

            total += finding._risk_score

        summary["average_risk_score"] = round(total / len(findings), 2) if findings else 0

        summary["security_posture_score"] = max(
            0, round(100 - summary["average_risk_score"], 2)
        )

        return summary

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, findings, summary):

        with open(self.output_directory / "risk_findings.json", "w") as f:

            json.dump(
                [f.to_dict(include_internal=True) for f in findings],
                f,
                indent=4,
                default=str,
            )

        with open(self.output_directory / "risk_summary.json", "w") as f:

            json.dump(summary, f, indent=4)

    ###########################################################################
    # Run
    ###########################################################################

    def run(self, findings):

        console.rule(
            "[bold cyan]Risk Prioritization"
        )

        for finding in findings:

            self.score_finding(finding)

        summary = self.build_summary(findings)

        self.save(findings, summary)

        logger.success(
            f"Security Posture Score : {summary['security_posture_score']}/100"
        )

        console.print(
            f"[green]Security Posture Score : {summary['security_posture_score']}/100[/green]"
        )

        console.print(
            f"[red]Critical : {summary['critical']}[/red]  "
            f"[yellow]High : {summary['high']}[/yellow]  "
            f"[cyan]Medium : {summary['medium']}[/cyan]  "
            f"[green]Low : {summary['low']}[/green]"
        )

        return summary
