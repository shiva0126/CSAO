from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from core.file_utils import load_json_with_recovery
from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.engines.assessment_register_engine import AssessmentRegisterEngine
from core.engines.attack_path_engine import AttackPathEngine
from core.engines.checklist_engine import ChecklistValidationEngine
from core.engines.crown_jewel_engine import CrownJewelEngine
from core.engines.discovery_engine import DiscoveryEngine
from core.engines.evidence_engine import EvidenceCollectionEngine
from core.engines.mitre_engine import MitreMappingEngine
from core.engines.normalization_engine import NormalizationEngine
from core.engines.recommendation_engine import RecommendationEngine
from core.engines.risk_engine import RiskPrioritizationEngine
from core.engines.threat_correlation_engine import ThreatCorrelationEngine
from core.engines.threat_validation_engine import ThreatValidationEngine
from core.engines.traceability_engine import AssessmentTraceabilityEngine
from core.providers.registry import get_provider
from core.reporting.reporting_engine import ReportingEngine

# Same 14 stages as the pre-Phase-2 AssessmentRunner.STAGES -- moved here so
# both callers (CLI main.py, web control_plane.py via the ARQ worker) share
# one definition instead of two.
STAGES = [
    ("discovery", "Cloud Discovery"),
    ("inventory", "Asset Inventory"),
    ("crown_jewel", "Crown Jewel Identification"),
    ("evidence_collection", "Evidence Collection"),
    ("normalization", "Normalization"),
    ("assessment_register", "Assessment Register"),
    ("checklist_validation", "Checklist Validation"),
    ("threat_validation", "Threat Validation"),
    ("threat_correlation", "Threat Correlation"),
    ("attack_paths", "Attack Path Generation"),
    ("risk_prioritization", "Risk Prioritization"),
    ("recommendations", "Recommendations"),
    ("traceability", "Traceability"),
    ("reporting", "Reporting"),
]


class CancelledError(RuntimeError):
    """Raised when cancel_check() reports a cancellation request between
    stages. Message format ("CANCELLED: <checkpoint>") matches the
    pre-Phase-2 convention so callers can keep distinguishing a clean
    cancel from a real failure by string prefix, unchanged."""


def _resource_count(discovery_summary: Dict[str, Any]) -> int:
    counts = discovery_summary.get("resource_counts", {}) or {}
    return sum(counts.values())


def _default_stage_hook(
    stage_key: str,
    status: str,
    current_collector: str = "",
    current_api: str = "",
    resources_processed: Optional[int] = None,
) -> None:
    return None


def _default_cancel_check() -> bool:
    return False


@dataclass
class PipelineResult:
    findings: list = field(default_factory=list)
    assessment_register: list = field(default_factory=list)
    filtered_findings: list = field(default_factory=list)
    filtered_register: list = field(default_factory=list)
    checklist_coverage: list = field(default_factory=list)
    threat_scenarios: list = field(default_factory=list)
    correlated_threats: list = field(default_factory=list)
    attack_path_candidates: list = field(default_factory=list)
    risk_summary: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)
    mitre_summary: dict = field(default_factory=dict)
    discovery_summary: dict = field(default_factory=dict)
    execution_status: dict = field(default_factory=dict)
    evidence_index: dict = field(default_factory=dict)
    report_files: list = field(default_factory=list)
    traceability_engine: Any = None
    knowledge: Any = None


def run_pipeline(
    config: Dict[str, Any],
    assessment_id: str,
    *,
    stage_hook: Callable[..., None] = _default_stage_hook,
    cancel_check: Callable[[], bool] = _default_cancel_check,
    validations: Optional[Dict[str, Any]] = None,
    assessment_metadata: Optional[Dict[str, Any]] = None,
) -> PipelineResult:
    """The 14-stage assessment pipeline, shared by the CLI (main.py) and the
    web control plane's background runner (workbench/control_plane.py, via
    the ARQ worker). Faithful extraction of the engine-calling sequence that
    previously existed twice, independently, in both callers.

    `stage_hook(stage_key, status, current_collector="", current_api="",
    resources_processed=None)` matches AssessmentRunner._mark_stage's exact
    signature -- the web caller passes that method directly. The CLI caller
    passes a small adapter that prints Rich console output instead.

    `cancel_check()` is also set into `config["_cancel_check"]` so
    core/base_module.py's existing subprocess-level cancellation (used by
    collectors that shell out to external tools) keeps working exactly as
    before -- this was already a real mechanism prior to Phase 2, not
    something new introduced here.
    """
    config["_cancel_check"] = cancel_check

    def checkpoint(label: str) -> None:
        if cancel_check():
            raise CancelledError(f"CANCELLED: {label}")

    result = PipelineResult()

    knowledge = AssessmentKnowledgeEngine(config)
    result.knowledge = knowledge
    provider = get_provider(config)
    if not provider.authenticate():
        raise RuntimeError("AWS credential binding failed for the selected cloud account.")
    cli_env = provider.exported_credentials()
    if config.get("aws", {}).get("regions"):
        cli_env["AWS_DEFAULT_REGION"] = config["aws"]["regions"][0]
        cli_env["AWS_REGION"] = config["aws"]["regions"][0]
    config["_aws_cli_env"] = cli_env

    checkpoint("before discovery")
    stage_hook("discovery", "RUNNING", current_collector="provider", current_api="sts:GetCallerIdentity")
    result.discovery_summary = DiscoveryEngine(config, provider).run()
    stage_hook("discovery", "COMPLETED", resources_processed=_resource_count(result.discovery_summary))

    # "inventory" reuses the discovery pass -- pre-Phase-2 code had this
    # stage in STAGES but never called stage_hook for it, leaving it stuck
    # at NOT_RUN forever. Fixed here since the extraction surfaced it.
    stage_hook("inventory", "COMPLETED", resources_processed=_resource_count(result.discovery_summary))

    crown_jewel_engine = CrownJewelEngine(config)
    checkpoint("before crown jewel identification")
    stage_hook("crown_jewel", "RUNNING", current_api="inventory:identify")
    crown_jewel_engine.identify_in_inventory()
    stage_hook("crown_jewel", "COMPLETED")

    checkpoint("before evidence collection")
    stage_hook(
        "evidence_collection", "RUNNING",
        current_collector="collectors", current_api="read-only evidence collection",
    )
    result.execution_status = EvidenceCollectionEngine(config, provider).run()
    stage_hook("evidence_collection", "COMPLETED")

    checkpoint("before normalization")
    stage_hook("normalization", "RUNNING", current_api="normalize:findings")
    result.findings = NormalizationEngine().run()
    stage_hook("normalization", "COMPLETED", resources_processed=len(result.findings))

    checkpoint("before assessment register")
    stage_hook("assessment_register", "RUNNING", current_api="register:build")
    result.assessment_register = AssessmentRegisterEngine(
        config, assessment_id, knowledge_engine=knowledge
    ).run(result.findings)
    stage_hook("assessment_register", "COMPLETED", resources_processed=len(result.assessment_register))

    checkpoint("before checklist validation")
    stage_hook("checklist_validation", "RUNNING", current_api="checklist:evaluate")
    result.checklist_coverage = ChecklistValidationEngine(
        config, knowledge_engine=knowledge
    ).run(result.assessment_register)
    stage_hook("checklist_validation", "COMPLETED")

    # Not stage-marked, matching both pre-Phase-2 callers exactly: this
    # second crown_jewel_engine.run() call happens inline between the
    # checklist_validation and threat_validation stages in both main.py and
    # control_plane.py today.
    crown_jewel_engine.run(result.findings)

    checkpoint("before threat validation")
    stage_hook("threat_validation", "RUNNING", current_api="threat:validate")
    result.threat_scenarios = ThreatValidationEngine(
        config, knowledge_engine=knowledge
    ).run(result.checklist_coverage, result.assessment_register)
    stage_hook("threat_validation", "COMPLETED")

    checkpoint("before threat correlation")
    stage_hook("threat_correlation", "RUNNING", current_api="threat:correlate")
    result.correlated_threats = ThreatCorrelationEngine(
        config, knowledge_engine=knowledge
    ).run(result.threat_scenarios, result.assessment_register)
    stage_hook("threat_correlation", "COMPLETED")

    checkpoint("before attack path generation")
    stage_hook("attack_paths", "RUNNING", current_api="graph:attack-paths")
    result.mitre_summary = MitreMappingEngine().run(result.findings)
    attack_path_engine = AttackPathEngine(config, crown_jewel_engine, knowledge_engine=knowledge)
    result.attack_path_candidates = attack_path_engine.run(
        result.assessment_register, correlated_threats=result.correlated_threats
    )
    stage_hook("attack_paths", "COMPLETED")

    checkpoint("before risk prioritization")
    stage_hook("risk_prioritization", "RUNNING", current_api="risk:score")
    result.risk_summary = RiskPrioritizationEngine(
        config, attack_path_engine, result.checklist_coverage, knowledge_engine=knowledge
    ).run(result.findings)
    stage_hook("risk_prioritization", "COMPLETED")

    checkpoint("before recommendation generation")
    stage_hook("recommendations", "RUNNING", current_api="recommendations:generate")
    result.recommendations = RecommendationEngine(config, knowledge_engine=knowledge).run(
        result.checklist_coverage,
        result.assessment_register,
        result.threat_scenarios,
        result.correlated_threats,
    )
    stage_hook("recommendations", "COMPLETED")

    checkpoint("before traceability")
    stage_hook("traceability", "RUNNING", current_api="traceability:build")
    traceability_engine = AssessmentTraceabilityEngine(knowledge, config)
    traceability_engine.build(
        findings=result.findings,
        assessment_register=result.assessment_register,
        checklist_coverage=result.checklist_coverage,
        threat_scenarios=result.threat_scenarios,
        correlated_threats=result.correlated_threats,
        attack_path_candidates=result.attack_path_candidates,
        risk_summary=result.risk_summary,
        recommendations=result.recommendations,
    )
    result.traceability_engine = traceability_engine
    stage_hook("traceability", "COMPLETED")

    checkpoint("before reporting")
    stage_hook("reporting", "RUNNING", current_api="reporting:generate")
    result.filtered_findings, result.filtered_register = _apply_validations(
        result.findings, result.assessment_register, validations
    )
    result.evidence_index = load_json_with_recovery(Path("output/evidence_index.json"), {}).get(
        "evidence", {}
    )
    attack_path_catalog: List[Dict[str, Any]] = []
    catalog_file = config.get("attack_path", {}).get("catalog")
    if catalog_file and Path(catalog_file).exists():
        attack_path_catalog = (
            yaml.safe_load(Path(catalog_file).read_text(encoding="utf-8")) or {}
        ).get("attack_paths", [])

    base_metadata = {
        "platform_version": "2.0.0",
        "assessment_engine_version": "2.0.0",
        "collector_versions": sorted(result.execution_status.keys()),
        "checklist_version": config.get("framework", {}).get("version", "Current"),
        "threat_library_version": config.get("framework", {}).get("version", "Current"),
        "assessment_date": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "assessment_duration": "",
        "assessment_id": assessment_id,
    }
    final_metadata = {**base_metadata, **(assessment_metadata or {})}

    ReportingEngine(
        findings=result.filtered_findings,
        assessment_register=result.filtered_register,
        execution_status=result.execution_status,
        checklist_coverage=result.checklist_coverage,
        threat_scenarios=result.threat_scenarios,
        correlated_threats=result.correlated_threats,
        mitre_summary=result.mitre_summary,
        attack_path_candidates=result.attack_path_candidates,
        risk_summary=result.risk_summary,
        evidence_index=result.evidence_index,
        discovery_summary=result.discovery_summary,
        attack_path_catalog=attack_path_catalog,
        recommendations=result.recommendations,
        knowledge_engine=knowledge,
        traceability_engine=traceability_engine,
        assessment_metadata=final_metadata,
    ).generate()
    result.report_files = [str(path) for path in sorted(Path("output/reports").glob("*.html"))]
    stage_hook("reporting", "COMPLETED")

    return result


def _apply_validations(findings, register_entries, validations: Optional[Dict[str, Any]]):
    if not validations:
        return findings, register_entries
    confirmed_findings = []
    confirmed_register = []
    for entry in register_entries:
        validation = validations.get(entry.register_id, {})
        status = validation.get("status", entry.validation_status)
        entry.validation_status = status
        entry.analyst_notes = validation.get("notes", entry.analyst_notes)
        if status == "CONFIRMED":
            confirmed_register.append(entry)
    allowed_ids = {entry.register_id for entry in confirmed_register}
    for finding in findings:
        status = validations.get(finding.assessment_register_id, {}).get(
            "status", finding.validation_status
        )
        finding.validation_status = status
        finding.analyst_notes = validations.get(finding.assessment_register_id, {}).get(
            "notes", finding.analyst_notes
        )
        if finding.assessment_register_id in allowed_ids:
            confirmed_findings.append(finding)
    return confirmed_findings, confirmed_register
