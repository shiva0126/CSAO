from __future__ import annotations

import csv
import datetime as dt
import json
import os
import re
import secrets
import zipfile
from configparser import ConfigParser
from copy import deepcopy
from io import StringIO
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote, urlencode

from core.config_loader import load_config
from core.file_utils import atomic_write_json, load_json_with_recovery
from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.engines.assessment_register_engine import AssessmentRegisterEngine
from core.engines.attack_path_engine import AttackPathEngine
from core.engines.checklist_engine import ChecklistValidationEngine
from core.engines.crown_jewel_engine import CrownJewelEngine
from core.engines.discovery_engine import DiscoveryEngine
from core.engines.evidence_engine import EvidenceCollectionEngine
from core.engines.normalization_engine import NormalizationEngine
from core.engines.risk_engine import RiskPrioritizationEngine
from core.engines.threat_correlation_engine import ThreatCorrelationEngine
from core.engines.threat_validation_engine import ThreatValidationEngine
from core.engines.traceability_engine import AssessmentTraceabilityEngine
from core.providers.registry import get_provider
from core.reporting.reporting_engine import ReportingEngine
from core.schema.assessment_register import AssessmentRegisterEntry
from core.schema.evidence import EvidenceRecord
from core.schema.finding import Finding
from core.schema.recommendation import Recommendation
from core.schema.threats import CorrelatedThreat, ThreatScenarioRecord
from workbench.control_plane import (
    AccountVault,
    AssessmentRunner,
    AuditLogger,
    REPORT_ARCHIVE_DIR,
    SUMMARY_FILE,
    WorkbenchState,
    deep_merge,
)
from workbench.collector_metadata import (
    CAPABILITY_VALIDATION_TARGETS,
    collector_metadata_rows,
    enabled_collector_keys,
)


IAM_ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
IAM_POLICY_CHARACTER_LIMIT = 6144
IAM_TRUST_POLICY_CHARACTER_LIMIT = 2048
DEFAULT_ASSESSMENT_ROLE_NAME = "CSAO-Assessor"
DEFAULT_TRUST_ACCOUNT_ID = "123456789012"
SUMMARY_SCOPE_BY_SERVICE = {
    "IAM": "Read Configuration",
    "Organizations": "Read Configuration",
    "CloudTrail": "Audit Validation",
    "Config": "Read Configuration",
    "Security Hub": "Read Findings",
    "GuardDuty": "Read Findings",
    "Access Analyzer": "Read Findings",
    "EC2": "Describe Resources",
    "S3": "Inventory",
    "Lambda": "Inventory",
    "RDS": "Describe Resources",
    "EKS": "Describe Resources",
    "ECS": "Describe Resources",
    "ELB": "Describe Resources",
    "CloudWatch": "Read Metrics",
}


def read_json(path: Path, default):
    return load_json_with_recovery(path, default)


def write_json(path: Path, data) -> None:
    atomic_write_json(path, data)


def load_dataclass_list(path: Path, factory):
    items = read_json(path, [])
    if not isinstance(items, list):
        return []
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append(factory(item))
    return result


def load_findings(path: Path) -> List[Finding]:
    return load_dataclass_list(path, Finding.from_dict)


def load_register_entries(
    path: Path, findings: Optional[List[Finding]] = None
) -> List[AssessmentRegisterEntry]:
    items = read_json(path, [])
    entries = []
    findings_by_register = {}
    findings_by_id = {}
    for finding in findings or []:
        if finding.assessment_register_id:
            findings_by_register[finding.assessment_register_id] = finding
        if finding.tool_source:
            findings_by_id[
                f"{finding.tool_source}:{getattr(finding, '_tool_check_id', 'unknown')}:{finding.resource_id}"
            ] = finding

    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        entry = AssessmentRegisterEntry(
            register_id=item.get("register_id", ""),
            assessment_id=item.get("assessment_id", ""),
            finding_id=item.get("finding_id", ""),
            resource=item.get("resource", "Unknown"),
            environment=item.get("environment", "Unknown"),
            cloud_platform=item.get("cloud_platform", "aws"),
            evidence_references=list(item.get("evidence_references", []) or []),
            evidence_ids=list(item.get("evidence_ids", []) or []),
            source=item.get("source", "Unknown"),
            validation_status=item.get("validation_status", "PENDING"),
            analyst_notes=item.get("analyst_notes", ""),
            business_exception=item.get("business_exception", ""),
            checklist_references=list(item.get("checklist_references", []) or []),
            mitre_tactics=list(item.get("mitre_tactics", []) or []),
            mitre_techniques=list(item.get("mitre_techniques", []) or []),
            threat_scenario_references=list(
                item.get("threat_scenario_references", []) or []
            ),
            attack_path_references=list(item.get("attack_path_references", []) or []),
            recommendation_references=list(
                item.get("recommendation_references", []) or []
            ),
            risk_score=float(item.get("risk_score", 0.0) or 0.0),
            risk_factors=dict(item.get("risk_factors", {}) or {}),
            title=item.get("title", ""),
            severity=item.get("severity", "INFO"),
            service=item.get("service", "Unknown"),
            resource_name=item.get("resource_name", "Unknown"),
            resource_type=item.get("resource_type", "Unknown"),
            internet_facing=item.get("internet_facing", "Unknown"),
            crown_jewel=item.get("crown_jewel", "No"),
            business_unit=item.get("business_unit", "Unknown"),
        )
        entry._finding = findings_by_register.get(
            entry.register_id
        ) or findings_by_id.get(entry.finding_id)
        entries.append(entry)
    return entries


def load_threat_scenarios(path: Path) -> List[ThreatScenarioRecord]:
    return load_dataclass_list(
        path,
        lambda item: ThreatScenarioRecord(
            scenario_id=item.get("scenario_id", ""),
            threat_id=item.get("threat_id", ""),
            threat_number=item.get("threat_number"),
            domain=item.get("domain", ""),
            title=item.get("title", ""),
            status=item.get("status", "PENDING"),
            prerequisite_checklists=list(item.get("prerequisite_checklists", []) or []),
            supporting_evidence=list(item.get("supporting_evidence", []) or []),
            supporting_evidence_ids=list(item.get("supporting_evidence_ids", []) or []),
            validated_finding_ids=list(item.get("validated_finding_ids", []) or []),
            validated_register_ids=list(item.get("validated_register_ids", []) or []),
            related_attack_paths=list(item.get("related_attack_paths", []) or []),
            mitre_tactics=list(item.get("mitre_tactics", []) or []),
            mitre_techniques=list(item.get("mitre_techniques", []) or []),
            risk_level=item.get("risk_level", ""),
            impact=item.get("impact", ""),
            data_flow=item.get("data_flow", ""),
            trust_boundary=item.get("trust_boundary", ""),
            business_impact=item.get("business_impact", ""),
            preconditions=item.get("preconditions", ""),
            existing_controls=item.get("existing_controls", ""),
            remediation=item.get("remediation", ""),
            analyst_notes=item.get("analyst_notes", ""),
        ),
    )


def load_correlated_threats(path: Path) -> List[CorrelatedThreat]:
    return load_dataclass_list(
        path,
        lambda item: CorrelatedThreat(
            correlation_id=item.get("correlation_id", ""),
            scenario_ids=list(item.get("scenario_ids", []) or []),
            status=item.get("status", "PENDING"),
            attack_path_refs=list(item.get("attack_path_refs", []) or []),
            source_resources=list(item.get("source_resources", []) or []),
            target_resources=list(item.get("target_resources", []) or []),
            supporting_evidence=list(item.get("supporting_evidence", []) or []),
            validated_register_ids=list(item.get("validated_register_ids", []) or []),
            analyst_decision=item.get("analyst_decision", "UNREVIEWED"),
            correlation_reason=item.get("correlation_reason", ""),
        ),
    )


def load_recommendations(path: Path) -> List[Recommendation]:
    return load_dataclass_list(
        path,
        lambda item: Recommendation(
            recommendation_id=item.get("recommendation_id", ""),
            title=item.get("title", ""),
            status=item.get("status", "OPEN"),
            assessment_register_ids=list(item.get("assessment_register_ids", []) or []),
            checklist_ids=list(item.get("checklist_ids", []) or []),
            threat_scenario_refs=list(item.get("threat_scenario_refs", []) or []),
            attack_path_refs=list(item.get("attack_path_refs", []) or []),
            evidence_references=list(item.get("evidence_references", []) or []),
            evidence_ids=list(item.get("evidence_ids", []) or []),
            priority=item.get("priority", ""),
            severity=item.get("severity", ""),
            rationale=item.get("rationale", ""),
            remediation=item.get("remediation", ""),
            verification_steps=item.get("verification_steps", ""),
            report_sections=list(item.get("report_sections", []) or []),
        ),
    )


def load_evidence_records(path: Path) -> List[EvidenceRecord]:
    return load_dataclass_list(path, EvidenceRecord.from_dict)


def load_dict_list(path: Path) -> List[Dict[str, Any]]:
    data = read_json(path, [])
    return data if isinstance(data, list) else []


def file_mtime(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    return path.stat().st_mtime


def latest_mtime(paths: Iterable[Path]) -> Optional[float]:
    stamps = [file_mtime(path) for path in paths if file_mtime(path)]
    if not stamps:
        return None
    return max(stamps)


def format_time(timestamp: Optional[float]) -> str:
    if not timestamp:
        return ""
    return dt.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%SZ")


def format_duration(start: Optional[float], finish: Optional[float]) -> str:
    if not start or not finish or finish < start:
        return ""
    seconds = int(round(finish - start))
    minutes, remainder = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{remainder}s")
    return " ".join(parts)


def parse_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class StageState:
    key: str
    label: str
    status: str = "NOT_RUN"
    start_time: str = ""
    finish_time: str = ""
    duration: str = ""
    errors: List[str] = field(default_factory=list)
    retryable: bool = True
    artifacts: List[str] = field(default_factory=list)


class WorkbenchRuntime:
    STAGE_ORDER = [
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

    PAGE_TEMPLATES = {
        "dashboard": "partials/dashboard.html",
        "assessments": "partials/assessments.html",
        "capability_validation": "partials/capability_validation.html",
        "access_requirements": "partials/access_requirements.html",
        "trust_center": "partials/trust_center.html",
        "coverage": "partials/coverage.html",
        "history": "partials/history.html",
        "progress": "partials/progress.html",
        "register": "partials/register.html",
        "checklist": "partials/checklist.html",
        "threat_scenarios": "partials/threat_scenarios.html",
        "threat_correlation": "partials/threat_correlation.html",
        "attack_paths": "partials/attack_paths.html",
        "risk": "partials/risk.html",
        "recommendations": "partials/recommendations.html",
        "reports": "partials/reports.html",
        "accounts": "partials/accounts.html",
        "users": "partials/users.html",
        "evidence": "partials/evidence.html",
        "settings": "partials/settings.html",
        "runtime_status": "partials/runtime_status.html",
    }

    def __init__(self):
        self._traceability_engine = None
        self._traceability_signature = None
        self._full_load_signature = None
        self._summary_signature = None
        self._provider_signature = None
        self._base_config = {}
        self._base_config_signature = None
        self._knowledge_signature = None
        self._knowledge_engine = None
        self.last_runtime_errors: List[Dict[str, str]] = []
        self.last_provider_error = ""
        self.last_traceability_error = ""
        self.summary = {}
        self.exception_callback = None
        self.refresh()

    def refresh(self, view_name: str = ""):
        self.state_store = WorkbenchState()
        self.audit = AuditLogger()
        self.account_vault = AccountVault(self.state_store, audit=self.audit)
        self.runner = AssessmentRunner(
            self.state_store,
            audit=self.audit,
            exception_callback=self.exception_callback,
        )
        self.state = self.state_store.load()
        self.config = deep_merge(
            self._load_base_config(), self.state.get("settings_overrides", {})
        )
        provider_signature = (
            self.config.get("provider"),
            json.dumps(self.config.get("aws", {}), sort_keys=True, default=str),
        )
        if (
            not hasattr(self, "provider")
            or provider_signature != self._provider_signature
        ):
            self.provider = get_provider(self.config)
            try:
                self.provider.authenticate()
                self.last_provider_error = ""
            except Exception as exc:
                self.last_provider_error = f"{type(exc).__name__}: {exc}"
                self.last_runtime_errors.append(
                    {"subsystem": "provider", "error": self.last_provider_error}
                )
                self.last_runtime_errors = self.last_runtime_errors[-20:]
            self._provider_signature = provider_signature

        self.base_directory = Path(self.state.get("active_output_root", "output"))
        self.state_file = self.state_store.path
        self.knowledge = self._load_knowledge_engine()
        self.assessment_id = self._load_session_id()
        self.summary = self._load_summary()
        if self._should_reload_full_state(view_name):
            self.discovery_summary = read_json(
                self.base_directory / "discovery" / "asset_inventory.json", {}
            )
            self.evidence_index = read_json(
                self.base_directory / "evidence_index.json", {}
            ).get("evidence", {})
            self.findings = load_findings(
                self.base_directory / "risk" / "risk_findings.json"
            )
            if not self.findings:
                self.findings = load_findings(
                    self.base_directory / "normalized" / "findings.json"
                )
            self.register_entries = load_register_entries(
                self.base_directory / "assessment_register" / "assessment_register.json",
                self.findings,
            )
            self.checklist_coverage = load_dict_list(
                self.base_directory / "checklist" / "checklist_coverage.json"
            )
            self.threat_scenarios = load_threat_scenarios(
                self.base_directory / "threats" / "threat_scenarios.json"
            )
            self.correlated_threats = load_correlated_threats(
                self.base_directory / "threats" / "correlated_threats.json"
            )
            self.attack_path_candidates = load_dict_list(
                self.base_directory / "attack_paths" / "attack_path_candidates.json"
            )
            self.risk_summary = read_json(
                self.base_directory / "risk" / "risk_summary.json", {}
            )
            self.recommendations = load_recommendations(
                self.base_directory / "assessment_register" / "recommendations.json"
            )
            if not self.recommendations:
                self.recommendations = load_recommendations(
                    self.base_directory / "recommendations" / "recommendations.json"
                )
            self.crown_jewels = load_dict_list(
                self.base_directory / "crown_jewel" / "identified_assets.json"
            )
            self.traceability_engine = self._build_traceability_engine()
        else:
            self.discovery_summary = self.summary.get("discovery_summary", {})
            self.evidence_index = getattr(self, "evidence_index", {})
            self.findings = getattr(self, "findings", [])
            self.register_entries = getattr(self, "register_entries", [])
            self.checklist_coverage = getattr(self, "checklist_coverage", [])
            self.threat_scenarios = getattr(self, "threat_scenarios", [])
            self.correlated_threats = getattr(self, "correlated_threats", [])
            self.attack_path_candidates = getattr(self, "attack_path_candidates", [])
            self.risk_summary = self.summary.get("risk_summary", getattr(self, "risk_summary", {}))
            self.recommendations = getattr(self, "recommendations", [])
            self.crown_jewels = getattr(self, "crown_jewels", [])
        self._apply_validation_overrides()
        self.report_files = self._load_reports()

    def _config_inputs_signature(self):
        config_path = Path("config/config.yaml")
        tools_path = Path("config/tools.yaml")
        return (
            file_mtime(config_path),
            file_mtime(tools_path),
        )

    def _load_base_config(self) -> Dict[str, Any]:
        signature = self._config_inputs_signature()
        if self._base_config and signature == self._base_config_signature:
            return deepcopy(self._base_config)
        self._base_config = load_config()
        self._base_config_signature = signature
        return deepcopy(self._base_config)

    def _knowledge_inputs_signature(self):
        checklist_file = Path(
            self.config.get("checklist", {}).get("file", "checklists/checklist.yaml")
        )
        attack_path_file = Path(
            self.config.get("attack_path", {}).get(
                "catalog", "data/attack_path_catalog.yaml"
            )
        )
        return (
            str(checklist_file),
            file_mtime(checklist_file),
            str(attack_path_file),
            file_mtime(attack_path_file),
        )

    def _load_knowledge_engine(self) -> AssessmentKnowledgeEngine:
        signature = self._knowledge_inputs_signature()
        if self._knowledge_engine is not None and signature == self._knowledge_signature:
            return self._knowledge_engine
        self._knowledge_engine = AssessmentKnowledgeEngine(self.config)
        self._knowledge_signature = signature
        return self._knowledge_engine

    def _load_summary(self) -> Dict[str, Any]:
        signature = file_mtime(SUMMARY_FILE)
        if signature == self._summary_signature and self.summary:
            return self.summary
        self._summary_signature = signature
        summary = read_json(SUMMARY_FILE, {})
        return summary if isinstance(summary, dict) else {}

    def _full_state_signature(self):
        relevant = [
            self.base_directory / "risk" / "risk_findings.json",
            self.base_directory / "normalized" / "findings.json",
            self.base_directory / "assessment_register" / "assessment_register.json",
            self.base_directory / "checklist" / "checklist_coverage.json",
            self.base_directory / "threats" / "threat_scenarios.json",
            self.base_directory / "threats" / "correlated_threats.json",
            self.base_directory / "attack_paths" / "attack_path_candidates.json",
            self.base_directory / "risk" / "risk_summary.json",
            self.base_directory / "assessment_register" / "recommendations.json",
            self.base_directory / "recommendations" / "recommendations.json",
            self.base_directory / "crown_jewel" / "identified_assets.json",
            self.base_directory / "evidence_index.json",
        ]
        return tuple((str(path), file_mtime(path)) for path in relevant)

    def _should_reload_full_state(self, view_name: str) -> bool:
        signature = self._full_state_signature()
        heavy_views = {
            "register",
            "checklist",
            "threat_scenarios",
            "threat_correlation",
            "attack_paths",
            "risk",
            "recommendations",
            "evidence",
        }
        if not hasattr(self, "findings"):
            self._full_load_signature = signature
            return True
        if view_name in heavy_views:
            changed = signature != self._full_load_signature
            self._full_load_signature = signature
            return changed
        if not self.summary:
            changed = signature != self._full_load_signature
            self._full_load_signature = signature
            return changed
        return False

    def _archive_reports(self) -> List[Path]:
        if not REPORT_ARCHIVE_DIR.exists():
            return []
        return sorted(
            [path for path in REPORT_ARCHIVE_DIR.glob("*.html") if path.is_file()],
            reverse=True,
        )

    def _load_session_id(self):
        session = read_json(Path("output/session.json"), {})
        return session.get("assessment_id") or session.get("assessmentId") or ""

    def _load_reports(self):
        if self.summary.get("reports"):
            reports = []
            for item in self.summary.get("reports", []):
                generated_at = item.get("generated_at", "")
                reports.append(
                    {
                        **item,
                        "generated_at": format_time(
                            dt.datetime.fromisoformat(
                                generated_at.replace("Z", "+00:00")
                            ).timestamp()
                        )
                        if generated_at
                        else "",
                    }
                )
            return reports
        reports_dir = self.base_directory / "reports"
        reports = []
        if not reports_dir.exists():
            return reports
        for path in sorted(reports_dir.glob("*.html")):
            reports.append(
                {
                    "name": path.name,
                    "title": path.stem.replace("_", " ").title(),
                    "path": str(path),
                    "size": path.stat().st_size,
                    "generated_at": format_time(path.stat().st_mtime),
                }
            )
        return reports

    def _build_traceability_engine(self):
        signature = self._traceability_inputs_signature()
        if self._traceability_engine is not None and signature == self._traceability_signature:
            return self._traceability_engine
        try:
            engine = AssessmentTraceabilityEngine(self.knowledge, self.config)
            engine.build(
                findings=self.findings,
                assessment_register=self.register_entries,
                checklist_coverage=self.checklist_coverage,
                threat_scenarios=self.threat_scenarios,
                correlated_threats=self.correlated_threats,
                attack_path_candidates=self.attack_path_candidates,
                risk_summary=self.risk_summary,
                recommendations=self.recommendations,
            )
            self._traceability_engine = engine
            self._traceability_signature = signature
            self.last_traceability_error = ""
            return engine
        except Exception as exc:
            self.last_traceability_error = f"{type(exc).__name__}: {exc}"
            self.last_runtime_errors.append(
                {"subsystem": "traceability", "error": self.last_traceability_error}
            )
            self.last_runtime_errors = self.last_runtime_errors[-20:]
            return self._traceability_engine

    def _traceability_inputs_signature(self):
        relevant = [
            self.base_directory / "risk" / "risk_findings.json",
            self.base_directory / "normalized" / "findings.json",
            self.base_directory / "assessment_register" / "assessment_register.json",
            self.base_directory / "checklist" / "checklist_coverage.json",
            self.base_directory / "threats" / "threat_scenarios.json",
            self.base_directory / "threats" / "correlated_threats.json",
            self.base_directory / "attack_paths" / "attack_path_candidates.json",
            self.base_directory / "risk" / "risk_summary.json",
            self.base_directory / "assessment_register" / "recommendations.json",
            self.base_directory / "recommendations" / "recommendations.json",
        ]
        return tuple((str(path), file_mtime(path)) for path in relevant)

    def page_context(self, request, view_name: str, title: str, **data):
        return {
            "request": request,
            "active_view": view_name,
            "page_title": title,
            "breadcrumbs": self.breadcrumbs(view_name, title),
            "nav_sections": self.nav_sections(),
            "runtime": self,
            "content_template": self.PAGE_TEMPLATES[view_name],
            "data": data,
            **data,
        }

    def breadcrumbs(self, view_name: str, title: str) -> List[Dict[str, str]]:
        if view_name == "dashboard":
            return [{"label": "Executive Dashboard", "href": "/dashboard"}]
        workspace_keys = {
            "progress",
            "coverage",
            "register",
            "checklist",
            "threat_scenarios",
            "threat_correlation",
            "attack_paths",
            "risk",
            "recommendations",
            "reports",
        }
        if view_name in workspace_keys:
            return [
                {"label": "Executive Dashboard", "href": "/dashboard"},
                {"label": "Assessment Workspace", "href": "/progress"},
                {"label": title, "href": ""},
            ]
        section_label = ""
        for section in self.nav_sections():
            for item in section["items"]:
                active_keys = item.get("active_keys") or [item["key"]]
                if view_name in active_keys or view_name == item["key"]:
                    section_label = section["label"]
                    break
            if section_label:
                break
        trail = [{"label": "Executive Dashboard", "href": "/dashboard"}]
        if section_label:
            trail.append({"label": section_label, "href": ""})
        if title != section_label:
            trail.append({"label": title, "href": ""})
        return trail

    def nav_sections(self):
        workspace_keys = [
            "progress",
            "coverage",
            "register",
            "checklist",
            "threat_scenarios",
            "threat_correlation",
            "attack_paths",
            "risk",
            "recommendations",
            "reports",
        ]
        return [
            {
                "label": "",
                "items": [
                    {"key": "dashboard", "label": "Executive Dashboard", "href": "/", "active_keys": ["dashboard"]},
                ],
            },
            {
                "label": "Access Setup",
                "items": [
                    {"key": "accounts", "label": "Cloud Accounts", "href": "/accounts", "active_keys": ["accounts"]},
                    {
                        "key": "capability_validation",
                        "label": "Pre-Assessment Validation",
                        "href": "/capability-validation",
                        "active_keys": ["capability_validation"],
                    },
                    {
                        "key": "access_requirements",
                        "label": "Customer Access Pack",
                        "href": "/access-requirements",
                        "active_keys": ["access_requirements"],
                    },
                    {
                        "key": "trust_center",
                        "label": "Read-Only Assurance",
                        "href": "/trust-center",
                        "active_keys": ["trust_center"],
                    },
                ],
            },
            {
                "label": "Assessment Launch",
                "items": [
                    {"key": "assessments", "label": "New Assessment", "href": "/assessments", "active_keys": ["assessments"]},
                    {"key": "history", "label": "Assessment History", "href": "/history", "active_keys": ["history"]},
                ],
            },
            {
                "label": "Assessment Workspace",
                "items": [
                    {"key": "workspace", "label": "Assessment Workspace", "href": "/progress", "active_keys": workspace_keys},
                ],
            },
            {
                "label": "Administration",
                "items": [
                    {"key": "users", "label": "Users", "href": "/users", "active_keys": ["users"]},
                    {"key": "settings", "label": "Settings", "href": "/settings", "active_keys": ["settings"]},
                    {"key": "runtime_status", "label": "Runtime Status", "href": "/runtime-status", "active_keys": ["runtime_status"]},
                ],
            },
        ]

    def available_collectors(self) -> List[Dict[str, Any]]:
        labels = {
            "aws_inventory": "AWS Inventory",
            "prowler": "Prowler",
            "cloudsplaining": "Cloudsplaining",
            "steampipe": "Steampipe",
            "access_analyzer": "IAM Access Analyzer",
            "config_aggregator": "AWS Config",
            "cartography": "Cartography",
            "tenable": "Tenable",
        }
        return [
            {
                "key": key,
                "label": labels.get(key, key.replace("_", " ").title()),
                "enabled": bool(value),
            }
            for key, value in (self.config.get("modules", {}) or {}).items()
        ]

    def collector_catalog(self) -> List[Dict[str, Any]]:
        rows = []
        for item in collector_metadata_rows(self.config):
            rows.append(
                {
                    "key": item["key"],
                    "label": item["name"],
                    "enabled": item["enabled"],
                    "description": item["purpose"],
                    "permissions": ", ".join(
                        sorted(
                            {
                                action
                                for permission in item.get("permissions", [])
                                for action in permission.get("actions", [])
                            }
                        )
                    )
                    or "No AWS permissions required",
                    "runtime": item.get("estimated_runtime", "Medium"),
                    "services": item.get("services_inspected", []),
                    "evidence": item.get("evidence_produced", []),
                    "mitre_mapping": item.get("mitre_mapping", []),
                    "threat_scenarios": item.get("threat_scenarios_supported", []),
                    "aws_apis": [
                        api
                        for permission in item.get("permissions", [])
                        for api in permission.get("apis", [])
                    ],
                }
            )
        return rows

    def _apply_validation_overrides(self) -> None:
        validations = self.state.get("finding_validations", {}) or {}
        for entry in self.register_entries:
            override = validations.get(entry.register_id, {})
            if isinstance(override, dict):
                entry.validation_status = override.get(
                    "status", entry.validation_status
                )
                entry.analyst_notes = override.get("notes", entry.analyst_notes)
        for finding in self.findings:
            override = validations.get(finding.assessment_register_id, {})
            if isinstance(override, dict):
                finding.validation_status = override.get(
                    "status", finding.validation_status
                )
                finding.analyst_notes = override.get("notes", finding.analyst_notes)

    def assessment_name(self) -> str:
        return self.config.get("framework", {}).get(
            "name", "Cloud Security Assessment Orchestrator"
        )

    def cloud_provider_name(self) -> str:
        return self.provider.platform_name.upper()

    def account_count(self) -> int:
        return len(self.account_records())

    def account_records(self) -> List[Dict[str, Any]]:
        last_assessment_by_account = {}
        for item in self.assessment_history():
            account_id = item.get("account_id")
            if account_id and account_id not in last_assessment_by_account:
                last_assessment_by_account[account_id] = item
        rows = []
        for item in self.account_vault.list_accounts():
            latest = last_assessment_by_account.get(item["id"], {})
            enriched = dict(item)
            enriched["last_assessment"] = latest.get("name", "")
            enriched["last_assessment_status"] = latest.get("status", "")
            rows.append(enriched)
        return rows

    def enabled_module_names(self) -> List[str]:
        return [
            key
            for key, value in (self.config.get("modules", {}) or {}).items()
            if value
        ]

    def account_choices(self) -> List[Dict[str, str]]:
        return [
            {
                "id": item["id"],
                "label": f'{item["name"]} ({item["account_id"] or item["auth_type"]})',
            }
            for item in self.account_records()
        ]

    def save_cloud_account(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        result = self.account_vault.save_account(payload)
        self.refresh()
        return result

    def delete_cloud_account(self, account_id: str) -> None:
        self.account_vault.delete_account(account_id)
        self.refresh()

    def test_cloud_account(self, account_id: str) -> Dict[str, Any]:
        result = self.account_vault.test_connection(account_id)
        self.refresh()
        return result

    def validate_cloud_account_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.account_vault.validate_account_payload(payload)

    def discovered_resources(self) -> int:
        if self.summary.get("resources_discovered") is not None:
            return int(self.summary.get("resources_discovered") or 0)
        counts = self.discovery_summary.get("resource_counts", {}) or {}
        return sum(counts.values())

    def evidence_source_count(self) -> int:
        if self.summary.get("evidence_sources") is not None:
            return int(self.summary.get("evidence_sources") or 0)
        return len(self.evidence_index)

    def high_risk_count(self) -> int:
        if self.summary.get("high_risk_findings") is not None:
            return int(self.summary.get("high_risk_findings") or 0)
        return sum(1 for finding in self.findings if (finding._risk_score or 0) >= 70)

    def manual_review_remaining(self) -> int:
        if self.summary.get("manual_reviews_remaining") is not None:
            return int(self.summary.get("manual_reviews_remaining") or 0)
        return sum(
            1
            for item in self.checklist_coverage
            if item.get("status") == "MANUAL_REVIEW"
        )

    def checklist_progress(self) -> Dict[str, int]:
        if self.summary.get("checklist_progress"):
            return dict(self.summary.get("checklist_progress", {}))
        summary = {"PASS": 0, "FAIL": 0, "MANUAL_REVIEW": 0, "NOT_EVALUATED": 0}
        for item in self.checklist_coverage:
            status = item.get("status", "NOT_EVALUATED")
            summary[status] = summary.get(status, 0) + 1
        summary["total"] = sum(summary.values())
        return summary

    def current_lifecycle_stage(self) -> str:
        for stage in self.stage_states():
            if stage.status not in {"COMPLETED", "SKIPPED"}:
                return stage.label
        return "Reporting"

    def recent_activity(self) -> List[Dict[str, str]]:
        if self.summary.get("recent_activity"):
            return [
                {
                    "name": item.get("name", ""),
                    "when": format_time(
                        dt.datetime.fromisoformat(
                            item.get("when", "").replace("Z", "+00:00")
                        ).timestamp()
                    )
                    if item.get("when")
                    else "",
                }
                for item in self.summary.get("recent_activity", [])
            ]
        activity = []
        for path in self._activity_artifacts():
            if not path.exists():
                continue
            activity.append(
                {
                    "name": str(path),
                    "when": format_time(path.stat().st_mtime),
                }
            )
        activity.sort(key=lambda item: item["when"], reverse=True)
        return activity[:12]

    def active_monitor(self) -> Dict[str, Any]:
        return self.state.get("monitor", {}) or {}

    def cancel_assessment(self) -> Dict[str, Any]:
        result = self.runner.cancel()
        self.refresh()
        return result

    def active_assessment(self) -> Dict[str, Any]:
        monitor = self.active_monitor()
        if monitor.get("assessment"):
            return monitor["assessment"]
        active_id = self.state.get("active_assessment_id")
        return next(
            (item for item in self.assessment_history() if item.get("id") == active_id),
            {},
        )

    def assessment_history(self) -> List[Dict[str, Any]]:
        return list(self.state.get("assessments", []) or [])

    def assessment_form_defaults(self) -> Dict[str, Any]:
        collectors = self.enabled_module_names()
        estimates = self.assessment_estimate(
            collectors, self.config.get("aws", {}).get("regions", [])
        )
        return {
            "name": "",
            "client": "",
            "description": "",
            "assessment_type": "full",
            "cloud_account_id": self.state.get("last_account_id", ""),
            "regions": ",".join(self.config.get("aws", {}).get("regions", []) or []),
            "collectors": collectors,
            "services": "ec2,s3,iam,rds,lambda,vpc",
            "output_location": str(self.base_directory),
            "risk_profile": "balanced",
            "report_types": self.report_format_flags(),
            "connection_status": "Pending validation",
            "estimate": estimates,
        }

    def client_records(self) -> List[Dict[str, Any]]:
        seen = set()
        rows = []
        for item in self.assessment_history():
            client = str(item.get("client") or "").strip()
            if not client:
                continue
            key = client.lower()
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "value": client,
                    "label": client,
                    "description": item.get("name", ""),
                }
            )
        rows.sort(key=lambda item: item["label"].lower())
        return rows

    def supported_regions(self) -> List[str]:
        regions = self.config.get("aws", {}).get("regions", []) or []
        defaults = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
        ]
        ordered = []
        for item in list(regions) + defaults:
            if item and item not in ordered:
                ordered.append(item)
        return ordered

    def cloud_provider_options(self) -> List[Dict[str, Any]]:
        return [
            {"value": "aws", "label": "AWS", "enabled": True, "description": "Available now"},
            {"value": "azure", "label": "Azure", "enabled": False, "description": "Planned"},
            {"value": "gcp", "label": "Google Cloud", "enabled": False, "description": "Planned"},
        ]

    def auth_method_options(self) -> List[Dict[str, str]]:
        return [
            {
                "value": "profile",
                "label": "AWS Profile",
                "badge": "Local Development",
                "description": "Recommended for engineers using a configured AWS CLI profile on the CSAO host.",
            },
            {
                "value": "assume_role",
                "label": "Assume Role",
                "badge": "Recommended",
                "description": "Best for enterprise onboarding. Uses temporary credentials and aligns with least-privilege deployment.",
            },
            {
                "value": "access_keys",
                "label": "AWS Access Keys",
                "badge": "Standalone",
                "description": "Use for standalone or temporary onboarding when a profile or role is not available.",
            },
            {
                "value": "sso",
                "label": "AWS IAM Identity Center",
                "badge": "Organization SSO",
                "description": "For environments using IAM Identity Center and CLI-backed SSO authentication.",
            },
        ]

    def aws_profile_options(self) -> List[str]:
        parser = ConfigParser()
        profiles: List[str] = []
        for path in (Path.home() / ".aws" / "credentials", Path.home() / ".aws" / "config"):
            if not path.exists():
                continue
            try:
                parser.read(path, encoding="utf-8")
            except Exception:
                continue
            for section in parser.sections():
                profile = section.removeprefix("profile ").strip()
                if profile and profile not in profiles:
                    profiles.append(profile)
        if "default" not in profiles:
            profiles.insert(0, "default")
        return profiles

    def user_role_options(self) -> List[Dict[str, str]]:
        return [
            {"value": "READ_ONLY", "label": "Read Only"},
            {"value": "ANALYST", "label": "Security Analyst"},
            {"value": "ADMINISTRATOR", "label": "Administrator"},
        ]

    def user_status_options(self) -> List[Dict[str, str]]:
        return [
            {"value": "active", "label": "Active"},
            {"value": "disabled", "label": "Disabled"},
        ]

    def supported_services(self) -> List[Dict[str, str]]:
        return [
            {"key": "iam", "label": "IAM"},
            {"key": "ec2", "label": "EC2"},
            {"key": "vpc", "label": "VPC"},
            {"key": "s3", "label": "S3"},
            {"key": "lambda", "label": "Lambda"},
            {"key": "rds", "label": "RDS"},
            {"key": "eks", "label": "EKS"},
            {"key": "ecs", "label": "ECS"},
            {"key": "cloudtrail", "label": "CloudTrail"},
            {"key": "config", "label": "Config"},
            {"key": "organizations", "label": "Organizations"},
            {"key": "guardduty", "label": "GuardDuty"},
            {"key": "securityhub", "label": "Security Hub"},
            {"key": "accessanalyzer", "label": "Access Analyzer"},
            {"key": "route53", "label": "Route53"},
            {"key": "elb", "label": "ELB"},
            {"key": "apigateway", "label": "API Gateway"},
        ]

    def report_type_options(self) -> List[Dict[str, str]]:
        return [
            {"value": "generate_executive_summary", "label": "Executive Summary"},
            {"value": "generate_technical_report", "label": "Technical Report"},
            {"value": "generate_html", "label": "HTML"},
            {"value": "generate_pdf", "label": "PDF"},
            {"value": "generate_json", "label": "JSON"},
            {"value": "generate_excel", "label": "Excel"},
            {"value": "generate_evidence_archive", "label": "Evidence Archive"},
        ]

    def recent_output_locations(self) -> List[str]:
        locations = []
        default_location = str(self.base_directory)
        for item in [default_location] + [
            str(entry.get("output_location") or "").strip()
            for entry in self.assessment_history()
        ]:
            if item and item not in locations:
                locations.append(item)
        return locations[:6]

    def assessment_wizard_view_model(self) -> Dict[str, Any]:
        defaults = self.assessment_form_defaults()
        selected_regions = [
            item.strip() for item in str(defaults.get("regions") or "").split(",") if item.strip()
        ]
        selected_services = [
            item.strip() for item in str(defaults.get("services") or "").split(",") if item.strip()
        ]
        selected_reports = list(defaults.get("report_types") or [])
        selected_collectors = list(defaults.get("collectors") or [])
        readiness = self.assessment_readiness(
            account_id=str(defaults.get("cloud_account_id") or "").strip(),
            collectors=selected_collectors,
        )
        return {
            "defaults": defaults,
            "clients": self.client_records(),
            "accounts": self.account_records(),
            "collectors": self.collector_catalog(),
            "regions": self.supported_regions(),
            "services": self.supported_services(),
            "report_types": self.report_type_options(),
            "recent_output_locations": self.recent_output_locations(),
            "selected_regions": selected_regions,
            "selected_services": selected_services,
            "selected_collectors": selected_collectors,
            "selected_reports": selected_reports,
            "readiness": readiness,
            "risk_profiles": [
                {"value": "conservative", "label": "Conservative"},
                {"value": "balanced", "label": "Balanced"},
                {"value": "aggressive", "label": "Aggressive"},
                {"value": "compliance", "label": "Compliance"},
            ],
            "assessment_type_options": [
                {"value": "full", "label": "Full Assessment"},
                {"value": "quick", "label": "Quick Assessment"},
                {"value": "compliance", "label": "Compliance Assessment"},
                {"value": "iam", "label": "IAM Assessment"},
                {"value": "network", "label": "Network Assessment"},
            ],
        }

    def assessment_readiness(
        self, account_id: str = "", collectors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        account_id = str(account_id or self.state.get("last_account_id") or "").strip()
        account = self.account_vault.get_account(account_id) if account_id else None
        selected_collectors = list(collectors or self.enabled_module_names())
        preflight = (
            self.pre_assessment_validation(account_id, selected_collectors)
            if account_id
            else {"status": "NOT_READY", "capabilities": [], "collectors": []}
        )
        output_root = Path(
            self.config.get("output", {}).get("root_directory", str(self.base_directory))
        )
        report_templates_loaded = all(
            (Path("workbench/templates") / name).exists()
            for name in ("base.html", "page.html", "partials/reports.html")
        )
        checks = [
            {
                "label": "AWS account configured",
                "status": "PASS" if account else "FAIL",
                "detail": (
                    f"{account.get('name')} | {account.get('account_id') or account.get('alias')}"
                    if account
                    else "Select a saved cloud account."
                ),
            },
            {
                "label": "IAM permissions validated",
                "status": "PASS" if preflight.get("status") == "READY" else "FAIL",
                "detail": (
                    "Capability and connection checks are ready."
                    if preflight.get("status") == "READY"
                    else "Run Pre-Assessment Validation before launch."
                ),
            },
            {
                "label": "Knowledge catalog loaded",
                "status": "PASS" if bool(self.knowledge.checklist_items) else "FAIL",
                "detail": f"{len(self.knowledge.checklist_items)} workbook controls loaded.",
            },
            {
                "label": "Runtime healthy",
                "status": "PASS" if not self.last_runtime_errors else "FAIL",
                "detail": (
                    "No runtime health issues detected."
                    if not self.last_runtime_errors
                    else self.last_runtime_errors[-1].get("error", "Runtime error detected.")
                ),
            },
            {
                "label": "Collectors available",
                "status": "PASS" if bool(selected_collectors) else "FAIL",
                "detail": (
                    f"{len(selected_collectors)} collector(s) selected."
                    if selected_collectors
                    else "Select at least one collector."
                ),
            },
            {
                "label": "Report templates loaded",
                "status": "PASS" if report_templates_loaded else "FAIL",
                "detail": (
                    "Workbench report templates are available."
                    if report_templates_loaded
                    else "Required report templates are missing."
                ),
            },
            {
                "label": "Output directory writable",
                "status": "PASS" if os.access(output_root.parent if not output_root.exists() else output_root, os.W_OK) else "FAIL",
                "detail": str(output_root),
            },
            {
                "label": "Configuration valid",
                "status": "PASS" if self.config else "FAIL",
                "detail": "Configuration loaded successfully." if self.config else "Configuration is unavailable.",
            },
        ]
        ready = all(item["status"] == "PASS" for item in checks)
        return {"checks": checks, "ready": ready, "preflight": preflight}

    def methodology_progress(self) -> List[Dict[str, str]]:
        stage_by_key = {stage.key: stage.status for stage in self.stage_states()}
        validated_accounts = any(
            account.get("last_validation_status") == "VALIDATED"
            for account in self.account_records()
        )
        preflight_ready = (
            (self.state.get("preflight_validation", {}) or {}).get("status") == "READY"
        )
        has_assessment = bool(self.active_assessment())

        def stage_status(*keys):
            statuses = [stage_by_key.get(key, "NOT_RUN") for key in keys]
            if any(status == "FAILED" for status in statuses):
                return "FAILED"
            if any(status == "RUNNING" for status in statuses):
                return "RUNNING"
            if statuses and all(status in {"COMPLETED", "SKIPPED"} for status in statuses):
                return "COMPLETED"
            if any(status in {"COMPLETED", "SKIPPED"} for status in statuses):
                return "PENDING"
            return "PENDING"

        return [
            {"label": "Access Setup", "status": "COMPLETED" if validated_accounts else "PENDING", "href": "/accounts"},
            {"label": "Validation", "status": "COMPLETED" if preflight_ready else "PENDING", "href": "/capability-validation"},
            {"label": "Launch", "status": "COMPLETED" if has_assessment else "PENDING", "href": "/assessments"},
            {"label": "Evidence", "status": stage_status("evidence_collection"), "href": "/evidence"},
            {"label": "Checklist", "status": stage_status("checklist_validation"), "href": "/checklist"},
            {"label": "Findings", "status": stage_status("assessment_register"), "href": "/register"},
            {"label": "Threat Scenarios", "status": stage_status("threat_validation"), "href": "/threat-scenarios"},
            {"label": "Threat Correlation", "status": stage_status("threat_correlation"), "href": "/threat-correlation"},
            {"label": "Attack Paths", "status": stage_status("attack_paths"), "href": "/attack-paths"},
            {"label": "Risk", "status": stage_status("risk_prioritization"), "href": "/risk"},
            {"label": "Recommendations", "status": stage_status("recommendations"), "href": "/recommendations"},
            {"label": "Deliverables", "status": stage_status("reporting"), "href": "/reports"},
        ]

    def start_assessment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        safety = self.safety_validation()
        if safety["status"] != "PASSED":
            raise ValueError("Safety Validation Failed. CSAO must remain read-only.")
        account_id = str(payload.get("cloud_account_id") or "").strip()
        account = self.account_vault.get_account(account_id)
        if not account:
            raise ValueError("A validated cloud account is required.")
        if account.get("last_validation_status") != "VALIDATED":
            raise ValueError(
                "Selected cloud account must pass connection testing before use."
            )
        assessment = {
            "name": str(payload.get("name") or "Enterprise Assessment").strip(),
            "client": str(payload.get("client") or "").strip(),
            "description": str(payload.get("description") or "").strip(),
            "assessment_type": str(payload.get("assessment_type") or "full").strip(),
            "regions": [
                item.strip()
                for item in str(payload.get("regions") or "").split(",")
                if item.strip()
            ],
            "collectors": list(payload.get("collectors") or []),
            "services": list(payload.get("services") or []),
            "output_location": str(payload.get("output_location") or "output").strip(),
            "risk_profile": str(payload.get("risk_profile") or "balanced").strip(),
            "report_types": list(payload.get("report_types") or []),
            "settings_overrides": self.state.get("settings_overrides", {}),
        }
        validation = self.pre_assessment_validation(account_id, assessment["collectors"])
        creds = self.account_vault.get_credentials(account_id)
        self.state = self.state_store.update(
            lambda state: {
                **state,
                "last_account_id": account_id,
                "preflight_validation": validation,
                "safety_validation": safety,
            }
        )
        result = self.runner.start(
            self.config,
            assessment,
            account,
            creds,
            self.state.get("finding_validations", {}),
        )
        self.refresh()
        return result

    def pre_assessment_validation(
        self, account_id: str, collectors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        account = self.account_vault.get_account(account_id)
        if not account:
            return {
                "status": "NOT_READY",
                "warnings": ["Select a cloud account to validate."],
                "errors": [],
                "account": {},
                "capabilities": [],
                "collectors": [],
                "validated_at": "",
            }
        record = self.account_vault.get_account_record(account_id) or {}
        metadata = dict(record.get("metadata", {}) or {})
        credentials = self.account_vault.get_credentials(account_id)
        auth_type = record.get("auth_type", "profile")
        result = self.account_vault._test_aws_connection(auth_type, credentials, metadata)
        capabilities = []
        warnings = []
        errors = []
        collector_rows = []
        capability_status = {}
        if result.get("status") == "VALIDATED":
            try:
                session, _ = self.account_vault._build_session(
                    auth_type, credentials, metadata
                )
                region_name = (
                    (result.get("metadata", {}).get("regions", []) or ["us-east-1"])[0]
                )
                for target in CAPABILITY_VALIDATION_TARGETS:
                    status = "Available"
                    detail = ""
                    try:
                        client_kwargs = {}
                        if target.get("regional", True):
                            client_kwargs["region_name"] = region_name
                        client = session.client(target["service"], **client_kwargs)
                        getattr(client, target["operation"])(**target.get("params", {}))
                    except Exception as exc:
                        detail = str(exc)
                        if "AccessDenied" in detail or "access denied" in detail.lower():
                            status = "Access Denied"
                        elif "OptInRequired" in detail or "not subscribed" in detail.lower():
                            status = "Service Disabled"
                        else:
                            status = "Unavailable"
                    capability_status[target["name"]] = status
                    capabilities.append(
                        {
                            "name": target["name"],
                            "status": status,
                            "detail": detail,
                            "mandatory": target.get("mandatory", False),
                        }
                    )
            except Exception as exc:
                errors.append(str(exc))
        else:
            errors.append(result.get("error", "AWS authentication failed."))
        selected_collectors = collectors or self.enabled_module_names()
        metadata_rows = {item["key"]: item for item in collector_metadata_rows(self.config)}
        for collector in selected_collectors:
            item = metadata_rows.get(collector)
            required_services = {
                permission.get("service")
                for permission in (item or {}).get("permissions", [])
                if permission.get("classification") == "required"
            }
            unavailable = [
                service
                for service in required_services
                if capability_status.get(service)
                in {"Access Denied", "Service Disabled", "Unavailable"}
            ]
            collector_rows.append(
                {
                    "name": collector,
                    "status": "Disabled"
                    if collector not in self.enabled_module_names()
                    else ("Disabled by Capability" if unavailable else "Ready"),
                    "detail": ", ".join(unavailable) if unavailable else "",
                }
            )
            if unavailable:
                warnings.append(
                    f"Collector {collector} depends on unavailable capabilities: {', '.join(unavailable)}."
                )
        if any(item.get("status") != "Available" for item in capabilities):
            warnings.append(
                "Some AWS services are unavailable or access-denied. The assessment can continue with partial coverage."
            )
        return {
            "status": "READY" if result.get("status") == "VALIDATED" else "NOT_READY",
            "warnings": warnings,
            "errors": errors,
            "account": result.get("metadata", {}),
            "critical_dependencies": [
                {
                    "name": "STS Identity",
                    "status": "Available" if result.get("status") == "VALIDATED" else "Unavailable",
                },
                {
                    "name": "Configured Regions",
                    "status": "Available"
                    if (result.get("metadata", {}).get("regions") or [])
                    else "Unavailable",
                },
            ],
            "capabilities": capabilities,
            "collectors": collector_rows,
            "validated_at": result.get("validated_at", ""),
        }

    def capability_validation_view_model(self, account_id: str = "") -> Dict[str, Any]:
        accounts = self.account_records()
        selected_id = account_id or self.state.get("last_account_id", "")
        validation = self.pre_assessment_validation(
            selected_id, self.enabled_module_names()
        )
        return {
            "accounts": accounts,
            "selected_account_id": selected_id,
            "validation": validation,
            "collectors": self.available_collectors(),
        }

    def safety_validation(self) -> Dict[str, Any]:
        forbidden = (
            "create",
            "put",
            "update",
            "delete",
            "modify",
            "authorize",
            "revoke",
            "attach",
            "detach",
            "passrole",
            "runinstances",
            "terminateinstances",
            "createbucket",
            "deletebucket",
        )
        read_only_exceptions = {"iam:GenerateCredentialReport"}
        violations = []
        for collector in collector_metadata_rows(self.config):
            if not collector["enabled"]:
                continue
            if collector.get("writes_customer_aws"):
                violations.append(
                    {
                        "collector": collector["name"],
                        "reason": collector.get("notes", "Collector declares AWS write behavior."),
                    }
                )
            for permission in collector.get("permissions", []):
                for action in permission.get("actions", []):
                    if action in read_only_exceptions:
                        continue
                    action_name = action.split(":")[-1].lower()
                    if any(action_name.startswith(prefix) for prefix in forbidden):
                        violations.append(
                            {
                                "collector": collector["name"],
                                "reason": f"Forbidden action detected: {action}",
                            }
                        )
        return {"status": "FAILED" if violations else "PASSED", "violations": violations}

    def external_tool_validation(self) -> List[Dict[str, Any]]:
        # Live local-host check -- kept for any direct/CLI caller, but the
        # Trust Center UI does NOT use this anymore (see
        # trust_center_view_model below): collector tools are installed in
        # the Docker worker container, not on whatever host workbench.serve
        # runs on, so a live shutil.which() here would check the wrong
        # environment. The worker reports its own status into
        # workbench_state at startup instead.
        from core.tool_check import check_external_tools

        return check_external_tools()

    def evidence_coverage_summary(self) -> List[Dict[str, Any]]:
        validation = (
            self.summary.get("diagnostics", {}).get("capability_validation", {}) or {}
        )
        status_by_name = {
            item.get("name"): item.get("status", "Unavailable")
            for item in validation.get("capabilities", [])
        }
        coverage = []
        mapping = [
            "IAM",
            "EC2",
            "CloudTrail",
            "Config",
            "GuardDuty",
            "Organizations",
            "Lambda",
            "VPC",
            "Security Hub",
            "Access Analyzer",
            "S3",
        ]
        for service in mapping:
            status = status_by_name.get(service, "Unavailable")
            percent = (
                "100%"
                if status == "Available"
                else (
                    "Unavailable"
                    if status in {"Service Disabled", "Unavailable"}
                    else "Limited"
                )
            )
            coverage.append(
                {"service": service, "coverage": percent, "status": status}
            )
        return coverage

    def assessment_health_view_model(self) -> Dict[str, Any]:
        diagnostics = self.summary.get("diagnostics", {}) or {}
        validation = diagnostics.get("capability_validation", {}) or {}
        capabilities = validation.get("capabilities", [])
        available = sum(
            1 for item in capabilities if item.get("status") == "Available"
        )
        total = len(capabilities) or 1
        permissions_pct = round((available / total) * 100)
        evidence_cov = self.evidence_coverage_summary()
        available_cov = sum(1 for item in evidence_cov if item["coverage"] == "100%")
        evidence_pct = round((available_cov / (len(evidence_cov) or 1)) * 100)
        collectors = diagnostics.get("execution_status", {}) or {}
        collector_success = round(
            (
                sum(
                    1
                    for status in collectors.values()
                    if str(status).upper() == "SUCCESS"
                )
                / (len(collectors) or 1)
            )
            * 100
        )
        config_pct = 100 if self.safety_validation()["status"] == "PASSED" else 0
        cloud_pct = evidence_pct
        confidence = round(
            (permissions_pct + evidence_pct + collector_success + cloud_pct) / 4
        )
        deductions = []
        for item in capabilities:
            if item.get("status") != "Available":
                deductions.append(f"{item.get('name')} is {item.get('status')}.")
        return {
            "configuration": config_pct,
            "permissions": permissions_pct,
            "evidence_coverage": evidence_pct,
            "collector_success": collector_success,
            "cloud_coverage": cloud_pct,
            "assessment_confidence": confidence,
            "deductions": deductions[:8],
        }

    def assessment_timeline(self) -> List[Dict[str, Any]]:
        timeline = self.active_monitor().get("timeline")
        if timeline:
            return timeline
        return list(self.summary.get("timeline", []) or [])

    def trust_center_view_model(self) -> Dict[str, Any]:
        access = self.access_requirements_view_model()
        read_only_guarantee = [
            "CSAO never modifies AWS resources.",
            "Only read operations are performed during assessment execution.",
            "No infrastructure changes, resource creation, policy modification, "
            "IAM updates, EC2 actions, S3 modifications, or CloudFormation "
            "changes occur.",
        ]
        faq = [
            {
                "q": "Why is sts:AssumeRole required?",
                "a": (
                    "It is used only to obtain temporary customer-approved "
                    "read-only credentials."
                ),
            },
            {
                "q": "Why do we need DescribeInstances?",
                "a": "It supports EC2 inventory and exposure evidence.",
            },
            {
                "q": "Why do we need ListBuckets?",
                "a": (
                    "It supports S3 inventory evidence only, not object data "
                    "inspection."
                ),
            },
            {
                "q": "What happens if Config is disabled?",
                "a": (
                    "Config-dependent evidence is marked unavailable and "
                    "assessment coverage is reduced rather than forcing failure."
                ),
            },
            {
                "q": "What happens if GuardDuty isn't enabled?",
                "a": (
                    "GuardDuty-related validation becomes optional coverage and "
                    "does not stop the assessment."
                ),
            },
            {
                "q": "Can CSAO change my environment?",
                "a": "No. CSAO is designed to remain non-intrusive and read-only.",
            },
            {
                "q": "Can CSAO access application data?",
                "a": (
                    "CSAO collects service configuration and security evidence, "
                    "not application payload data."
                ),
            },
            {
                "q": "How is evidence stored?",
                "a": (
                    "Evidence is stored locally in CSAO output artifacts and can "
                    "be packaged into diagnostics bundles and evidence archives."
                ),
            },
        ]
        # Sourced from what the ARQ worker reported about its own
        # environment at startup (workbench/worker.py), not a live check on
        # whatever host workbench.serve happens to run on -- the worker is
        # what actually executes collectors, so it's the one that can
        # correctly answer "is this tool available."
        tool_status = self.state.get("tool_status") or []
        return {
            "read_only_guarantee": read_only_guarantee,
            "permission_matrix": access.get("permission_matrix", []),
            "collector_permissions": access.get("collector_permissions", []),
            "faq": faq,
            "tool_validation": tool_status,
            "tool_status_checked_at": self.state.get("tool_status_checked_at", ""),
            "safety_validation": self.safety_validation(),
        }

    def _default_assessment_account_id(self) -> str:
        provider = getattr(self, "provider", None)
        if provider is not None:
            try:
                account_id = str(provider.account_id() or "").strip()
                if account_id.isdigit() and len(account_id) == 12:
                    return account_id
            except Exception:
                pass
        for account_id in self.config.get("aws", {}).get("account_ids", []) or []:
            candidate = str(account_id or "").strip()
            if candidate.isdigit() and len(candidate) == 12:
                return candidate
        return DEFAULT_TRUST_ACCOUNT_ID

    def _default_assessment_role_name(self) -> str:
        for candidate in [
            self.config.get("access_requirements", {}).get("assessment_role_name"),
            self.config.get("onboarding", {}).get("assessment_role_name"),
            self.config.get("aws", {}).get("assessment_role_name"),
            DEFAULT_ASSESSMENT_ROLE_NAME,
        ]:
            value = str(candidate or "").strip()
            if value:
                return value
        return DEFAULT_ASSESSMENT_ROLE_NAME

    def _build_assessment_role_arn(self, account_id: str, role_name: str) -> str:
        return f"arn:aws:iam::{account_id}:role/{role_name}"

    def _build_trust_policy(
        self,
        assessment_account_id: str,
        assessment_role_name: str,
        use_root_trust: bool,
        use_external_id: bool,
        external_id: str = "",
    ) -> Dict[str, Any]:
        assessment_account_id = str(assessment_account_id or "").strip() or DEFAULT_TRUST_ACCOUNT_ID
        assessment_role_name = str(assessment_role_name or "").strip() or DEFAULT_ASSESSMENT_ROLE_NAME
        principal = (
            {"AWS": f"arn:aws:iam::{assessment_account_id}:root"}
            if use_root_trust
            else {"AWS": self._build_assessment_role_arn(assessment_account_id, assessment_role_name)}
        )
        statement: Dict[str, Any] = {
            "Effect": "Allow",
            "Principal": principal,
            "Action": "sts:AssumeRole",
        }
        if use_external_id:
            external_id = str(external_id or "").strip() or secrets.token_urlsafe(24)
            statement["Condition"] = {"StringEquals": {"sts:ExternalId": external_id}}
        else:
            external_id = ""
        return {
            "trust_policy": {"Version": "2012-10-17", "Statement": [statement]},
            "external_id": external_id,
        }

    def _policy_scope_label(self, service: str, actions: List[str]) -> str:
        if service in SUMMARY_SCOPE_BY_SERVICE:
            return SUMMARY_SCOPE_BY_SERVICE[service]
        prefixes = {
            action.split(":", 1)[1].split("/", 1)[0].split(".", 1)[0].split("-", 1)[0].lower()
            for action in actions
            if ":" in action
        }
        if prefixes and prefixes.issubset({"describe"}):
            return "Describe Resources"
        if prefixes and prefixes.issubset({"list"}):
            return "List Resources"
        if prefixes and prefixes.issubset({"get"}):
            return "Read Configuration"
        if "describe" in prefixes or "list" in prefixes:
            return "Read Configuration"
        return "Read Access"

    def _policy_summary_rows(self, groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {
                "aws_service": group["service"],
                "permission_scope": self._policy_scope_label(group["service"], group["actions"]),
                "purpose": group["purpose"],
            }
            for group in groups
        ]

    def _permission_matrix_csv(self, permission_matrix: List[Dict[str, Any]]) -> str:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Collector",
                "AWS Service",
                "AWS APIs Used",
                "IAM Actions Required",
                "Purpose",
                "Mandatory / Optional",
                "Assessment Capability",
                "Evidence Collected",
            ]
        )
        for row in permission_matrix:
            writer.writerow(
                [
                    row.get("collector", ""),
                    row.get("aws_service", ""),
                    ", ".join(row.get("aws_apis", [])),
                    ", ".join(row.get("iam_actions", [])),
                    row.get("purpose", ""),
                    str(row.get("classification", "")).upper(),
                    row.get("assessment_capability_enabled", ""),
                    ", ".join(row.get("evidence_collected", [])),
                ]
            )
        return output.getvalue()

    def _services_covered_payload(
        self, groups: List[Dict[str, Any]], optional: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {
            "required_services": [
                group["service"] for group in groups if group.get("classification") == "required"
            ],
            "optional_services": [
                group["service"] for group in groups if group.get("classification") != "required"
            ],
            "available_optional_integrations": [
                {"service": item["service"], "purpose": item["purpose"]} for item in optional
            ],
        }

    def _collect_known_actions(self, collector_rows: List[Dict[str, Any]]) -> Dict[str, set[str]]:
        known_actions: Dict[str, set[str]] = {}
        for collector in collector_rows:
            if not collector.get("enabled"):
                continue
            for permission in collector.get("permissions", []):
                service = str(permission.get("service", "")).strip()
                if not service:
                    continue
                known_actions.setdefault(service, set()).update(
                    str(action).strip()
                    for action in permission.get("actions", [])
                    if str(action).strip()
                )
        return known_actions

    def _validate_access_requirements_bundle(
        self,
        policy: Dict[str, Any],
        trust_policy: Dict[str, Any],
        groups: List[Dict[str, Any]],
        collector_rows: List[Dict[str, Any]],
        trust_settings: Dict[str, Any],
    ) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []
        policy_json = json.dumps(policy, indent=2)
        trust_policy_json = json.dumps(trust_policy, indent=2)

        try:
            json.loads(policy_json)
            json.loads(trust_policy_json)
        except json.JSONDecodeError as exc:
            errors.append(f"JSON syntax error: {exc}")

        if len(policy_json.encode("utf-8")) > IAM_POLICY_CHARACTER_LIMIT:
            errors.append(
                f"IAM policy exceeds the {IAM_POLICY_CHARACTER_LIMIT}-character size limit."
            )
        if len(trust_policy_json.encode("utf-8")) > IAM_TRUST_POLICY_CHARACTER_LIMIT:
            errors.append(
                f"Trust policy exceeds the {IAM_TRUST_POLICY_CHARACTER_LIMIT}-character size limit."
            )

        statements = policy.get("Statement", [])
        if not isinstance(statements, list) or not statements:
            errors.append("IAM policy must contain at least one statement.")
        else:
            known_actions = {
                action
                for collector in collector_rows
                if collector.get("enabled")
                for permission in collector.get("permissions", [])
                for action in permission.get("actions", [])
                if str(action).strip()
            }
            for index, statement in enumerate(statements, start=1):
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if not isinstance(actions, list) or not actions:
                    errors.append(f"IAM policy statement {index} has no actions.")
                    continue
                normalized_actions = [str(action).strip() for action in actions if str(action).strip()]
                if len(normalized_actions) != len(set(normalized_actions)):
                    errors.append(
                        f"IAM policy statement {index} contains duplicate actions."
                    )
                if statement.get("Effect") != "Allow":
                    errors.append(f"IAM policy statement {index} must use Effect Allow.")
                if statement.get("Resource") != "*":
                    errors.append(f"IAM policy statement {index} must target Resource '*'.")
                invalid_actions = []
                for action in normalized_actions:
                    if "*" in action or action not in known_actions:
                        invalid_actions.append(action)
                if invalid_actions:
                    errors.append(
                        f"IAM policy statement {index} contains invalid actions: {', '.join(sorted(dict.fromkeys(invalid_actions)))}."
                    )

        trust_statements = trust_policy.get("Statement", [])
        if not isinstance(trust_statements, list) or not trust_statements:
            errors.append("Trust policy must contain at least one statement.")
        else:
            trust_statement = trust_statements[0]
            if trust_statement.get("Action") != "sts:AssumeRole":
                errors.append("Trust policy must allow sts:AssumeRole.")
            principal = trust_statement.get("Principal", {}) or {}
            principal_arn = str(principal.get("AWS", "")).strip()
            if trust_settings.get("use_root_trust"):
                if not principal_arn.endswith(":root"):
                    errors.append(
                        "Root trust was requested, but the trust policy does not target the account root principal."
                    )
            else:
                role_name = str(trust_settings.get("assessment_role_name") or "").strip()
                account_id = str(trust_settings.get("assessment_account_id") or "").strip()
                if not account_id.isdigit() or len(account_id) != 12:
                    errors.append("CSAO account ID must be a 12-digit AWS account number.")
                if not IAM_ROLE_NAME_PATTERN.fullmatch(role_name or ""):
                    errors.append("CSAO assessment role name contains invalid IAM characters.")
                expected_arn = self._build_assessment_role_arn(account_id, role_name)
                if principal_arn != expected_arn:
                    errors.append(
                        "Trust policy principal does not match the configured CSAO assessment role."
                    )
            if trust_settings.get("use_external_id"):
                condition = trust_statement.get("Condition", {}) or {}
                condition_external_id = (
                    condition.get("StringEquals", {}) or {}
                ).get("sts:ExternalId")
                configured_external_id = str(trust_settings.get("external_id") or "").strip()
                if not condition_external_id:
                    errors.append(
                        "ExternalId was enabled, but the trust policy does not include sts:ExternalId."
                    )
                elif condition_external_id != configured_external_id:
                    errors.append(
                        "The generated ExternalId in the trust policy does not match the configured value."
                    )

        if not groups:
            warnings.append("No collector permissions are enabled, so the IAM policy is empty.")

        return {
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
            "warnings": warnings,
            "policy_size_bytes": len(policy_json.encode("utf-8")),
            "trust_policy_size_bytes": len(trust_policy_json.encode("utf-8")),
        }

    def _build_onboarding_readme(
        self,
        trust_settings: Dict[str, Any],
        validation: Dict[str, Any],
        services_covered: Dict[str, Any],
    ) -> str:
        trust_mode = "root trust" if trust_settings.get("use_root_trust") else "dedicated CSAO assessment role"
        external_id_line = (
            f"- ExternalId: `{trust_settings.get('external_id')}`"
            if trust_settings.get("use_external_id")
            else "- ExternalId: disabled"
        )
        return "\n".join(
            [
                "# CSAO Onboarding Package",
                "",
                "Purpose",
                "- This package contains the least-privilege permissions policy and trust policy for CSAO onboarding.",
                "",
                "How to create the role",
                "1. Create an IAM role in the customer account.",
                "2. Attach `assessment-policy.json` as the permissions policy.",
                "3. Attach `trust-policy.json` as the trust relationship.",
                "4. Return the resulting Role ARN to the CSAO operator.",
                "",
                "Trust configuration",
                f"- Trust mode: {trust_mode}",
                f"- CSAO account ID: `{trust_settings.get('assessment_account_id')}`",
                f"- CSAO assessment role: `{trust_settings.get('assessment_role_name')}`",
                external_id_line,
                "",
                "Validation",
                f"- Status: {validation.get('status', 'PASS')}",
                f"- Policy size: {validation.get('policy_size_bytes', 0)} bytes",
                f"- Trust policy size: {validation.get('trust_policy_size_bytes', 0)} bytes",
                "",
                "Services covered",
                f"- Required services: {', '.join(services_covered.get('required_services', [])) or 'None'}",
                f"- Optional services: {', '.join(services_covered.get('optional_services', [])) or 'None'}",
            ]
        )

    def _build_permission_guide_markdown(
        self,
        permission_matrix: List[Dict[str, Any]],
        services_covered: Dict[str, Any],
    ) -> str:
        lines = [
            "# CSAO Collector Permission Matrix",
            "",
            "This reference explains why each read-only IAM action is requested by the enabled CSAO collectors.",
            "",
            "## Services Covered",
            "",
            f"- Required services: {', '.join(services_covered.get('required_services', [])) or 'None'}",
            f"- Optional services: {', '.join(services_covered.get('optional_services', [])) or 'None'}",
            "",
        ]
        for row in permission_matrix:
            lines.extend(
                [
                    f"## {row.get('collector', '')} -> {row.get('aws_service', '')}",
                    f"- Purpose: {row.get('purpose', '')}",
                    f"- Mandatory / Optional: {str(row.get('classification', '')).upper()}",
                    f"- Assessment Capability: {row.get('assessment_capability_enabled', '')}",
                    f"- AWS APIs Used: {', '.join(row.get('aws_apis', [])) or 'None'}",
                    f"- IAM Actions Required: {', '.join(row.get('iam_actions', [])) or 'None'}",
                    f"- Evidence Collected: {', '.join(row.get('evidence_collected', [])) or 'None'}",
                    "",
                ]
            )
        return "\n".join(lines)

    def _build_onboarding_package(
        self,
        policy: Dict[str, Any],
        trust_policy: Dict[str, Any],
        trust_settings: Dict[str, Any],
        validation: Dict[str, Any],
        permission_matrix: List[Dict[str, Any]],
        services_covered: Dict[str, Any],
    ) -> Path:
        package_path = Path("output/workbench/onboarding-package.zip")
        package_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("assessment-policy.json", json.dumps(policy, indent=2))
            archive.writestr("trust-policy.json", json.dumps(trust_policy, indent=2))
            archive.writestr(
                "collector-permission-matrix.csv",
                self._permission_matrix_csv(permission_matrix),
            )
            archive.writestr(
                "collector-permission-matrix.json",
                json.dumps(permission_matrix, indent=2),
            )
            archive.writestr(
                "permission-guide.md",
                self._build_permission_guide_markdown(permission_matrix, services_covered),
            )
            archive.writestr(
                "services-covered.json",
                json.dumps(services_covered, indent=2),
            )
            archive.writestr(
                "README.md",
                self._build_onboarding_readme(trust_settings, validation, services_covered),
            )
        return package_path

    def _policy_query_string(self, trust_settings: Dict[str, Any]) -> str:
        params = {
            "trust_account_id": trust_settings.get("assessment_account_id", ""),
            "assessment_role_name": trust_settings.get("assessment_role_name", ""),
            "use_root_trust": "true" if trust_settings.get("use_root_trust") else "",
            "use_external_id": "true" if trust_settings.get("use_external_id") else "",
            "external_id": trust_settings.get("external_id", ""),
        }
        return urlencode({key: value for key, value in params.items() if value})

    def access_requirements_view_model(
        self,
        trust_account_id: str = "",
        assessment_role_name: str = "",
        use_root_trust: bool = False,
        use_external_id: bool = False,
        external_id: str = "",
    ) -> Dict[str, Any]:
        read_only_guarantee = [
            "CSAO never modifies AWS resources.",
            "Only read operations are performed during assessment execution.",
            "No infrastructure changes, resource creation, policy modification, "
            "IAM updates, EC2 actions, S3 modifications, or CloudFormation "
            "changes occur.",
        ]
        faq = [
            {
                "q": "Will CSAO modify resources?",
                "a": "No. CSAO is designed to remain read-only and non-intrusive.",
            },
            {
                "q": "Can I use temporary credentials?",
                "a": "Yes. Temporary credentials and AssumeRole are the recommended enterprise onboarding path.",
            },
            {
                "q": "Why does CSAO need STS?",
                "a": "STS is used only to obtain temporary customer-approved credentials for the assessment role.",
            },
            {
                "q": "What happens if Config is disabled?",
                "a": "Config-related evidence becomes unavailable and coverage is reduced without blocking the entire onboarding flow.",
            },
            {
                "q": "Can I assess only one account?",
                "a": "Yes. CSAO supports standalone account onboarding as well as multi-account enterprise environments.",
            },
            {
                "q": "What happens if Organizations access is denied?",
                "a": "Organization-scoped context becomes limited, but the account-level assessment can still proceed.",
            },
        ]
        enabled = set(enabled_collector_keys(self.config))
        grouped: Dict[str, Dict[str, Any]] = {}
        collector_rows = collector_metadata_rows(self.config)
        for collector in collector_rows:
            if not collector["enabled"]:
                continue
            for permission in collector.get("permissions", []):
                service = permission.get("service", "Unknown")
                group = grouped.setdefault(
                    service,
                    {
                        "service": service,
                        "purpose": "",
                        "purposes": [],
                        "actions": [],
                        "collectors": [],
                        "evidence": [],
                        "domain": permission.get("capability", ""),
                        "classification": permission.get("classification", "required"),
                    },
                )
                group["actions"].extend(permission.get("actions", []))
                group["collectors"].append(collector["name"])
                group["evidence"].extend(permission.get("evidence", []))
                group["purposes"].append(
                    permission.get("purpose") or permission.get("capability", "")
                )
                if permission.get("classification") == "required":
                    group["classification"] = "required"
        groups = []
        statements = []
        for service, group in grouped.items():
            actions = sorted(dict.fromkeys(group["actions"]))
            collectors = sorted(dict.fromkeys(group["collectors"]))
            evidence = sorted(dict.fromkeys(group["evidence"]))
            purposes = [item for item in dict.fromkeys(group.get("purposes", [])) if item]
            view = {
                **group,
                "purpose": "; ".join(purposes),
                "actions": actions,
                "collectors": collectors,
                "evidence": evidence,
                "capability_name": service,
                "capability_href": "/capability-validation",
            }
            groups.append(view)
            statements.append(
                {
                    "Sid": f"CSAO{service.replace(' ', '').replace('-', '')}ReadOnly",
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                }
            )
        groups.sort(key=lambda item: item["service"])
        optional = [
            {
                "service": "Macie",
                "purpose": "Improves sensitive-data exposure evidence for data protection reviews.",
            },
            {
                "service": "Inspector",
                "purpose": "Adds workload vulnerability posture context to compute findings.",
            },
            {
                "service": "Detective",
                "purpose": "Adds investigation context for threat-detection findings.",
            },
            {
                "service": "Trusted Advisor",
                "purpose": "Adds curated posture checks that can complement control validation.",
            },
            {
                "service": "Resource Explorer",
                "purpose": "Improves asset discovery coverage and cross-service inventory validation.",
            },
            {
                "service": "Backup",
                "purpose": "Improves backup and resilience evidence for recovery-related controls.",
            },
        ]
        policy = {
            "Version": "2012-10-17",
            "PolicyName": "CSAO_Assessment_ReadOnly",
            "Statement": statements,
        }
        lines = [
            "# CSAO Access Requirements",
            "",
            "CSAO performs a read-only security assessment.",
            "",
            "- The assessment does not modify customer cloud resources.",
            "- Assessment execution uses read/list/describe/get APIs.",
            "- The only write-like operation is STS AssumeRole for temporary credentials.",
            "",
            "## Supported Authentication",
            "",
            "- AWS Profile",
            "- IAM Access Keys",
            "- Assume Role",
            "- AWS SSO (Future)",
            "",
            "## Required IAM Permissions",
            "",
        ]
        for group in groups:
            lines.extend(
                [
                    f"### {group['service']}",
                    f"- Purpose: {group['purpose']}",
                    f"- Collectors: {', '.join(group['collectors'])}",
                    f"- Evidence Produced: {', '.join(group['evidence'])}",
                    f"- Assessment Domain: {group['domain']}",
                    "- Required Actions:",
                ]
            )
            lines.extend([f"  - `{action}`" for action in group["actions"]])
            lines.append("")
        lines.extend(
            [
                "## Optional Permissions",
                "",
                "These services improve assessment quality when available:",
                "",
            ]
        )
        lines.extend(
            [f"- {item['service']}: {item['purpose']}" for item in optional]
        )
        lines.extend(
            [
                "",
                "## Capability Validation Mapping",
                "",
                "Use the Capability Validation page to compare allowed permissions "
                "with observed service availability and access-denied results.",
                "",
                "## Future Multi-Cloud",
                "",
                "- Google Cloud Platform: Planned for Future Release",
                "- Microsoft Azure: Planned for Future Release",
            ]
        )
        explanation_rows = []
        for group in groups:
            explanation_rows.append(
                {
                    "service": group["service"],
                    "why_access_is_needed": group["purpose"],
                    "collector": ", ".join(group["collectors"]),
                    "evidence_produced": ", ".join(group["evidence"]),
                    "assessment_domain": group["domain"],
                    "capability_href": group["capability_href"],
                    "classification": group.get("classification", "required"),
                }
            )
        permission_matrix = []
        for collector in collector_rows:
            if not collector.get("enabled"):
                continue
            for permission in collector.get("permissions", []):
                permission_matrix.append(
                    {
                        "aws_service": permission.get("service", ""),
                        "collector": collector["name"],
                        "aws_apis": permission.get("apis", []),
                        "iam_actions": permission.get("actions", []),
                        "purpose": permission.get("purpose")
                        or permission.get("capability", ""),
                        "evidence_collected": permission.get("evidence", []),
                        "assessment_capability_enabled": permission.get("capability", ""),
                        "classification": permission.get("classification", "required"),
                    }
                )
        assessment_account_id = str(trust_account_id or "").strip() or self._default_assessment_account_id()
        configured_role_name = str(assessment_role_name or "").strip() or self._default_assessment_role_name()
        trust_payload = self._build_trust_policy(
            assessment_account_id=assessment_account_id,
            assessment_role_name=configured_role_name,
            use_root_trust=use_root_trust,
            use_external_id=use_external_id,
            external_id=external_id,
        )
        trust_policy = trust_payload["trust_policy"]
        trust_settings = {
            "assessment_account_id": assessment_account_id,
            "assessment_role_name": configured_role_name,
            "use_root_trust": use_root_trust,
            "use_external_id": use_external_id,
            "external_id": trust_payload["external_id"],
        }
        policy_validation = self._validate_access_requirements_bundle(
            policy=policy,
            trust_policy=trust_policy,
            groups=groups,
            collector_rows=collector_rows,
            trust_settings=trust_settings,
        )
        services_covered = self._services_covered_payload(groups, optional)
        onboarding_package = self._build_onboarding_package(
            policy=policy,
            trust_policy=trust_policy,
            trust_settings=trust_settings,
            validation=policy_validation,
            permission_matrix=permission_matrix,
            services_covered=services_covered,
        )
        policy_summary_rows = self._policy_summary_rows(groups)
        policy_query_string = self._policy_query_string(trust_settings)
        auth_cards = [
            {
                "name": "AWS Profile",
                "slug": "profile",
                "use_case": "Local development and analyst workstations with a configured AWS CLI profile.",
                "security_recommendation": "Best for internal testing and controlled operator environments.",
                "required_fields": ["Profile Name"],
                "enterprise_suitability": "Medium",
                "recommended": False,
            },
            {
                "name": "Assume Role",
                "slug": "assume_role",
                "use_case": "Enterprise onboarding with customer-managed trust boundaries and temporary credentials.",
                "security_recommendation": "Recommended for production enterprise environments.",
                "required_fields": ["Role ARN", "Source Profile"],
                "enterprise_suitability": "High",
                "recommended": True,
            },
            {
                "name": "Access Keys",
                "slug": "access_keys",
                "use_case": "Standalone accounts or interim onboarding where role assumption is not yet available.",
                "security_recommendation": "Use only when a role or profile workflow is unavailable.",
                "required_fields": ["Access Key ID", "Secret Access Key"],
                "enterprise_suitability": "Low",
                "recommended": False,
            },
            {
                "name": "IAM Identity Center",
                "slug": "sso",
                "use_case": "Organizations standardizing on IAM Identity Center-backed CLI access.",
                "security_recommendation": "Coming soon for guided onboarding; currently requires an existing CLI SSO profile.",
                "required_fields": ["Profile Name", "SSO Start URL", "SSO Account ID", "SSO Role Name", "SSO Region"],
                "enterprise_suitability": "High",
                "recommended": False,
            },
        ]
        quick_start_steps = [
            {
                "title": "Create Read-Only IAM Role",
                "description": "Create a dedicated assessment role in the customer AWS account for CSAO.",
            },
            {
                "title": "Attach Generated IAM Policy",
                "description": "Apply the dynamic least-privilege policy generated from the currently enabled collectors.",
            },
            {
                "title": "Configure Trust Relationship",
                "description": "Allow the approved CSAO principal to assume the role using `sts:AssumeRole`.",
            },
            {
                "title": "Validate Connection",
                "description": "Use Cloud Accounts to confirm STS identity, region access, and baseline credential health.",
            },
            {
                "title": "Save Cloud Account",
                "description": "Store the validated account in the encrypted workbench vault for ongoing assessment use.",
            },
            {
                "title": "Launch Assessment",
                "description": "Start the read-only cloud security assessment from the assessment workflow.",
            },
        ]
        required_services = services_covered["required_services"]
        optional_services = services_covered["optional_services"]
        collector_count = sum(1 for collector in collector_rows if collector.get("enabled"))
        permission_count = len(permission_matrix)
        optional_available = sum(
            1
            for name in [item["service"] for item in optional]
            if any(row["service"] == name for row in groups)
        )
        readiness = [
            {"label": "IAM Role Created", "status": "Guided", "detail": "Use the generated IAM policy and trust policy below."},
            {"label": "Connection Validated", "status": "Ready", "detail": "Validated in Cloud Accounts before saving the account."},
            {"label": "STS Verified", "status": "Ready", "detail": "CSAO uses STS only to acquire temporary role credentials."},
            {"label": "Permissions Verified", "status": "Ready", "detail": f"{permission_count} permission mappings are generated from enabled collectors."},
            {"label": "Regions Discovered", "status": "Ready", "detail": "Regions are validated during account connection testing."},
            {"label": "Collectors Available", "status": "Ready", "detail": f"{collector_count} collector definitions are available for onboarding."},
            {"label": "Assessment Ready", "status": "Ready", "detail": "Complete validation and launch the assessment workflow."},
        ]
        impact_rows = []
        for group in groups:
            severity = "Medium"
            if group["service"] in {"IAM", "EC2", "VPC", "S3"}:
                severity = "High"
            if group["service"] in {"CloudTrail", "Config"}:
                severity = "Medium"
            impact_rows.append(
                {
                    "service": group["service"],
                    "purpose": group["purpose"],
                    "impact": f"{group['service']} assessment coverage cannot be completed.",
                    "severity": severity,
                    "collectors": group["collectors"],
                }
            )
        return {
            "overview": {
                "title": "Read-Only Enterprise Onboarding Guide",
                "statements": [
                    "CSAO performs a read-only security assessment.",
                    "The assessment never modifies customer cloud resources.",
                    "Assessment execution uses only read/list/describe/get APIs.",
                    "The only write-like operation is STS AssumeRole for obtaining temporary credentials.",
                ],
            },
            "executive_summary": {
                "average_setup_time": "5-10 minutes",
                "supported_clouds": ["AWS", "Azure (Planned)", "Google Cloud (Planned)"],
                "workflow": [
                    "Configure access",
                    "Validate connection",
                    "Save account",
                    "Launch assessment",
                    "Review evidence and results",
                ],
            },
            "authentication_methods": [
                "AWS Profile",
                "IAM Access Keys",
                "Assume Role",
                "AWS SSO (Future)",
            ],
            "authentication_cards": auth_cards,
            "quick_start_steps": quick_start_steps,
            "required_permissions": groups,
            "optional_permissions": optional,
            "required_services": required_services,
            "optional_services": optional_services,
            "coverage_summary": {
                "core_coverage": "100%",
                "enhanced_coverage": f"{max(80, 80 + min(optional_available, 6) * 2)}%",
                "advanced_detection": "Available when optional services are enabled.",
            },
            "assessment_readiness": readiness,
            "service_impact_matrix": impact_rows,
            "permission_explanations": explanation_rows,
            "collector_permissions": collector_rows,
            "permission_matrix": permission_matrix,
            "services_covered": services_covered,
            "enabled_collectors": sorted(enabled),
            "policy": policy,
            "policy_json": json.dumps(policy, indent=2),
            "trust_policy": trust_policy,
            "trust_policy_json": json.dumps(trust_policy, indent=2),
            "trust_settings": trust_settings,
            "policy_validation": policy_validation,
            "policy_summary_rows": policy_summary_rows,
            "policy_query_string": f"?{policy_query_string}" if policy_query_string else "",
            "onboarding_package": {
                "path": str(onboarding_package),
                "filename": onboarding_package.name,
            },
            "policy_markdown": "\n".join(lines),
            "technical_reference": {
                "collector_count": collector_count,
                "permission_count": permission_count,
                "service_count": len(groups),
            },
            "faq": faq,
            "security_transparency": {
                "read_only_guarantee": read_only_guarantee,
                "tool_validation": self.external_tool_validation(),
                "safety_validation": self.safety_validation(),
            },
        }

    def open_assessment(self, assessment_id: str) -> None:
        history = self.assessment_history()
        selected = next(
            (item for item in history if item.get("id") == assessment_id), None
        )
        if not selected:
            raise KeyError(f"Unknown assessment {assessment_id}")

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            state["active_assessment_id"] = assessment_id
            state["active_output_root"] = selected.get("snapshot_directory") or "output"
            return state

        self.state = self.state_store.update(mutate)
        self.refresh()

    def current_output_root(self) -> str:
        return str(self.base_directory)

    def validation_statuses(self) -> List[str]:
        return [
            "CONFIRMED",
            "FALSE_POSITIVE",
            "ACCEPTED_RISK",
            "NEEDS_REVIEW",
            "NOT_APPLICABLE",
        ]

    def save_validation(self, register_id: str, status: str, notes: str = "") -> None:
        register_id = str(register_id or "").strip()
        if not register_id:
            raise ValueError("register_id is required")
        status = str(status or "NEEDS_REVIEW").strip().upper()
        if status not in self.validation_statuses():
            raise ValueError(f"Unsupported validation status: {status}")

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            validations = dict(state.get("finding_validations", {}) or {})
            validations[register_id] = {
                "status": status,
                "notes": notes.strip(),
                "updated_at": format_time(dt.datetime.now().timestamp()),
            }
            state["finding_validations"] = validations
            return state

        self.state = self.state_store.update(mutate)
        self.refresh()

    def settings_payload(self) -> Dict[str, Any]:
        return self.state.get("settings_overrides", {}) or {}

    def settings_view_model(self) -> Dict[str, Any]:
        config = self.config
        reports = config.get("reports", {}) or {}
        execution = config.get("execution", {}) or {}
        logging = config.get("logging", {}) or {}
        aws = config.get("aws", {}) or {}
        output = config.get("output", {}) or {}
        return {
            "general": {
                "default_region": (aws.get("regions") or ["us-east-1"])[0],
                "additional_regions": ", ".join((aws.get("regions") or [])[1:]),
                "output_folder": output.get("root_directory", "output"),
                "concurrency": execution.get("max_threads", 6),
                "timeout": execution.get("timeout", 3600),
            },
            "assessment": {
                "threat_correlation": bool(
                    config.get("correlation", {}).get("correlate_findings", True)
                ),
                "risk_scoring": bool(
                    config.get("risk_scoring", {}).get("enabled", True)
                ),
                "recommendation_generation": True,
            },
            "logging": {
                "level": logging.get("level", "INFO"),
                "debug_mode": logging.get("level", "INFO") == "DEBUG",
                "retention": "30 days",
            },
            "reporting": {
                "executive_report": bool(reports.get("generate_html", True)),
                "technical_report": bool(reports.get("generate_html", True)),
                "mitre_report": True,
                "checklist_report": True,
                "evidence_report": True,
                "attack_path_report": True,
            },
            "theme": self.state.get("theme", "operator"),
            "collectors": self.available_collectors(),
            "region_options": self.supported_regions(),
            "report_format_options": self.report_type_options(),
            "log_level_options": ["DEBUG", "INFO", "WARNING", "ERROR"],
            "parallel_options": [
                {"value": "true", "label": "Enabled"},
                {"value": "false", "label": "Disabled"},
            ],
            "theme_options": [
                {"value": "operator", "label": "Operator"},
                {"value": "analyst", "label": "Analyst"},
            ],
        }

    def save_settings(self, payload: Dict[str, Any]) -> None:
        collector_selection = set(payload.get("collectors", []))
        modules = {}
        for key in (self.config.get("modules", {}) or {}).keys():
            modules[key] = key in collector_selection
        report_formats = set(payload.get("report_formats", []))
        region_values = [
            item.strip()
            for item in str(payload.get("regions") or "").split(",")
            if item.strip()
        ]
        default_region = str(payload.get("default_region") or "").strip()
        additional_regions = [
            item.strip()
            for item in str(payload.get("additional_regions") or "").split(",")
            if item.strip()
        ]
        all_regions = [
            item
            for item in [default_region] + additional_regions + region_values
            if item
        ]
        if not all_regions:
            all_regions = list(self.config.get("aws", {}).get("regions", []))
        overrides = {
            "aws": {
                "regions": all_regions,
            },
            "execution": {
                "max_threads": int(
                    payload.get("max_threads")
                    or self.config.get("execution", {}).get("max_threads", 6)
                ),
                "parallel_execution": parse_bool(
                    payload.get("parallel_execution") or "true"
                ),
                "retry_count": int(
                    payload.get("retry_count")
                    or self.config.get("execution", {}).get("retry_count", 3)
                ),
                "timeout": int(
                    payload.get("timeout")
                    or self.config.get("execution", {}).get("timeout", 3600)
                ),
            },
            "logging": {
                "level": str(
                    payload.get("log_level")
                    or self.config.get("logging", {}).get("level", "INFO")
                ).upper(),
            },
            "output": {
                "root_directory": str(
                    payload.get("output_folder")
                    or self.config.get("output", {}).get("root_directory", "output")
                ),
                "reports_directory": str(
                    payload.get("reports_directory")
                    or self.config.get("output", {}).get(
                        "reports_directory", "output/reports"
                    )
                ),
            },
            "reports": {
                "generate_html": "generate_html" in report_formats,
                "generate_pdf": "generate_pdf" in report_formats,
                "generate_json": "generate_json" in report_formats,
                "generate_csv": "generate_csv" in report_formats,
            },
            "correlation": {
                "correlate_findings": parse_bool(
                    payload.get("threat_correlation") or "true"
                ),
            },
            "risk_scoring": {
                "enabled": parse_bool(payload.get("risk_enabled") or "true"),
            },
            "modules": modules,
        }

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            state["settings_overrides"] = overrides
            state["theme"] = str(
                payload.get("theme") or state.get("theme") or "operator"
            )
            return state

        self.state = self.state_store.update(mutate)
        self.refresh()

    def report_format_flags(self) -> List[str]:
        reports = self.config.get("reports", {}) or {}
        return [
            key
            for key in (
                "generate_html",
                "generate_pdf",
                "generate_json",
                "generate_csv",
            )
            if reports.get(key)
        ]

    def assessment_estimate(
        self, collectors: List[str], regions: List[str]
    ) -> Dict[str, Any]:
        collector_count = len(collectors)
        region_count = len(regions) or 1
        estimated_minutes = max(10, region_count * 6 + collector_count * 8)
        return {
            "estimated_minutes": estimated_minutes,
            "estimated_regions": region_count,
            "estimated_collectors": collector_count,
            "estimated_apis": max(5, collector_count * region_count * 4),
        }

    def evidence_sources(
        self, source_filter: str = "", search: str = ""
    ) -> List[Dict[str, Any]]:
        if self.summary.get("evidence_rows"):
            rows = []
            for item in self.summary.get("evidence_rows", []):
                if source_filter and item.get("source") != source_filter:
                    continue
                if search and search.lower() not in " ".join(
                    str(v) for v in item.values()
                ).lower():
                    continue
                row = dict(item)
                if row.get("modified"):
                    row["modified"] = format_time(
                        dt.datetime.fromisoformat(
                            row["modified"].replace("Z", "+00:00")
                        ).timestamp()
                    )
                row["collector"] = row.get("collector") or row.get("source") or "Unknown"
                row["aws_service"] = (
                    row.get("aws_service")
                    or row.get("service")
                    or row.get("source")
                    or "Unknown"
                )
                row["region"] = row.get("region") or row.get("aws_region") or "N/A"
                row["resource"] = (
                    row.get("resource")
                    or row.get("resource_id")
                    or row.get("name")
                    or Path(str(row.get("path") or "")).name
                    or "N/A"
                )
                row["evidence_type"] = (
                    row.get("evidence_type") or row.get("kind") or "file"
                )
                row["timestamp"] = row.get("timestamp") or row.get("modified") or ""
                row["checklist_controls"] = list(row.get("checklist_controls") or [])
                rows.append(row)
            return rows
        rows = []
        raw_dir = self.base_directory / "raw"
        for source, files in (self.evidence_index or {}).items():
            if source_filter and source != source_filter:
                continue
            for file_path in files:
                path = Path(file_path)
                if not path.is_absolute():
                    path = Path(file_path)
                if not path.exists() and raw_dir.exists():
                    alt = raw_dir / source / Path(file_path).name
                    path = alt if alt.exists() else path
                row = {
                    "source": source,
                    "path": str(path),
                    "name": path.name,
                    "exists": path.exists(),
                    "size": path.stat().st_size if path.exists() else 0,
                    "modified": (
                        format_time(path.stat().st_mtime) if path.exists() else ""
                    ),
                    "kind": path.suffix.lstrip(".") or "file",
                }
                region_match = re.search(
                    r"\b(?:us|ca|eu|ap|sa|af|me)-[a-z]+-\d\b", str(path)
                )
                if (
                    search
                    and search.lower()
                    not in " ".join(str(v) for v in row.values()).lower()
                ):
                    continue
                rows.append(
                    {
                        **row,
                        "collector": source,
                        "aws_service": source,
                        "region": region_match.group(0) if region_match else "N/A",
                        "resource": path.stem,
                        "evidence_type": row["kind"],
                        "timestamp": row["modified"],
                        "checklist_controls": [],
                    }
                )
        if not rows and raw_dir.exists():
            for path in sorted(raw_dir.rglob("*.json")):
                row = {
                    "source": path.parent.name,
                    "path": str(path),
                    "name": path.name,
                    "exists": True,
                    "size": path.stat().st_size,
                    "modified": format_time(path.stat().st_mtime),
                    "kind": path.suffix.lstrip(".") or "file",
                }
                region_match = re.search(
                    r"\b(?:us|ca|eu|ap|sa|af|me)-[a-z]+-\d\b", str(path)
                )
                if source_filter and row["source"] != source_filter:
                    continue
                if (
                    search
                    and search.lower()
                    not in " ".join(str(v) for v in row.values()).lower()
                ):
                    continue
                rows.append(row)
                rows[-1].update(
                    {
                        "collector": row["source"],
                        "aws_service": row["source"],
                        "region": region_match.group(0) if region_match else "N/A",
                        "resource": path.stem,
                        "evidence_type": row["kind"],
                        "timestamp": row["modified"],
                        "checklist_controls": [],
                    }
                )
        return rows

    def evidence_sources_grouped(self) -> List[str]:
        if self.summary.get("evidence_rows"):
            return sorted(
                {
                    item.get("source", "")
                    for item in self.summary.get("evidence_rows", [])
                    if item.get("source")
                }
            )
        return sorted({item["source"] for item in self.evidence_sources()})

    def evidence_preview(self, path_value: str, search: str = "") -> Dict[str, Any]:
        path = self.resolve_evidence_path(path_value)
        if not path.exists():
            return {
                "path": path_value,
                "content": "Evidence file not found.",
                "downloadable": False,
            }
        content = path.read_text(encoding="utf-8", errors="replace")
        if search:
            lines = [
                line for line in content.splitlines() if search.lower() in line.lower()
            ]
            content = "\n".join(lines[:200]) if lines else "No matching lines."
        return {
            "path": str(path),
            "content": content[:50000],
            "downloadable": True,
            "size": path.stat().st_size,
            "modified": format_time(path.stat().st_mtime),
            "source": path.parent.name,
        }

    def resolve_evidence_path(self, path_value: str) -> Path:
        raw_dir = self.base_directory / "raw"
        candidate = Path(unquote(path_value))
        allowed_roots = [self.base_directory.resolve()]
        if raw_dir.exists():
            allowed_roots.append(raw_dir.resolve())
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not any(str(candidate).startswith(str(root)) for root in allowed_roots):
            raise ValueError("Evidence path is outside the active assessment output.")
        return candidate

    def _activity_artifacts(self) -> List[Path]:
        return [
            self.base_directory / "discovery" / "asset_inventory.json",
            self.base_directory / "raw" / "aws_inventory" / "ec2.json",
            self.base_directory / "evidence_index.json",
            self.base_directory / "normalized" / "findings.json",
            self.base_directory / "assessment_register" / "assessment_register.json",
            self.base_directory / "checklist" / "checklist_coverage.json",
            self.base_directory / "threats" / "threat_scenarios.json",
            self.base_directory / "threats" / "correlated_threats.json",
            self.base_directory / "attack_paths" / "attack_path_candidates.json",
            self.base_directory / "risk" / "risk_summary.json",
            self.base_directory / "assessment_register" / "recommendations.json",
            self.base_directory / "reports" / "index.html",
        ]

    def recent_logs(self, limit: int = 80) -> List[str]:
        log_path = Path("logs/framework.log")
        if not log_path.exists():
            return []
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []
        return lines[-limit:]

    def _stage_artifacts(self, key: str) -> List[Path]:
        mapping = {
            "discovery": [self.base_directory / "discovery" / "asset_inventory.json"],
            "inventory": [self.base_directory / "raw" / "aws_inventory"],
            "crown_jewel": [
                self.base_directory / "crown_jewel" / "identified_assets.json"
            ],
            "evidence_collection": [
                self.base_directory / "evidence_index.json",
                self.base_directory / "raw" / "prowler",
                self.base_directory / "raw" / "cloudsplaining",
                self.base_directory / "raw" / "steampipe",
                self.base_directory / "raw" / "access_analyzer",
                self.base_directory / "raw" / "config_aggregator",
                self.base_directory / "raw" / "cartography",
                self.base_directory / "raw" / "tenable",
            ],
            "normalization": [self.base_directory / "normalized" / "findings.json"],
            "assessment_register": [
                self.base_directory / "assessment_register" / "assessment_register.json"
            ],
            "checklist_validation": [
                self.base_directory / "checklist" / "checklist_coverage.json"
            ],
            "threat_validation": [
                self.base_directory / "threats" / "threat_scenarios.json"
            ],
            "threat_correlation": [
                self.base_directory / "threats" / "correlated_threats.json"
            ],
            "attack_paths": [
                self.base_directory / "attack_paths" / "attack_path_candidates.json"
            ],
            "risk_prioritization": [
                self.base_directory / "risk" / "risk_summary.json",
                self.base_directory / "risk" / "risk_findings.json",
            ],
            "recommendations": [
                self.base_directory / "assessment_register" / "recommendations.json",
                self.base_directory / "recommendations" / "recommendations.json",
            ],
            "traceability": [
                self.base_directory / "traceability" / "traceability_graph.json"
            ],
            "reporting": [self.base_directory / "reports" / "index.html"],
        }
        return mapping.get(key, [])

    def _artifact_times(self, artifacts: List[Path]) -> Dict[str, Optional[float]]:
        file_paths = []
        for artifact in artifacts:
            if artifact.is_file():
                file_paths.append(artifact)
            elif artifact.is_dir():
                file_paths.extend(
                    [path for path in artifact.rglob("*") if path.is_file()]
                )
        if not file_paths:
            return {"start": None, "finish": None}
        return {
            "start": min(path.stat().st_mtime for path in file_paths),
            "finish": max(path.stat().st_mtime for path in file_paths),
        }

    def stage_states(self) -> List[StageState]:
        overrides = self.state.get("stages", {}) or {}
        stages = []
        for key, label in self.STAGE_ORDER:
            artifacts = self._stage_artifacts(key)
            times = self._artifact_times(artifacts)
            artifact_exists = any(
                artifact.exists() if artifact.is_file() else artifact.is_dir()
                for artifact in artifacts
            )
            status = "COMPLETED" if artifact_exists else "NOT_RUN"
            if (
                key == "inventory"
                and not artifact_exists
                and not self.config.get("modules", {}).get("aws_inventory", True)
            ):
                status = "SKIPPED"
            if key in overrides:
                status = overrides[key].get("status", status)
            stage = StageState(
                key=key,
                label=label,
                status=status,
                start_time=overrides.get(key, {}).get("start_time")
                or format_time(times["start"]),
                finish_time=overrides.get(key, {}).get("finish_time")
                or format_time(times["finish"]),
                duration=overrides.get(key, {}).get("duration")
                or format_duration(times["start"], times["finish"]),
                errors=list(overrides.get(key, {}).get("errors", []) or []),
                retryable=True,
                artifacts=[str(artifact) for artifact in artifacts],
            )
            stages.append(stage)
        return stages

    def register_rows(
        self, filters: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        filters = filters or {}
        search = (filters.get("search") or "").strip().lower()
        rows = []
        findings_by_register = {
            entry.assessment_register_id: entry
            for entry in self.findings
            if entry.assessment_register_id
        }
        checklist_by_id = {
            item.get("id"): item for item in self.knowledge.checklist_items
        }
        scenario_by_id = {
            scenario.scenario_id: scenario for scenario in self.threat_scenarios
        }
        correlated_by_scenario = {}
        for threat in self.correlated_threats:
            for scenario_id in threat.scenario_ids:
                correlated_by_scenario.setdefault(scenario_id, []).append(threat)

        for entry in self.register_entries:
            finding = findings_by_register.get(entry.register_id)
            checklist_ids = list(entry.checklist_references or [])
            if finding and finding.checklist_ids:
                checklist_ids = list(
                    dict.fromkeys(checklist_ids + finding.checklist_ids)
                )
            threat_ids = list(entry.threat_scenario_references or [])
            if finding and finding.threat_scenario_ids:
                threat_ids = list(
                    dict.fromkeys(threat_ids + finding.threat_scenario_ids)
                )
            attack_path_ids = list(entry.attack_path_references or [])
            if finding and finding.attack_path_ids:
                attack_path_ids = list(
                    dict.fromkeys(attack_path_ids + finding.attack_path_ids)
                )

            risk_score = finding._risk_score if finding else entry.risk_score
            status = entry.validation_status or (
                finding.validation_status if finding else "NOT_EVALUATED"
            )
            row = {
                "finding_id": entry.finding_id,
                "register_id": entry.register_id,
                "severity": entry.severity,
                "cloud_service": entry.service,
                "resource": entry.resource_name or entry.resource,
                "evidence": (
                    entry.evidence_references[0]
                    if entry.evidence_references
                    else (finding.evidence_location if finding else "")
                ),
                "checklist_controls": checklist_ids,
                "threat_scenarios": threat_ids,
                "risk": round(risk_score or 0, 2),
                "status": status,
                "analyst_notes": entry.analyst_notes
                or (finding.analyst_notes if finding else ""),
                "crown_jewel": entry.crown_jewel == "Yes"
                or (finding.crown_jewel == "Yes" if finding else False),
                "internet_facing": entry.internet_facing == "Yes"
                or (finding.internet_facing == "Yes" if finding else False),
                "risk_bucket": self._risk_bucket(risk_score or 0),
                "manual_review": status == "MANUAL_REVIEW",
                "needs_review": status in {"MANUAL_REVIEW", "NOT_EVALUATED"},
                "finding": finding,
                "entry": entry,
                "checklist_titles": [
                    checklist_by_id[cid].get("title", cid)
                    for cid in checklist_ids
                    if cid in checklist_by_id
                ],
                "scenario_titles": [
                    scenario_by_id[sid].title
                    for sid in threat_ids
                    if sid in scenario_by_id
                ],
                "correlated_threats": [
                    threat.correlation_id
                    for sid in threat_ids
                    for threat in correlated_by_scenario.get(sid, [])
                ],
                "attack_path_ids": attack_path_ids,
            }
            if search:
                haystack = " ".join(
                    str(value) for value in row.values() if value is not None
                ).lower()
                if search not in haystack:
                    continue
            if filters.get("high_risk") and row["risk_bucket"] not in {
                "HIGH",
                "CRITICAL",
            }:
                continue
            if filters.get("needs_review") and not row["needs_review"]:
                continue
            if filters.get("manual_validation") and row["status"] != "MANUAL_REVIEW":
                continue
            if filters.get("crown_jewel") and not row["crown_jewel"]:
                continue
            if filters.get("internet_facing") and not row["internet_facing"]:
                continue
            rows.append(row)
        rows.sort(key=lambda row: row["risk"], reverse=True)
        return rows

    def _risk_bucket(self, risk_score: float) -> str:
        if risk_score >= 90:
            return "CRITICAL"
        if risk_score >= 70:
            return "HIGH"
        if risk_score >= 40:
            return "MEDIUM"
        if risk_score >= 10:
            return "LOW"
        return "INFO"

    def checklist_rows(self) -> List[Dict[str, Any]]:
        coverage_by_id = {item.get("id"): item for item in self.checklist_coverage}
        rows = []
        for item in self.knowledge.checklist_items:
            coverage = coverage_by_id.get(item.get("id"), {})
            rows.append(
                {
                    "id": item.get("id"),
                    "title": item.get("title", ""),
                    "domain": item.get("domain", "Uncategorized"),
                    "status": coverage.get("status", "NOT_EVALUATED"),
                    "evidence_type": item.get("evidence_type", ""),
                    "collection_method": item.get("collection_method", ""),
                    "output_document": item.get("output_document", ""),
                    "manual_validation_required": bool(
                        item.get("manual_validation_required")
                    ),
                    "matched_findings": coverage.get("matched_findings", 0),
                    "register_ids": coverage.get("register_ids", []),
                    "sources": coverage.get("sources", []),
                    "related_attack_paths": coverage.get("related_attack_paths", []),
                    "threat_scenario_ids": coverage.get("threat_scenario_ids", []),
                    "priority_tier": item.get("priority_tier", ""),
                    "severity": item.get("severity", ""),
                    "mitre_mapping": item.get("mitre_mapping", {}),
                    "finding_count": coverage.get("matched_findings", 0),
                }
            )
        return rows

    def coverage_rows(self) -> List[Dict[str, Any]]:
        rows = self.checklist_rows()
        by_domain: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            domain = row.get("domain") or "Uncategorized"
            entry = by_domain.setdefault(
                domain,
                {
                    "domain": domain,
                    "implemented_controls": 0,
                    "automatically_validated": 0,
                    "manual_validation_required": 0,
                    "not_covered": 0,
                },
            )
            entry["implemented_controls"] += 1
            if row.get("manual_validation_required"):
                entry["manual_validation_required"] += 1
            if row.get("status") in {"PASS", "FAIL"} and not row.get(
                "manual_validation_required"
            ):
                entry["automatically_validated"] += 1
            if row.get("status") == "NOT_EVALUATED":
                entry["not_covered"] += 1
        result = []
        for entry in sorted(by_domain.values(), key=lambda item: item["domain"]):
            total = entry["implemented_controls"] or 1
            entry["coverage_percentage"] = round(
                ((entry["implemented_controls"] - entry["not_covered"]) / total) * 100,
                2,
            )
            result.append(entry)
        return result

    def coverage_summary(self) -> Dict[str, Any]:
        rows = self.coverage_rows()
        return {
            "rows": rows,
            "domains": len(rows),
            "implemented_controls": sum(item["implemented_controls"] for item in rows),
            "automatically_validated": sum(
                item["automatically_validated"] for item in rows
            ),
            "manual_validation_required": sum(
                item["manual_validation_required"] for item in rows
            ),
            "not_covered": sum(item["not_covered"] for item in rows),
            "average_coverage": round(
                (
                    sum(item["coverage_percentage"] for item in rows) / len(rows)
                    if rows
                    else 0
                ),
                2,
            ),
        }

    def scenario_rows(self) -> List[Dict[str, Any]]:
        coverage_by_id = {item.get("id"): item for item in self.checklist_coverage}
        scenario_map = {
            scenario.scenario_id: scenario for scenario in self.threat_scenarios
        }
        correlated_by_scenario = {}
        for threat in self.correlated_threats:
            for scenario_id in threat.scenario_ids:
                correlated_by_scenario.setdefault(scenario_id, []).append(threat)
        rows = []
        for scenario in self.knowledge.scenarios:
            actual = scenario_map.get(scenario.scenario_id)
            prerequisites = scenario.prerequisite_checklists
            control_statuses = [
                coverage_by_id.get(control, {}).get("status", "NOT_EVALUATED")
                for control in prerequisites
            ]
            validated_controls = [
                control
                for control, status in zip(prerequisites, control_statuses)
                if status in {"PASS", "CONFIRMED", "COMPLETED"}
            ]
            missing_controls = [
                control
                for control, status in zip(prerequisites, control_statuses)
                if status in {"NOT_EVALUATED", "MANUAL_REVIEW", "FAIL"}
            ]
            rows.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "title": scenario.title,
                    "status": (actual.status if actual else scenario.status),
                    "validated_controls": validated_controls,
                    "missing_controls": missing_controls,
                    "stride_category": getattr(scenario, "stride_category", "")
                    or getattr(scenario, "stride", ""),
                    "affected_crown_jewels": list(scenario.crown_jewel_types),
                    "evidence": list(
                        (
                            actual.supporting_evidence
                            if actual
                            else scenario.supporting_evidence
                        )
                        or []
                    ),
                    "mitre_mapping": {
                        "tactics": list(scenario.mitre_tactics),
                        "techniques": list(scenario.mitre_techniques),
                    },
                    "recommendations": list(scenario.recommendation_refs),
                    "attack_paths": list(scenario.attack_path_refs),
                    "business_impact": (
                        actual.business_impact if actual and getattr(actual, "business_impact", "")
                        else scenario.business_impact
                    ),
                    "risk_level": (
                        actual.risk_level if actual and getattr(actual, "risk_level", "")
                        else scenario.risk_level
                    ),
                    "correlated_threats": [
                        threat.correlation_id
                        for threat in correlated_by_scenario.get(
                            scenario.scenario_id, []
                        )
                    ],
                }
            )
        return rows

    def correlated_rows(self) -> List[Dict[str, Any]]:
        rows = []
        for threat in self.correlated_threats:
            rows.append(
                {
                    "correlation_id": threat.correlation_id,
                    "scenario_ids": list(threat.scenario_ids),
                    "status": threat.status,
                    "attack_path_refs": list(threat.attack_path_refs),
                    "source_resources": list(threat.source_resources),
                    "target_resources": list(threat.target_resources),
                    "supporting_evidence": list(threat.supporting_evidence),
                    "validated_register_ids": list(threat.validated_register_ids),
                    "analyst_decision": threat.analyst_decision,
                    "correlation_reason": threat.correlation_reason,
                    "chain": self._correlation_chain(threat),
                }
            )
        return rows

    def _correlation_chain(self, threat: CorrelatedThreat) -> List[Dict[str, Any]]:
        chain = []
        for index, scenario_id in enumerate(threat.scenario_ids):
            scenario = next(
                (
                    item
                    for item in self.threat_scenarios
                    if item.scenario_id == scenario_id
                ),
                None,
            )
            chain.append(
                {
                    "label": scenario.title if scenario else scenario_id,
                    "scenario_id": scenario_id,
                    "evidence": list(
                        (scenario.supporting_evidence if scenario else []) or []
                    ),
                    "index": index,
                }
            )
        return chain

    def attack_path_graph(self) -> Dict[str, Any]:
        nodes = [
            {
                "id": "internet",
                "label": "Internet",
                "kind": "category",
                "color": "#ef4444",
                "details_url": "/api/node/category/internet",
            },
            {
                "id": "cloud",
                "label": "Cloud Resources",
                "kind": "category",
                "color": "#0f766e",
                "details_url": "/api/node/category/cloud",
            },
            {
                "id": "iam",
                "label": "IAM",
                "kind": "category",
                "color": "#2563eb",
                "details_url": "/api/node/category/iam",
            },
            {
                "id": "storage",
                "label": "Storage",
                "kind": "category",
                "color": "#7c3aed",
                "details_url": "/api/node/category/storage",
            },
            {
                "id": "compute",
                "label": "Compute",
                "kind": "category",
                "color": "#f59e0b",
                "details_url": "/api/node/category/compute",
            },
            {
                "id": "crown_jewels",
                "label": "Crown Jewels",
                "kind": "category",
                "color": "#111827",
                "details_url": "/api/node/category/crown_jewels",
            },
        ]
        edges = []
        seen_nodes = {node["id"] for node in nodes}
        for candidate in self.attack_path_candidates:
            hops = candidate.get("hops", [])
            previous = None
            for index, hop in enumerate(hops):
                node_id = hop.get("node") or f"{candidate.get('id')}-{index}"
                label = hop.get("resource_id") or node_id
                kind = hop.get("type", "resource")
                node_entry = {
                    "id": node_id,
                    "label": label,
                    "kind": kind,
                    "resource_id": hop.get("resource_id") or label,
                    "candidate_id": candidate.get("id"),
                    "evidence": hop.get("findings", []),
                    "color": self._node_color(kind),
                    "details_url": f"/api/node/resource/{label}",
                }
                if node_id not in seen_nodes:
                    nodes.append(node_entry)
                    seen_nodes.add(node_id)
                if previous:
                    edges.append(
                        {
                            "source": previous,
                            "target": node_id,
                            "label": hop.get("relationship_from_previous")
                            or "relates_to",
                            "candidate_id": candidate.get("id"),
                        }
                    )
                previous = node_id
            if hops:
                edges.append(
                    {
                        "source": "internet",
                        "target": hops[0].get("node") or f"{candidate.get('id')}-0",
                        "label": "entry point",
                        "candidate_id": candidate.get("id"),
                    }
                )
                edges.append(
                    {
                        "source": hops[-1].get("node")
                        or f"{candidate.get('id')}-{len(hops) - 1}",
                        "target": "crown_jewels",
                        "label": "crown jewel path",
                        "candidate_id": candidate.get("id"),
                    }
                )
        return {
            "nodes": nodes,
            "edges": edges,
            "candidates": self.attack_path_candidates,
        }

    def node_detail(self, kind: str, identifier: str) -> Dict[str, Any]:
        kind = (kind or "").lower()
        identifier = identifier or ""

        if kind == "category":
            return {
                "title": identifier.replace("_", " ").title(),
                "subtitle": "Attack path category",
                "identifier": identifier,
                "status": "Summary",
                "sections": [
                    {
                        "label": "Attack Paths",
                        "value": len(self.attack_path_candidates),
                    },
                    {"label": "Findings", "value": len(self.findings)},
                    {"label": "Threat Scenarios", "value": len(self.threat_scenarios)},
                    {"label": "Recommendations", "value": len(self.recommendations)},
                ],
            }

        matching_findings = [
            finding
            for finding in self.findings
            if identifier
            in {
                finding.resource_id,
                finding.resource_name,
                finding.assessment_register_id,
            }
        ]
        register_ids = [
            finding.assessment_register_id
            for finding in matching_findings
            if finding.assessment_register_id
        ]
        checklist_ids = sorted(
            set(
                control
                for finding in matching_findings
                for control in (
                    finding.checklist_ids
                    or ([finding.checklist_id] if finding.checklist_id else [])
                )
            )
        )
        threat_ids = sorted(
            set(
                scenario
                for finding in matching_findings
                for scenario in (finding.threat_scenario_ids or [])
            )
        )
        attack_paths = sorted(
            set(
                path
                for finding in matching_findings
                for path in (finding.attack_path_ids or [])
            )
        )
        evidence = sorted(
            set(
                finding.evidence_location
                for finding in matching_findings
                if finding.evidence_location
            )
        )
        risk_scores = [finding._risk_score or 0 for finding in matching_findings]

        if matching_findings:
            detail = self._register_detail(
                matching_findings[0].assessment_register_id or identifier
            )
            detail["title"] = detail.get("title") or identifier
            detail["subtitle"] = f"Graph node: {kind}"
            detail["sections"].extend(
                [
                    {
                        "label": "Matching Findings",
                        "value": [finding.to_dict() for finding in matching_findings],
                    },
                    {"label": "Checklist Controls", "value": checklist_ids},
                    {"label": "Threat Scenarios", "value": threat_ids},
                    {"label": "Attack Paths", "value": attack_paths},
                    {"label": "Evidence", "value": evidence},
                    {"label": "Risk", "value": max(risk_scores) if risk_scores else 0},
                ]
            )
            return detail

        for candidate in self.attack_path_candidates:
            if identifier in {
                candidate.get("id"),
                candidate.get("entry_point"),
                candidate.get("crown_jewel_target"),
            }:
                return self._path_detail(candidate.get("id"))

        return {
            "title": identifier or "Graph Node",
            "subtitle": kind,
            "identifier": identifier,
            "status": "Summary",
            "sections": [
                {"label": "Evidence", "value": evidence},
                {"label": "Checklist Controls", "value": checklist_ids},
                {"label": "Threat Scenarios", "value": threat_ids},
                {"label": "Attack Paths", "value": attack_paths},
                {"label": "Register Entries", "value": register_ids},
                {"label": "Risk", "value": max(risk_scores) if risk_scores else 0},
            ],
        }

    def _node_color(self, kind: str) -> str:
        kind = str(kind or "").lower()
        if kind in {"iam_role", "iam_user", "iam"}:
            return "#2563eb"
        if kind in {"s3_bucket", "storage"}:
            return "#7c3aed"
        if kind in {"ec2", "lambda", "compute"}:
            return "#f59e0b"
        if kind in {"category"}:
            return "#111827"
        return "#0f766e"

    def risk_rows(self) -> List[Dict[str, Any]]:
        rows = []
        for finding in self.findings:
            rows.append(
                {
                    "finding_id": finding.assessment_register_id
                    or finding._tool_check_id
                    or finding.resource_id,
                    "title": finding.title,
                    "service": finding.service,
                    "resource": finding.resource_name,
                    "risk_score": finding._risk_score or 0,
                    "business_impact": finding.business_unit or finding.environment,
                    "likelihood": self._risk_bucket(finding._risk_score or 0),
                    "exposure": finding.internet_facing,
                    "detection_coverage": self.risk_summary.get(
                        "detection_gap_score", 0
                    ),
                    "affected_crown_jewels": (
                        [finding.resource_name] if finding.crown_jewel == "Yes" else []
                    ),
                    "attack_paths": list(getattr(finding, "attack_path_ids", []) or []),
                    "severity": finding.severity,
                    "recommendation_ids": list(
                        getattr(finding, "recommendation_ids", []) or []
                    ),
                    "risk_factors": dict(getattr(finding, "_risk_factors", {}) or {}),
                }
            )
        return sorted(rows, key=lambda item: item["risk_score"], reverse=True)

    def recommendation_rows(self) -> List[Dict[str, Any]]:
        rows = []
        for recommendation in self.recommendations:
            context = (
                self.traceability_engine.analyst_summary(
                    recommendation.recommendation_id
                )
                if self.traceability_engine
                else {}
            )
            rows.append(
                {
                    "recommendation_id": recommendation.recommendation_id,
                    "title": recommendation.title,
                    "priority": recommendation.status,
                    "affected_resources": context.get("assessment_register_entries", [])
                    or recommendation.assessment_register_ids,
                    "checklist_controls": recommendation.checklist_ids,
                    "threat_scenarios": recommendation.threat_scenario_refs,
                    "supporting_evidence": recommendation.evidence_references,
                    "status": recommendation.status,
                    "risk_score": context.get("risk_score", 0),
                    "why": recommendation.rationale,
                    "remediation": recommendation.remediation,
                    "verification": recommendation.verification_steps,
                    "related_findings": context.get("assessment_register_entries", [])
                    or recommendation.assessment_register_ids,
                    "traceability": context,
                }
            )
        return rows

    def report_rows(self) -> List[Dict[str, Any]]:
        history = self.assessment_history()
        rows = []
        archived = self._archive_reports()
        for report in self.report_files:
            versions = []
            for assessment in history:
                for report_file in assessment.get("report_files", []) or []:
                    if Path(report_file).name == report["name"]:
                        versions.append(
                            {
                                "assessment_id": assessment.get("id", ""),
                                "assessment_name": assessment.get("name", ""),
                                "status": assessment.get("status", ""),
                                "completed": assessment.get("completed", ""),
                                "path": report_file,
                            }
                        )
            rows.append(
                {
                    **report,
                    "versions": versions,
                    "version_count": len(versions),
                    "archived_versions": [
                        str(path)
                        for path in archived
                        if path.name.endswith(report["name"])
                    ],
                }
            )
        diagnostics = self.summary.get("diagnostics", {}) or {}
        bundle_path = diagnostics.get("bundle_path", "")
        bundle_file = Path(bundle_path) if bundle_path else None
        if bundle_file and bundle_file.exists():
            rows.append(
                {
                    "name": bundle_file.name,
                    "title": "Assessment Diagnostics Bundle",
                    "path": str(bundle_file),
                    "size": bundle_file.stat().st_size,
                    "generated_at": format_time(bundle_file.stat().st_mtime),
                    "versions": [
                        {
                            "assessment_id": assessment.get("id", ""),
                            "assessment_name": assessment.get("name", ""),
                            "status": assessment.get("status", ""),
                            "completed": assessment.get("completed", ""),
                            "path": assessment.get("diagnostics_bundle", ""),
                        }
                        for assessment in history
                        if assessment.get("diagnostics_bundle")
                    ],
                    "version_count": sum(
                        1 for assessment in history if assessment.get("diagnostics_bundle")
                    ),
                    "archived_versions": [],
                    "download_href": f"/diagnostics/download?path={bundle_file}",
                    "previewable": False,
                }
            )
        return rows

    def detail_context(self, entity_type: str, identifier: str) -> Dict[str, Any]:
        entity_type = entity_type.lower()
        if entity_type == "register":
            return self._register_detail(identifier)
        if entity_type == "checklist":
            return self._checklist_detail(identifier)
        if entity_type == "threat":
            return self._threat_detail(identifier)
        if entity_type == "correlation":
            return self._correlation_detail(identifier)
        if entity_type == "path":
            return self._path_detail(identifier)
        if entity_type == "recommendation":
            return self._recommendation_detail(identifier)
        if entity_type == "report":
            return self._report_detail(identifier)
        return {"title": "Unknown", "sections": []}

    def _register_detail(self, register_id: str) -> Dict[str, Any]:
        entry = next(
            (item for item in self.register_entries if item.register_id == register_id),
            None,
        )
        if not entry:
            return {"title": "Assessment Register Entry Not Found", "sections": []}
        finding = next(
            (
                item
                for item in self.findings
                if item.assessment_register_id == register_id
            ),
            None,
        )
        return {
            "title": entry.title or register_id,
            "subtitle": entry.service,
            "identifier": register_id,
            "status": entry.validation_status,
            "sections": [
                {"label": "Evidence", "value": entry.evidence_references},
                {"label": "Checklist Controls", "value": entry.checklist_references},
                {
                    "label": "Threat Scenarios",
                    "value": entry.threat_scenario_references,
                },
                {"label": "Attack Paths", "value": entry.attack_path_references},
                {"label": "Risk Score", "value": entry.risk_score},
                {"label": "Analyst Notes", "value": entry.analyst_notes or ""},
                {"label": "Finding", "value": finding.to_dict() if finding else {}},
            ],
        }

    def _checklist_detail(self, checklist_id: str) -> Dict[str, Any]:
        item = next(
            (
                control
                for control in self.knowledge.checklist_items
                if control.get("id") == checklist_id
            ),
            None,
        )
        coverage = next(
            (
                record
                for record in self.checklist_coverage
                if record.get("id") == checklist_id
            ),
            {},
        )
        if not item:
            return {"title": "Checklist Control Not Found", "sections": []}
        related_registers = [
            entry.register_id
            for entry in self.register_entries
            if checklist_id in (entry.checklist_references or [])
        ]
        related_findings = [
            finding.to_dict()
            for finding in self.findings
            if checklist_id in (finding.checklist_ids or [finding.checklist_id])
        ]
        return {
            "title": item.get("title", checklist_id),
            "subtitle": item.get("domain", ""),
            "identifier": checklist_id,
            "status": coverage.get("status", "NOT_EVALUATED"),
            "sections": [
                {"label": "Evidence", "value": item.get("evidence_type", "")},
                {"label": "Related Findings", "value": related_findings},
                {
                    "label": "Threat Scenarios",
                    "value": self.knowledge.scenario_ids_for_checklist(checklist_id),
                },
                {
                    "label": "Recommendations",
                    "value": self.knowledge.recommendation_template_for_checklist(
                        checklist_id
                    ),
                },
                {"label": "Related Register Entries", "value": related_registers},
            ],
        }

    def _threat_detail(self, scenario_id: str) -> Dict[str, Any]:
        scenario = next(
            (item for item in self.threat_scenarios if item.scenario_id == scenario_id),
            None,
        )
        if not scenario:
            scenario = self.knowledge.threat_scenario(scenario_id)
        if not scenario:
            return {"title": "Threat Scenario Not Found", "sections": []}
        return {
            "title": scenario.title,
            "subtitle": scenario.scenario_id,
            "identifier": scenario.scenario_id,
            "status": scenario.status,
            "sections": [
                {
                    "label": "Validated Controls",
                    "value": scenario.prerequisite_checklists,
                },
                {
                    "label": "Missing Controls",
                    "value": [
                        control
                        for control in scenario.prerequisite_checklists
                        if control
                        not in {
                            item.get("id")
                            for item in self.checklist_coverage
                            if item.get("status") in {"PASS", "FAIL", "MANUAL_REVIEW"}
                        }
                    ],
                },
                {
                    "label": "Affected Crown Jewels",
                    "value": getattr(scenario, "crown_jewel_types", []),
                },
                {"label": "Evidence", "value": scenario.supporting_evidence},
                {
                    "label": "MITRE Mapping",
                    "value": {
                        "tactics": getattr(scenario, "mitre_tactics", []),
                        "techniques": getattr(scenario, "mitre_techniques", []),
                    },
                },
                {
                    "label": "Recommendations",
                    "value": getattr(scenario, "recommendation_refs", []),
                },
            ],
        }

    def _correlation_detail(self, correlation_id: str) -> Dict[str, Any]:
        threat = next(
            (
                item
                for item in self.correlated_threats
                if item.correlation_id == correlation_id
            ),
            None,
        )
        if not threat:
            return {"title": "Correlated Threat Not Found", "sections": []}
        return {
            "title": correlation_id,
            "subtitle": threat.correlation_reason,
            "identifier": correlation_id,
            "status": threat.status,
            "sections": [
                {"label": "Chain", "value": self._correlation_chain(threat)},
                {"label": "Attack Path References", "value": threat.attack_path_refs},
                {"label": "Supporting Evidence", "value": threat.supporting_evidence},
                {
                    "label": "Validated Register IDs",
                    "value": threat.validated_register_ids,
                },
            ],
        }

    def _path_detail(self, candidate_id: str) -> Dict[str, Any]:
        candidate = next(
            (
                item
                for item in self.attack_path_candidates
                if item.get("id") == candidate_id
            ),
            None,
        )
        if not candidate:
            return {"title": "Attack Path Not Found", "sections": []}
        return {
            "title": candidate.get("label", candidate_id),
            "subtitle": candidate_id,
            "identifier": candidate_id,
            "status": "Candidate",
            "sections": [
                {"label": "Hops", "value": candidate.get("hops", [])},
                {
                    "label": "Correlated Threats",
                    "value": candidate.get("correlated_threats", []),
                },
                {
                    "label": "Template References",
                    "value": candidate.get("template_refs", []),
                },
                {
                    "label": "Analyst Decision",
                    "value": candidate.get("analyst_decision", ""),
                },
            ],
        }

    def _recommendation_detail(self, recommendation_id: str) -> Dict[str, Any]:
        recommendation = next(
            (
                item
                for item in self.recommendations
                if item.recommendation_id == recommendation_id
            ),
            None,
        )
        if not recommendation:
            return {"title": "Recommendation Not Found", "sections": []}
        trace = (
            self.traceability_engine.analyst_summary(recommendation_id)
            if self.traceability_engine
            else {}
        )
        return {
            "title": recommendation.title,
            "subtitle": recommendation_id,
            "identifier": recommendation_id,
            "status": recommendation.status,
            "sections": [
                {
                    "label": "Affected Resources",
                    "value": trace.get("assessment_register_entries", []),
                },
                {"label": "Checklist Controls", "value": recommendation.checklist_ids},
                {
                    "label": "Threat Scenarios",
                    "value": recommendation.threat_scenario_refs,
                },
                {"label": "Attack Paths", "value": recommendation.attack_path_refs},
                {
                    "label": "Supporting Evidence",
                    "value": recommendation.evidence_references,
                },
                {"label": "Traceability", "value": trace},
            ],
        }

    def _report_detail(self, filename: str) -> Dict[str, Any]:
        report = next(
            (item for item in self.report_files if item["name"] == filename), None
        )
        if not report:
            return {"title": "Report Not Found", "sections": []}
        return {
            "title": report["title"],
            "subtitle": filename,
            "identifier": filename,
            "status": "Generated",
            "sections": [
                {"label": "Generation Time", "value": report.get("generated_at", "")},
                {
                    "label": "Assessment Version",
                    "value": self.config.get("framework", {}).get("version", ""),
                },
                {
                    "label": "Methodology Version",
                    "value": self.config.get("framework", {}).get("version", ""),
                },
                {"label": "File", "value": report["path"]},
                {"label": "Size", "value": report["size"]},
            ],
        }

    def dashboard(self) -> Dict[str, Any]:
        monitor = self.active_monitor()
        health = self.assessment_health_view_model()
        timeline = self.assessment_timeline()[-8:]
        evidence_coverage = self.evidence_coverage_summary()[:8]
        safety = self.safety_validation()
        diagnostics = self.summary.get("diagnostics", {}) or {}
        validations = self.state.get("finding_validations", {}) or {}
        status_counts = {key: 0 for key in self.validation_statuses()}
        for item in validations.values():
            if isinstance(item, dict):
                status_counts[item.get("status", "NEEDS_REVIEW")] = (
                    status_counts.get(item.get("status", "NEEDS_REVIEW"), 0) + 1
                )
        collector_health = []
        for collector in self.available_collectors():
            collector_health.append(
                {
                    "name": collector["label"],
                    "status": "ENABLED" if collector["enabled"] else "DISABLED",
                }
            )
        reports = self.report_rows()
        findings_by_severity = dict(self.summary.get("findings_by_severity", {}))
        if not findings_by_severity:
            for finding in self.findings:
                findings_by_severity[finding.severity] = (
                    findings_by_severity.get(finding.severity, 0) + 1
                )
        platform_health = {
            "provider_available": bool(getattr(self.provider, "available", False)),
            "accounts_validated": sum(
                1
                for account in self.account_records()
                if account.get("last_validation_status") == "VALIDATED"
            ),
            "collector_count": sum(
                1 for item in collector_health if item["status"] == "ENABLED"
            ),
            "report_count": len(reports),
            "issues": list(monitor.get("failures", [])),
        }
        return {
            "assessment_name": self.assessment_name(),
            "cloud_provider": self.cloud_provider_name(),
            "assessment_status": monitor.get("status")
            or ("READY" if self.provider.available else "DEGRADED"),
            "current_lifecycle_stage": self.current_lifecycle_stage(),
            "number_of_accounts": self.account_count(),
            "accounts": self.account_records(),
            "regions": self.config.get("aws", {}).get("regions", []),
            "resources_discovered": self.discovered_resources(),
            "total_resources": self.discovered_resources(),
            "evidence_sources": self.evidence_source_count(),
            "findings": self.summary.get("findings", len(self.findings)),
            "findings_by_severity": findings_by_severity,
            "checklist_progress": self.checklist_progress(),
            "threat_scenarios": self.summary.get(
                "threat_scenarios", len(self.knowledge.scenarios)
            ),
            "attack_paths": self.summary.get(
                "attack_paths", len(self.attack_path_candidates)
            ),
            "high_risk_findings": self.high_risk_count(),
            "manual_reviews_remaining": self.manual_review_remaining(),
            "recent_activity": self.recent_activity(),
            "recent_assessments": self.assessment_history()[:5],
            "recent_reports": reports[:6],
            "risk_summary": self.summary.get("risk_summary", self.risk_summary),
            "enabled_modules": sum(
                1 for value in (self.config.get("modules", {}) or {}).values() if value
            ),
            "monitor": monitor,
            "validation_summary": status_counts,
            "assessment_health": (
                "Healthy" if not monitor.get("failures") else "Attention Required"
            ),
            "assessment_health_score": health,
            "evidence_coverage": evidence_coverage,
            "timeline": timeline,
            "safety_validation": safety,
            "diagnostics_bundle": diagnostics.get("bundle_path", ""),
            "collector_health": collector_health,
            "platform_health": platform_health,
            "quick_actions": [
                {"label": "New Assessment", "href": "/assessments"},
                {"label": "Cloud Accounts", "href": "/accounts"},
                {"label": "Customer Access Pack", "href": "/access-requirements"},
                {"label": "Pre-Assessment Validation", "href": "/capability-validation"},
                {"label": "Evidence", "href": "/evidence"},
                {"label": "Findings Register", "href": "/register"},
                {"label": "Deliverables", "href": "/reports"},
                {"label": "Settings", "href": "/settings"},
                {"label": "Read-Only Assurance", "href": "/trust-center"},
            ],
        }

    def progress(self) -> List[StageState]:
        return self.stage_states()

    def editable_account(self, account_id: str) -> Dict[str, Any]:
        record = self.account_vault.get_account(account_id)
        if not record:
            return {}
        payload = dict(record)
        payload.update(self.account_vault.get_credentials(account_id))
        payload["auth_type"] = record.get("auth_type", "").lower()
        payload["regions"] = ", ".join(record.get("regions", []))
        return payload

    def archive_report(self, filename: str) -> str:
        result = self.runner.archive_report(filename)
        self.refresh()
        return result

    def retry_stage(self, stage_key: str) -> Dict[str, Any]:
        monitor = self.active_monitor()
        if monitor.get("status") == "RUNNING":
            raise KeyError("Retry is disabled while a full assessment is running.")
        stage_key = stage_key.lower()
        stage_map = {
            "discovery": self._retry_discovery,
            "inventory": self._retry_inventory,
            "evidence_collection": self._retry_evidence_collection,
            "normalization": self._retry_normalization,
            "assessment_register": self._retry_assessment_register,
            "checklist_validation": self._retry_checklist_validation,
            "threat_validation": self._retry_threat_validation,
            "threat_correlation": self._retry_threat_correlation,
            "attack_paths": self._retry_attack_paths,
            "risk_prioritization": self._retry_risk_prioritization,
            "reporting": self._retry_reporting,
        }
        runner = stage_map.get(stage_key)
        if not runner:
            raise KeyError(f"Unknown stage: {stage_key}")
        start = dt.datetime.utcnow()
        result = runner()
        finish = dt.datetime.utcnow()
        self._store_stage_state(
            stage_key,
            status="COMPLETED",
            start_time=start.isoformat() + "Z",
            finish_time=finish.isoformat() + "Z",
            duration=str((finish - start).total_seconds()),
            errors=[],
        )
        self.refresh()
        return result

    def _store_stage_state(self, stage_key: str, **data):
        def mutate(state):
            state.setdefault("stages", {})[stage_key] = data
            return state

        self.state = self.state_store.update(mutate)

    def _retry_discovery(self):
        engine = DiscoveryEngine(self.config, self.provider)
        return engine.run()

    def _retry_inventory(self):
        return self._retry_discovery()

    def _retry_evidence_collection(self):
        engine = EvidenceCollectionEngine(self.config, self.provider)
        return engine.run()

    def _retry_normalization(self):
        engine = NormalizationEngine()
        return engine.run()

    def _retry_assessment_register(self):
        findings = load_findings(Path("output/normalized/findings.json"))
        engine = AssessmentRegisterEngine(
            self.config,
            self.assessment_id or "ASSESSMENT",
            knowledge_engine=self.knowledge,
        )
        return engine.run(findings)

    def _retry_checklist_validation(self):
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json")
        )
        engine = ChecklistValidationEngine(self.config, knowledge_engine=self.knowledge)
        return engine.run(register_entries)

    def _retry_threat_validation(self):
        findings = load_findings(
            Path("output/risk/risk_findings.json")
        ) or load_findings(Path("output/normalized/findings.json"))
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json"), findings
        )
        coverage = load_dict_list(Path("output/checklist/checklist_coverage.json"))
        engine = ThreatValidationEngine(self.config, knowledge_engine=self.knowledge)
        return engine.run(coverage, register_entries)

    def _retry_threat_correlation(self):
        findings = load_findings(
            Path("output/risk/risk_findings.json")
        ) or load_findings(Path("output/normalized/findings.json"))
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json"), findings
        )
        scenarios = load_threat_scenarios(Path("output/threats/threat_scenarios.json"))
        engine = ThreatCorrelationEngine(self.config, knowledge_engine=self.knowledge)
        return engine.run(scenarios, register_entries)

    def _retry_attack_paths(self):
        findings = load_findings(
            Path("output/risk/risk_findings.json")
        ) or load_findings(Path("output/normalized/findings.json"))
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json"), findings
        )
        correlated = load_correlated_threats(
            Path("output/threats/correlated_threats.json")
        )
        crown_jewel_engine = CrownJewelEngine(self.config)
        if findings:
            crown_jewel_engine.run(findings)
        engine = AttackPathEngine(
            self.config, crown_jewel_engine, knowledge_engine=self.knowledge
        )
        return engine.run(register_entries or findings, correlated_threats=correlated)

    def _retry_risk_prioritization(self):
        findings = load_findings(
            Path("output/risk/risk_findings.json")
        ) or load_findings(Path("output/normalized/findings.json"))
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json"), findings
        )
        checklist_coverage = load_dict_list(
            Path("output/checklist/checklist_coverage.json")
        )
        correlated = load_correlated_threats(
            Path("output/threats/correlated_threats.json")
        )
        crown_jewel_engine = CrownJewelEngine(self.config)
        attack_path_engine = AttackPathEngine(
            self.config, crown_jewel_engine, knowledge_engine=self.knowledge
        )
        attack_path_engine.run(
            register_entries or findings, correlated_threats=correlated
        )
        engine = RiskPrioritizationEngine(
            self.config,
            attack_path_engine,
            checklist_coverage,
            knowledge_engine=self.knowledge,
        )
        return engine.run(findings)

    def _retry_reporting(self):
        findings = load_findings(
            Path("output/risk/risk_findings.json")
        ) or load_findings(Path("output/normalized/findings.json"))
        register_entries = load_register_entries(
            Path("output/assessment_register/assessment_register.json")
        )
        checklist_coverage = load_dict_list(
            Path("output/checklist/checklist_coverage.json")
        )
        threat_scenarios = load_threat_scenarios(
            Path("output/threats/threat_scenarios.json")
        )
        correlated = load_correlated_threats(
            Path("output/threats/correlated_threats.json")
        )
        recommendations = load_recommendations(
            Path("output/assessment_register/recommendations.json")
        )
        attack_path_candidates = load_dict_list(
            Path("output/attack_paths/attack_path_candidates.json")
        )
        risk_summary = read_json(Path("output/risk/risk_summary.json"), {})
        discovery_summary = read_json(Path("output/discovery/asset_inventory.json"), {})
        evidence_index = read_json(Path("output/evidence_index.json"), {}).get(
            "evidence", {}
        )
        report = ReportingEngine(
            findings=findings,
            assessment_register=register_entries,
            execution_status=self.state_store.load().get("execution_status", {}),
            checklist_coverage=checklist_coverage,
            threat_scenarios=threat_scenarios,
            correlated_threats=correlated,
            mitre_summary=read_json(Path("output/mitre/mitre_summary.json"), {}),
            attack_path_candidates=attack_path_candidates,
            risk_summary=risk_summary,
            evidence_index=evidence_index,
            discovery_summary=discovery_summary,
            recommendations=recommendations,
            attack_path_catalog=self.knowledge.attack_path_catalog,
            knowledge_engine=self.knowledge,
            traceability_engine=self.traceability_engine,
            assessment_metadata={
                "platform_version": self.config.get("framework", {}).get("version", "2.0.0"),
                "assessment_engine_version": self.config.get("framework", {}).get("version", "2.0.0"),
                "collector_versions": [
                    item["name"] for item in self.external_tool_validation() if item.get("installed")
                ],
                "checklist_version": self.config.get("framework", {}).get("version", "Current"),
                "threat_library_version": self.config.get("framework", {}).get("version", "Current"),
                "assessment_date": self.summary.get("generated_at", ""),
                "assessment_duration": self.active_assessment().get("duration", ""),
                "assessment_id": self.summary.get("assessment_id", ""),
                "permission_matrix": self.access_requirements_view_model().get(
                    "permission_matrix", []
                ),
                "capability_validation": self.summary.get("diagnostics", {}).get(
                    "capability_validation", {}
                ),
                "safety_validation": self.summary.get("diagnostics", {}).get(
                    "safety_validation", self.safety_validation()
                ),
                "tool_validation": self.external_tool_validation(),
            },
        )
        report.generate()
        return {"status": "generated"}
