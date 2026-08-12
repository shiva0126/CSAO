"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Assessment Register Schema

Purpose
-------
Canonical working register for the assessment. Every normalized Finding is
first converted into an Assessment Register entry, and all downstream stages
read and enrich this register rather than operating directly on raw tool
output.
===============================================================================
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AssessmentRegisterEntry:

    register_id: str
    assessment_id: str
    finding_id: str

    resource: str = "Unknown"
    environment: str = "Unknown"
    cloud_platform: str = "aws"

    evidence_references: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    source: str = "Unknown"
    validation_status: str = "PENDING"
    analyst_notes: str = ""
    business_exception: str = ""
    checklist_references: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_scenario_references: List[str] = field(default_factory=list)
    attack_path_references: List[str] = field(default_factory=list)
    recommendation_references: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: dict = field(default_factory=dict)

    title: str = ""
    severity: str = "INFO"
    service: str = "Unknown"
    resource_name: str = "Unknown"
    resource_type: str = "Unknown"
    internet_facing: str = "Unknown"
    crown_jewel: str = "No"
    business_unit: str = "Unknown"

    # Direct object reference retained in-memory so downstream stages can
    # update the canonical Finding without re-looking it up.
    _finding: Optional[object] = field(default=None, repr=False)

    def to_dict(self, include_internal=False):
        data = {
            "register_id": self.register_id,
            "assessment_id": self.assessment_id,
            "finding_id": self.finding_id,
            "resource": self.resource,
            "environment": self.environment,
            "cloud_platform": self.cloud_platform,
            "evidence_references": list(self.evidence_references),
            "evidence_ids": list(self.evidence_ids),
            "source": self.source,
            "validation_status": self.validation_status,
            "analyst_notes": self.analyst_notes,
            "business_exception": self.business_exception,
            "checklist_references": list(self.checklist_references),
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "threat_scenario_references": list(self.threat_scenario_references),
            "attack_path_references": list(self.attack_path_references),
            "recommendation_references": list(self.recommendation_references),
            "risk_score": self.risk_score,
            "risk_factors": dict(self.risk_factors),
            "title": self.title,
            "severity": self.severity,
            "service": self.service,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "internet_facing": self.internet_facing,
            "crown_jewel": self.crown_jewel,
            "business_unit": self.business_unit,
        }

        if include_internal:

            data["_finding"] = self._finding

        return data

    @classmethod
    def from_finding(cls, assessment_id, register_id, finding):

        finding_id = (
            f"{finding.tool_source}:{getattr(finding, '_tool_check_id', 'unknown')}:"
            f"{finding.resource_id}"
        )

        return cls(
            register_id=register_id,
            assessment_id=assessment_id,
            finding_id=finding_id,
            resource=finding.resource_id,
            environment=finding.environment,
            cloud_platform=finding.cloud_platform,
            evidence_references=[finding.evidence_location] if finding.evidence_location else [],
            evidence_ids=list(getattr(finding, "evidence_ids", []) or []),
            source=finding.tool_source,
            validation_status=finding.validation_status,
            analyst_notes=finding.analyst_notes,
            title=finding.title,
            severity=finding.severity,
            service=finding.service,
            resource_name=finding.resource_name,
            resource_type=finding.resource_type,
            internet_facing=finding.internet_facing,
            crown_jewel=finding.crown_jewel,
            business_unit=finding.business_unit,
            _finding=finding,
        )
