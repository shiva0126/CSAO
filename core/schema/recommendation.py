"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Recommendation Schema
===============================================================================
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Recommendation:

    recommendation_id: str
    title: str
    status: str = "OPEN"
    assessment_register_ids: List[str] = field(default_factory=list)
    checklist_ids: List[str] = field(default_factory=list)
    threat_scenario_refs: List[str] = field(default_factory=list)
    attack_path_refs: List[str] = field(default_factory=list)
    evidence_references: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    priority: str = ""
    severity: str = ""
    rationale: str = ""
    remediation: str = ""
    verification_steps: str = ""
    report_sections: List[str] = field(default_factory=list)

    def to_dict(self):

        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "status": self.status,
            "assessment_register_ids": list(self.assessment_register_ids),
            "checklist_ids": list(self.checklist_ids),
            "threat_scenario_refs": list(self.threat_scenario_refs),
            "attack_path_refs": list(self.attack_path_refs),
            "evidence_references": list(self.evidence_references),
            "evidence_ids": list(self.evidence_ids),
            "priority": self.priority,
            "severity": self.severity,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "verification_steps": self.verification_steps,
            "report_sections": list(self.report_sections),
        }
