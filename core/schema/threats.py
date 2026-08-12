"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Threat Validation / Correlation Schemas
===============================================================================
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ThreatScenarioRecord:

    scenario_id: str
    title: str
    threat_id: str = ""
    threat_number: Optional[int] = None
    domain: str = ""
    status: str = "PENDING"
    prerequisite_checklists: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    validated_finding_ids: List[str] = field(default_factory=list)
    validated_register_ids: List[str] = field(default_factory=list)
    related_attack_paths: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    risk_level: str = ""
    impact: str = ""
    data_flow: str = ""
    trust_boundary: str = ""
    business_impact: str = ""
    preconditions: str = ""
    existing_controls: str = ""
    remediation: str = ""
    analyst_notes: str = ""

    def to_dict(self):

        return {
            "scenario_id": self.scenario_id,
            "threat_id": self.threat_id,
            "threat_number": self.threat_number,
            "domain": self.domain,
            "title": self.title,
            "status": self.status,
            "prerequisite_checklists": list(self.prerequisite_checklists),
            "supporting_evidence": list(self.supporting_evidence),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "validated_finding_ids": list(self.validated_finding_ids),
            "validated_register_ids": list(self.validated_register_ids),
            "related_attack_paths": list(self.related_attack_paths),
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "risk_level": self.risk_level,
            "impact": self.impact,
            "data_flow": self.data_flow,
            "trust_boundary": self.trust_boundary,
            "business_impact": self.business_impact,
            "preconditions": self.preconditions,
            "existing_controls": self.existing_controls,
            "remediation": self.remediation,
            "analyst_notes": self.analyst_notes,
        }


@dataclass
class CorrelatedThreat:

    correlation_id: str
    scenario_ids: List[str] = field(default_factory=list)
    status: str = "PENDING"
    attack_path_refs: List[str] = field(default_factory=list)
    source_resources: List[str] = field(default_factory=list)
    target_resources: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    validated_register_ids: List[str] = field(default_factory=list)
    analyst_decision: str = "UNREVIEWED"
    correlation_reason: str = ""

    def to_dict(self):

        return {
            "correlation_id": self.correlation_id,
            "scenario_ids": list(self.scenario_ids),
            "status": self.status,
            "attack_path_refs": list(self.attack_path_refs),
            "source_resources": list(self.source_resources),
            "target_resources": list(self.target_resources),
            "supporting_evidence": list(self.supporting_evidence),
            "validated_register_ids": list(self.validated_register_ids),
            "analyst_decision": self.analyst_decision,
            "correlation_reason": self.correlation_reason,
        }
