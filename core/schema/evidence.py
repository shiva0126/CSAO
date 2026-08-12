"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Canonical Evidence Schema
===============================================================================
"""

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass
class EvidenceRecord:

    evidence_id: str
    checklist_control_id: str
    collector: str
    raw_evidence: List[str] = field(default_factory=list)
    evidence_type: str = ""
    evidence_format: str = ""
    collection_method: str = ""
    timestamp: str = ""
    source: str = ""
    assessment_id: str = ""
    result: str = "NOT_EVALUATED"
    automatic: bool = False
    finding_ids: List[str] = field(default_factory=list)
    register_ids: List[str] = field(default_factory=list)
    attack_path_refs: List[str] = field(default_factory=list)
    threat_scenario_refs: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self):

        return asdict(self)

    @classmethod
    def from_dict(cls, data):

        known = {
            key: value
            for key, value in data.items()
            if key in cls.__dataclass_fields__
        }

        return cls(**known)
