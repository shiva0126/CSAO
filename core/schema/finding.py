"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Canonical Finding Schema

Purpose
-------
Every evidence-provider tool (Prowler, Steampipe, Cloudsplaining, Access
Analyzer, Config Aggregator, Cartography, Tenable...) is parsed into this one
shape by the Normalization Engine. Every downstream engine (Checklist, MITRE,
Crown Jewel, Attack Path, Risk, Reporting) reads and enriches the same
Finding object in place instead of re-deriving a new shape at each stage.

READ ONLY - this module holds no execution logic.
===============================================================================
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional


VALID_VALIDATION_STATUSES = (
    "PASS",
    "FAIL",
    "MANUAL_REVIEW",
    "NOT_EVALUATED",
)

VALID_SEVERITIES = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
)


@dataclass
class Finding:

    # Identity / location
    cloud_platform: str = "aws"
    account: str = "Unknown"
    region: str = "Unknown"
    service: str = "Unknown"

    resource_id: str = "Unknown"
    resource_name: str = "Unknown"
    resource_type: str = "Unknown"

    # What was found
    title: str = "Untitled Finding"
    description: str = ""
    severity: str = "INFO"

    # Provenance
    tool_source: str = "Unknown"
    evidence_location: str = ""
    timestamp: str = ""

    # Business context
    environment: str = "Unknown"
    business_unit: str = "Unknown"
    internet_facing: str = "Unknown"
    crown_jewel: str = "No"

    # Checklist Validation Engine
    assessment_register_id: Optional[str] = None
    checklist_id: Optional[str] = None
    checklist_ids: List[str] = field(default_factory=list)
    validation_status: str = "NOT_EVALUATED"

    # MITRE Mapping Engine
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Threat Correlation / Attack Path Engine
    related_threat_scenario: Optional[str] = None
    threat_scenario_ids: List[str] = field(default_factory=list)
    attack_path_candidate: Optional[str] = None
    attack_path_ids: List[str] = field(default_factory=list)

    # Recommendation traceability
    recommendation_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    # Analyst
    analyst_notes: str = ""

    # Internal fields used by engines but not part of the 22 published
    # columns - kept on the object so later engines don't need a second
    # lookup structure. Excluded from to_dict() by default.
    _tool_check_id: Optional[str] = field(default=None, repr=False)
    _risk_factors: dict = field(default_factory=dict, repr=False)
    _risk_score: Optional[float] = field(default=None, repr=False)
    _crown_jewel_proximity: Optional[int] = field(default=None, repr=False)

    # -------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------

    PUBLISHED_FIELDS = (
        "cloud_platform",
        "account",
        "region",
        "service",
        "resource_id",
        "resource_name",
        "resource_type",
        "title",
        "description",
        "severity",
        "tool_source",
        "evidence_location",
        "timestamp",
        "environment",
        "business_unit",
        "internet_facing",
        "crown_jewel",
        "assessment_register_id",
        "checklist_id",
        "validation_status",
        "mitre_tactics",
        "mitre_techniques",
        "related_threat_scenario",
        "attack_path_candidate",
        "analyst_notes",
    )

    def to_dict(self, include_internal=False):

        data = asdict(self)

        if not include_internal:

            for key in list(data.keys()):

                if key.startswith("_"):

                    del data[key]

        return data

    def set_check_id(self, check_id):
        """
        Stamps the tool-specific check identifier used as the lookup key
        into data/mitre_mappings.yaml and checklist.yaml
        (e.g. "aws/iam/wildcard_permissions" for Steampipe, a Prowler
        CheckID, or a Cloudsplaining finding_type). Returns self so it can
        be chained directly onto the constructor call.
        """

        self._tool_check_id = check_id

        return self

    @classmethod
    def from_dict(cls, data):

        known = {
            key: value
            for key, value in data.items()
            if key in cls.__dataclass_fields__
        }

        return cls(**known)
