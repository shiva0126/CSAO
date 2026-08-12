"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Assessment Knowledge Engine

Purpose
-------
Authoritative assessment knowledge base for the platform. This engine loads
the imported workbook-backed checklist and attack-path catalog, builds the
relationship graph between assessment objects, and exposes reusable lookup and
validation helpers for downstream engines.

The imported YAML files are the current serialized form of the finalized
workbooks. The engine treats them as methodology data rather than as flat
reference files.
===============================================================================
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import networkx as nx
import yaml

from rich.console import Console


console = Console()


@dataclass
class KnowledgeScenario:

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
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    crown_jewel_types: List[str] = field(default_factory=list)
    attack_path_refs: List[str] = field(default_factory=list)
    recommendation_refs: List[str] = field(default_factory=list)
    business_impact: str = ""
    preconditions: str = ""
    mitigation_strategy: str = ""
    risk_level: str = ""
    impact: str = ""
    data_flow: str = ""
    trust_boundary: str = ""
    existing_controls: str = ""
    report_sections: List[str] = field(default_factory=list)

    def to_dict(self):

        return {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "threat_id": self.threat_id,
            "threat_number": self.threat_number,
            "domain": self.domain,
            "status": self.status,
            "prerequisite_checklists": list(self.prerequisite_checklists),
            "supporting_evidence": list(self.supporting_evidence),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "validated_finding_ids": list(self.validated_finding_ids),
            "validated_register_ids": list(self.validated_register_ids),
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "crown_jewel_types": list(self.crown_jewel_types),
            "attack_path_refs": list(self.attack_path_refs),
            "related_attack_paths": list(self.attack_path_refs),
            "recommendation_refs": list(self.recommendation_refs),
            "business_impact": self.business_impact,
            "preconditions": self.preconditions,
            "mitigation_strategy": self.mitigation_strategy,
            "risk_level": self.risk_level,
            "impact": self.impact,
            "data_flow": self.data_flow,
            "trust_boundary": self.trust_boundary,
            "existing_controls": self.existing_controls,
            "report_sections": list(self.report_sections),
        }


class AssessmentKnowledgeEngine:

    WORKBOOK_METADATA = {
        "checklist": {
            "workbook": "Checklist Workbook",
            "source_file": "data/assessment_knowledge_catalog.yaml",
            "worksheets": (
                "Master STRIDE–Checklist Map",
                "Evidence & Output Format",
                "STRIDE Checklist Post-Val Log",
            ),
        },
        "threat_scenarios": {
            "workbook": "Threat Scenario Workbook",
            "source_file": "data/assessment_knowledge_catalog.yaml",
            "worksheets": (
                "Refined Threat Scenarios",
                "Checklist Validation Matrix",
                "Attack Path Linkage",
            ),
        },
    }

    TOOL_ALIAS = {
        "steampipe": "steampipe",
        "prowler": "prowler",
        "cloudsplaining": "cloudsplaining",
        "access_analyzer": "access_analyzer",
        "config_aggregator": "config_aggregator",
        "cartography": "cartography",
        "tenable": "tenable",
    }

    def __init__(self, config):

        self.config = config

        checklist_file = config.get("checklist", {}).get(
            "file", "checklists/checklist.yaml"
        )
        knowledge_catalog_file = config.get("knowledge_catalog", {}).get(
            "file", ""
        )
        attack_path_catalog_file = config.get("attack_path", {}).get(
            "catalog", "data/attack_path_catalog.yaml"
        )

        self.checklist_file = Path(checklist_file)
        self.knowledge_catalog_file = Path(knowledge_catalog_file) if knowledge_catalog_file else None
        self.attack_path_catalog_file = Path(attack_path_catalog_file)
        self.catalog = self.load_catalog()

        self.checklist_items = self.load_checklist_items()
        self.attack_path_catalog = self.load_attack_path_catalog()
        self.collector_catalog = list(self.catalog.get("collectors", []) or [])
        self.recommendation_catalog = list(self.catalog.get("recommendations", []) or [])
        self.report_sections = list(self.catalog.get("report_sections", []) or [])
        self.scenarios = self.build_scenarios()

        self.checklist_by_id = {
            item.get("id"): item for item in self.checklist_items if item.get("id")
        }
        self.attack_path_by_code = {
            item.get("ap_code"): item
            for item in self.attack_path_catalog
            if item.get("ap_code")
        }
        self.scenario_by_id = {
            scenario.scenario_id: scenario for scenario in self.scenarios
        }

        self.scenarios_by_checklist = self._index_scenarios_by_checklist()
        self.graph = self.build_relationship_graph()

    ###########################################################################
    # Load helpers
    ###########################################################################

    def load_catalog(self):

        if not self.knowledge_catalog_file:
            return {}

        if not self.knowledge_catalog_file.exists():
            return {}

        with open(self.knowledge_catalog_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return data if isinstance(data, dict) else {}

    def load_checklist_items(self):

        if self.catalog.get("controls"):
            return list(self.catalog.get("controls", []) or [])

        if not self.checklist_file.exists():

            console.print(
                f"[yellow]Checklist knowledge file not found: {self.checklist_file}[/yellow]"
            )

            return []

        with open(self.checklist_file, encoding="utf-8") as f:

            data = yaml.safe_load(f) or {}

        return data.get("checklist", [])

    def load_attack_path_catalog(self):

        if self.catalog.get("attack_paths"):
            return list(self.catalog.get("attack_paths", []) or [])

        if not self.attack_path_catalog_file.exists():

            return []

        with open(self.attack_path_catalog_file, encoding="utf-8") as f:

            data = yaml.safe_load(f) or {}

        return data.get("attack_paths", [])

    ###########################################################################
    # Basic normalization helpers
    ###########################################################################

    def _tool_alias(self, tool):

        return self.TOOL_ALIAS.get(str(tool or "").lower(), str(tool or "").lower())

    def _split_attack_paths(self, value):

        if not value:

            return []

        if isinstance(value, list):

            values = value

        else:

            values = re.split(r"[|,]", str(value))

        return [
            item.strip()
            for item in values
            if str(item).strip() and str(item).strip() != "—"
        ]

    def _item_sources(self, item):

        sources = item.get("sources")

        if sources:

            return [
                {
                    "tool": self._tool_alias(source.get("tool")),
                    "query_ref": source.get("query_ref"),
                }
                for source in sources
            ]

        tool = item.get("tool")

        if tool:

            return [
                {
                    "tool": self._tool_alias(tool),
                    "query_ref": item.get("query_ref"),
                }
            ]

        return []

    def workbook_metadata(self):

        return self.WORKBOOK_METADATA

    def collector_mappings(self):

        return list(self.collector_catalog or [])

    def report_section_catalog(self):

        return list(self.report_sections or [])

    def _item_mitre_mapping(self, item):

        mapping = item.get("mitre_mapping") or {}

        if isinstance(mapping, dict):

            return {
                "tactics": list(mapping.get("tactics", []) or []),
                "techniques": list(mapping.get("techniques", []) or []),
            }

        tactics = []
        techniques = []

        for entry in mapping:

            tactic = entry.get("tactic")
            technique = entry.get("technique_id") or entry.get("technique")

            if tactic:
                tactics.append(tactic)

            if technique:
                techniques.append(technique)

        return {
            "tactics": tactics,
            "techniques": techniques,
        }

    ###########################################################################
    # Scenario construction
    ###########################################################################

    def build_scenarios(self):

        if self.catalog.get("threat_scenarios"):
            scenarios = []
            for item in self.catalog.get("threat_scenarios", []):
                scenarios.append(
                    KnowledgeScenario(
                        scenario_id=item.get("scenario_id", ""),
                        title=item.get("title", ""),
                        threat_id=item.get("threat_id", ""),
                        threat_number=item.get("threat_number"),
                        domain=item.get("domain", ""),
                        prerequisite_checklists=list(
                            item.get("checklist_ids")
                            or item.get("primary_check_ids")
                            or []
                        ),
                        supporting_evidence=list(item.get("supporting_evidence", []) or []),
                        supporting_evidence_ids=list(item.get("supporting_evidence_ids", []) or []),
                        mitre_tactics=list(item.get("mitre_tactics", []) or []),
                        mitre_techniques=list(item.get("mitre_techniques", []) or []),
                        attack_path_refs=list(item.get("attack_path_refs", []) or []),
                        recommendation_refs=[
                            recommendation.get("recommendation_id")
                            for recommendation in self.recommendation_catalog
                            if item.get("scenario_id")
                            in set(recommendation.get("threat_scenario_refs", []) or [])
                        ],
                        business_impact=item.get("business_impact", ""),
                        preconditions=item.get("preconditions", ""),
                        mitigation_strategy=item.get("remediation", ""),
                        risk_level=item.get("risk_level", ""),
                        impact=item.get("impact", ""),
                        data_flow=item.get("data_flow", ""),
                        trust_boundary=item.get("trust_boundary", ""),
                        existing_controls=item.get("existing_controls", ""),
                        report_sections=list(item.get("report_sections", []) or []),
                    )
                )
            return scenarios

        grouped = []
        by_key = {}

        for item in self.checklist_items:

            scenario_text = item.get("threat_scenario")
            if not scenario_text:
                continue

            attack_paths = tuple(self._split_attack_paths(item.get("related_attack_paths")))
            key = (scenario_text, attack_paths)

            if key not in by_key:
                by_key[key] = {
                    "title": scenario_text,
                    "prerequisite_checklists": [],
                    "supporting_evidence": [],
                    "mitre_tactics": [],
                    "mitre_techniques": [],
                    "crown_jewel_types": [],
                    "attack_path_refs": [],
                    "recommendation_refs": [],
                    "business_impact": "",
                    "preconditions": "",
                    "mitigation_strategy": "",
                }
                grouped.append(by_key[key])

            scenario = by_key[key]
            scenario["prerequisite_checklists"].append(item.get("id"))
            scenario["supporting_evidence"].extend(
                [item.get("evidence_type"), item.get("evidence_format")]
            )
            mitre_mapping = self._item_mitre_mapping(item)
            scenario["mitre_tactics"].extend(mitre_mapping.get("tactics", []))
            scenario["mitre_techniques"].extend(mitre_mapping.get("techniques", []))
            scenario["crown_jewel_types"].append(item.get("primary_asset_at_risk"))
            scenario["attack_path_refs"].extend(attack_paths)
            scenario["recommendation_refs"].append(item.get("output_document"))
            scenario["business_impact"] = item.get("pass_criteria") or ""
            scenario["preconditions"] = item.get("fail_indicator") or ""
            scenario["mitigation_strategy"] = item.get("output_document") or ""

        scenarios = []

        for index, data in enumerate(grouped, start=1):

            scenarios.append(
                KnowledgeScenario(
                    scenario_id=f"TS-{index:03d}",
                    title=data["title"],
                    prerequisite_checklists=sorted(
                        set(filter(None, data["prerequisite_checklists"]))
                    ),
                    supporting_evidence=sorted(
                        set(filter(None, data["supporting_evidence"]))
                    ),
                    mitre_tactics=sorted(set(filter(None, data["mitre_tactics"]))),
                    mitre_techniques=sorted(set(filter(None, data["mitre_techniques"]))),
                    crown_jewel_types=sorted(set(filter(None, data["crown_jewel_types"]))),
                    attack_path_refs=sorted(set(filter(None, data["attack_path_refs"]))),
                    recommendation_refs=sorted(
                        set(filter(None, data["recommendation_refs"]))
                    ),
                    business_impact=data["business_impact"],
                    preconditions=data["preconditions"],
                    mitigation_strategy=data["mitigation_strategy"],
                )
            )

        return scenarios

    def _index_scenarios_by_checklist(self):

        index = {}

        for scenario in self.scenarios:

            for checklist_id in scenario.prerequisite_checklists:

                index.setdefault(checklist_id, []).append(scenario)

        return index

    def _control_attack_paths(self, item):

        refs = []

        scenario_ids = item.get("threat_scenario_ids") or []
        for scenario_id in scenario_ids:
            scenario = self.scenario_by_id.get(scenario_id)
            if scenario:
                refs.extend(scenario.attack_path_refs)

        if not refs:
            refs.extend(self._split_attack_paths(item.get("related_attack_paths")))

        return sorted(set(filter(None, refs)))

    ###########################################################################
    # Relationship graph
    ###########################################################################

    def _node_id(self, node_type, identifier):

        return f"{node_type}:{identifier}"

    def build_relationship_graph(self):

        graph = nx.DiGraph()

        for item in self.checklist_items:

            checklist_id = item.get("id")
            if not checklist_id:
                continue

            control_node = self._node_id("CHECKLIST", checklist_id)
            graph.add_node(
                control_node,
                type="CHECKLIST",
                id=checklist_id,
                title=item.get("title"),
                domain=item.get("domain"),
                check_area=item.get("check_area"),
                stride_category=item.get("stride_category"),
                priority_tier=item.get("priority_tier"),
                priority_score=item.get("priority_score"),
                severity=item.get("severity"),
                evidence_type=item.get("evidence_type"),
                evidence_format=item.get("evidence_format"),
                pass_criteria=item.get("pass_criteria"),
                fail_indicator=item.get("fail_indicator"),
                manual_validation_required=bool(item.get("manual_validation_required")),
            )

            graph.add_edge(
                control_node,
                self._node_id("DOMAIN", item.get("domain") or "Unknown"),
                relationship="BELONGS_TO_DOMAIN",
            )
            graph.add_edge(
                control_node,
                self._node_id("STRIDE", item.get("stride_category") or "Unknown"),
                relationship="HAS_STRIDE_CATEGORY",
            )
            graph.add_edge(
                control_node,
                self._node_id("EVIDENCE", item.get("evidence_type") or "Unknown"),
                relationship="REQUIRES_EVIDENCE",
            )
            graph.add_edge(
                control_node,
                self._node_id("RECOMMENDATION", checklist_id),
                relationship="HAS_RECOMMENDATION_TEMPLATE",
            )

            for source in self._item_sources(item):
                source_key = f"{source.get('tool')}:{source.get('query_ref')}"
                graph.add_edge(
                    source_key,
                    control_node,
                    relationship="VALIDATES_CONTROL",
                )

            for scenario in self.scenarios_by_checklist.get(checklist_id, []):
                scenario_node = self._node_id("SCENARIO", scenario.scenario_id)
                graph.add_edge(
                    control_node,
                    scenario_node,
                    relationship="SUPPORTS_SCENARIO",
                )

            for attack_path in self._control_attack_paths(item):
                graph.add_edge(
                    control_node,
                    self._node_id("ATTACK_PATH", attack_path),
                    relationship="LINKS_ATTACK_PATH_TEMPLATE",
                )

        for scenario in self.scenarios:

            scenario_node = self._node_id("SCENARIO", scenario.scenario_id)
            graph.add_node(
                scenario_node,
                type="SCENARIO",
                id=scenario.scenario_id,
                title=scenario.title,
                threat_id=scenario.threat_id,
                threat_number=scenario.threat_number,
                domain=scenario.domain,
                prerequisite_checklists=list(scenario.prerequisite_checklists),
                supporting_evidence=list(scenario.supporting_evidence),
                mitre_tactics=list(scenario.mitre_tactics),
                mitre_techniques=list(scenario.mitre_techniques),
                crown_jewel_types=list(scenario.crown_jewel_types),
                attack_path_refs=list(scenario.attack_path_refs),
                recommendation_refs=list(scenario.recommendation_refs),
                business_impact=scenario.business_impact,
                preconditions=scenario.preconditions,
                mitigation_strategy=scenario.mitigation_strategy,
                risk_level=scenario.risk_level,
                impact=scenario.impact,
                data_flow=scenario.data_flow,
                trust_boundary=scenario.trust_boundary,
                existing_controls=scenario.existing_controls,
            )

            for technique in scenario.mitre_techniques:
                graph.add_edge(
                    scenario_node,
                    self._node_id("MITRE", technique),
                    relationship="MAPS_TO_MITRE",
                )

            for crown_jewel_type in scenario.crown_jewel_types:
                graph.add_edge(
                    scenario_node,
                    self._node_id("CROWN_JEWEL", crown_jewel_type),
                    relationship="TARGETS_CROWN_JEWEL",
                )

            for attack_path in scenario.attack_path_refs:
                graph.add_edge(
                    scenario_node,
                    self._node_id("ATTACK_PATH", attack_path),
                    relationship="LINKS_ATTACK_PATH_TEMPLATE",
                )

            for checklist_id in scenario.prerequisite_checklists:
                graph.add_edge(
                    scenario_node,
                    self._node_id("CHECKLIST", checklist_id),
                    relationship="DEPENDS_ON_CONTROL",
                )

        for attack_path in self.attack_path_catalog:

            ap_code = attack_path.get("ap_code")
            if not ap_code:
                continue

            graph.add_node(
                self._node_id("ATTACK_PATH", ap_code),
                type="ATTACK_PATH",
                id=ap_code,
                name=attack_path.get("name"),
                kill_chain_summary=attack_path.get("kill_chain_summary"),
                domains_spanned=attack_path.get("domains_spanned"),
                stride_categories=attack_path.get("stride_categories"),
                linked_threat_numbers=attack_path.get("linked_threat_numbers"),
                severity=attack_path.get("severity"),
            )

        return graph

    ###########################################################################
    # Lookup APIs
    ###########################################################################

    def checklist_item(self, checklist_id):

        return self.checklist_by_id.get(checklist_id)

    def threat_scenario(self, scenario_id):

        return self.scenario_by_id.get(scenario_id)

    def attack_path_template(self, ap_code):

        return self.attack_path_by_code.get(ap_code)

    def checklist_items_for_finding(self, finding):

        tool_key = self._tool_alias(getattr(finding, "tool_source", ""))
        check_id = getattr(finding, "_tool_check_id", None)
        checklist_id = getattr(finding, "checklist_id", None)
        checklist_ids = list(getattr(finding, "checklist_ids", []) or [])

        if checklist_id and checklist_id in self.checklist_by_id:
            checklist_ids.append(checklist_id)

        if checklist_ids:
            return [
                self.checklist_by_id[control_id]
                for control_id in dict.fromkeys(checklist_ids)
                if control_id in self.checklist_by_id
            ]

        matched = []

        for item in self.checklist_items:

            for source in self._item_sources(item):
                if source.get("tool") != tool_key:
                    continue
                if source.get("query_ref") == check_id:
                    matched.append(item)
                    break

        return matched

    def checklist_ids_for_finding(self, finding):

        return [item.get("id") for item in self.checklist_items_for_finding(finding)]

    def scenarios_for_checklist(self, checklist_id):
        scenarios = list(self.scenarios_by_checklist.get(checklist_id, []))
        if scenarios:
            return scenarios

        item = self.checklist_item(checklist_id) or {}
        scenario_ids = item.get("threat_scenario_ids") or []
        return [
            self.scenario_by_id[scenario_id]
            for scenario_id in scenario_ids
            if scenario_id in self.scenario_by_id
        ]

    def scenario_ids_for_checklist(self, checklist_id):

        return [scenario.scenario_id for scenario in self.scenarios_for_checklist(checklist_id)]

    def attack_path_refs_for_checklist(self, checklist_id):

        item = self.checklist_item(checklist_id) or {}
        refs = self._control_attack_paths(item)
        return sorted(set(refs))

    def recommendation_template_for_checklist(self, checklist_id):

        for recommendation in self.recommendation_catalog:
            if recommendation.get("control_id") == checklist_id:
                return dict(recommendation)

        item = self.checklist_item(checklist_id)

        if not item:

            return {}

        return {
            "id": f"REC-TPL-{checklist_id}",
            "title": f"Remediate checklist item {checklist_id}: {item.get('title')}",
            "checklist_id": checklist_id,
            "stride_category": item.get("stride_category"),
            "priority_tier": item.get("priority_tier"),
            "priority_score": item.get("priority_score"),
            "severity": item.get("severity"),
            "pass_criteria": item.get("pass_criteria"),
            "fail_indicator": item.get("fail_indicator"),
            "output_document": item.get("output_document"),
            "attack_path_refs": self.attack_path_refs_for_checklist(checklist_id),
            "threat_scenario_refs": self.scenario_ids_for_checklist(checklist_id),
        }

    ###########################################################################
    # Checklist validation and traceability
    ###########################################################################

    def evaluate_checklist_item(self, item, records):

        sources = self._item_sources(item)
        tools_evaluated = [
            source["tool"]
            for source in sources
            if self.tool_has_evidence(source["tool"])
        ]

        matched = [
            record for record in records
            if self.record_matches_item(record, item)
        ]

        if not sources or not tools_evaluated:
            status = "NOT_EVALUATED"
        elif item.get("manual_validation_required"):
            status = "MANUAL_REVIEW"
        elif matched:
            status = "FAIL"
        else:
            status = "PASS"

        return status, matched, sources

    def record_matches_item(self, record, item):

        finding = getattr(record, "_finding", record)
        tool_key = self._tool_alias(getattr(finding, "tool_source", ""))
        check_id = getattr(finding, "_tool_check_id", None)

        for source in self._item_sources(item):
            if source.get("tool") != tool_key:
                continue
            if source.get("query_ref") == check_id:
                return True

        return False

    def tool_has_evidence(self, tool):

        directory = self.TOOL_ALIAS.get(tool, tool)
        evidence_index = Path("output/evidence_index.json")

        if not evidence_index.exists():
            return False

        try:
            import json

            files = json.load(open(evidence_index)).get("evidence", {}).get(directory, [])
            return len(files) > 0
        except Exception:
            return False

    ###########################################################################
    # Threat validation / correlation support
    ###########################################################################

    def validate_scenario(self, scenario, coverage, records):

        coverage_by_id = {item["id"]: item for item in coverage}
        prerequisite_statuses = [
            coverage_by_id.get(checklist_id, {}).get("status", "NOT_EVALUATED")
            for checklist_id in scenario.prerequisite_checklists
        ]

        if not scenario.prerequisite_checklists:
            status = "NOT_APPLICABLE"
        elif any(status == "NOT_EVALUATED" for status in prerequisite_statuses):
            status = "PENDING"
        elif any(status in ("FAIL", "MANUAL_REVIEW") for status in prerequisite_statuses) and records:
            status = "VALIDATED"
        else:
            status = "CONFIRMED"

        supporting_evidence = []
        supporting_evidence_ids = []
        validated_findings = []
        validated_register_ids = []

        for record in records:
            finding = getattr(record, "_finding", record)
            checklist_ids = set(getattr(finding, "checklist_ids", []) or [])

            if not checklist_ids.intersection(scenario.prerequisite_checklists):
                continue

            finding_id = getattr(record, "finding_id", None)
            register_id = getattr(record, "register_id", None) or getattr(
                record, "assessment_register_id", None
            )

            if finding_id and finding_id not in validated_findings:
                validated_findings.append(finding_id)

            if register_id and register_id not in validated_register_ids:
                validated_register_ids.append(register_id)

            for ref in getattr(record, "evidence_references", []) or []:
                if ref not in supporting_evidence:
                    supporting_evidence.append(ref)

            for evidence_id in getattr(record, "evidence_ids", []) or []:
                if evidence_id not in supporting_evidence_ids:
                    supporting_evidence_ids.append(evidence_id)

        scenario.status = status
        scenario.supporting_evidence = supporting_evidence or list(scenario.supporting_evidence)
        scenario.supporting_evidence_ids = supporting_evidence_ids or list(
            getattr(scenario, "supporting_evidence_ids", [])
        )
        scenario.validated_finding_ids = validated_findings
        scenario.validated_register_ids = validated_register_ids

        return scenario

    ###########################################################################
    # Priority / risk helpers
    ###########################################################################

    def checklist_priority_score(self, checklist_id):

        item = self.checklist_item(checklist_id)

        if not item:
            return 0

        try:
            return int(item.get("priority_score") or 0)
        except Exception:
            return 0

    def detection_coverage_controls(self):

        return [
            item for item in self.checklist_items
            if str(item.get("domain", "")).lower().startswith("logging, monitoring")
            or str(item.get("id", "")).startswith("1.7")
        ]

    def detection_gap_score(self, checklist_coverage):

        detection_ids = {item.get("id") for item in self.detection_coverage_controls()}
        log_items = [
            item for item in checklist_coverage
            if item.get("id") in detection_ids
        ]

        if not log_items:
            return 50

        if any(item["status"] == "FAIL" for item in log_items):
            return 100

        if any(item["status"] == "NOT_EVALUATED" for item in log_items):
            return 50

        return 0

    def business_criticality_score(self, finding):

        controls = self.checklist_items_for_finding(finding)

        if not controls:
            return 20

        scores = []

        for item in controls:
            try:
                scores.append(int(item.get("priority_score") or 0))
            except Exception:
                continue

        if not scores:
            return 20

        return max(scores)
