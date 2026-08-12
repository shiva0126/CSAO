"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Assessment Traceability Engine

Purpose
-------
Builds an assessment traceability graph that links raw evidence through the
full assessment workflow:
Evidence -> Finding -> Register -> Checklist -> Threat Scenario ->
Correlation -> Attack Path -> Risk -> Recommendation -> Report Section

The graph is used for explainability in the reporting layer.
===============================================================================
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import networkx as nx
from rich.console import Console
from loguru import logger


console = Console()


class AssessmentTraceabilityEngine:

    def __init__(self, knowledge_engine, config=None):

        self.knowledge = knowledge_engine
        self.config = config or {}
        self.output_directory = Path(
            self.config.get("output", {}).get(
                "traceability_directory", "output/traceability"
            )
        )
        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.graph = nx.DiGraph()

    ###########################################################################
    # Node helpers
    ###########################################################################

    def node_id(self, node_type, identifier):

        safe = re.sub(r"[^A-Za-z0-9._:-]+", "_", str(identifier or "unknown"))
        return f"{node_type}:{safe}"

    def add_node(self, node_type, identifier, **attrs):

        node_id = self.node_id(node_type, identifier)
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, type=node_type, identifier=str(identifier), **attrs)
        return node_id

    def add_edge(self, source, target, relationship, **attrs):

        if source and target:
            self.graph.add_edge(source, target, relationship=relationship, **attrs)

    ###########################################################################
    # Build
    ###########################################################################

    def _workbook_nodes(self):

        metadata = self.knowledge.workbook_metadata()

        for workbook_key, workbook in metadata.items():
            workbook_node = self.add_node(
                "WORKBOOK",
                workbook["workbook"],
                workbook_key=workbook_key,
                source_file=workbook.get("source_file", ""),
            )

            for worksheet in workbook.get("worksheets", []):
                worksheet_node = self.add_node(
                    "WORKSHEET",
                    f"{workbook['workbook']}::{worksheet}",
                    workbook=workbook["workbook"],
                    worksheet=worksheet,
                )
                self.add_edge(workbook_node, worksheet_node, "CONTAINS_WORKSHEET")

    def _report_section_nodes(self):

        sections = self.knowledge.report_section_catalog() or [
            {"id": "index", "title": "Overview"},
            {"id": "executive_summary", "title": "Executive Summary"},
            {"id": "technical_findings", "title": "Technical Findings"},
            {"id": "analyst_traceability", "title": "Analyst Traceability"},
            {"id": "mitre_matrix", "title": "MITRE ATT&CK Matrix"},
            {"id": "attack_path_summary", "title": "Attack Path Summary"},
            {"id": "checklist_coverage", "title": "Checklist Coverage"},
            {"id": "assessment_coverage", "title": "Assessment Coverage"},
            {"id": "evidence_index", "title": "Evidence Index"},
            {"id": "assessment_metadata", "title": "Assessment Metadata"},
            {"id": "permission_report", "title": "Permission Report"},
            {"id": "capability_report", "title": "Capability Report"},
            {"id": "read_only_verification", "title": "Read-Only Verification"},
            {"id": "risk_summary", "title": "Risk Summary"},
            {"id": "recommendations", "title": "Recommendations"},
            {"id": "appendices", "title": "Appendices"},
        ]

        for section in sections:
            section_id = section["id"]
            title = section["title"]
            self.add_node(
                "REPORT_SECTION",
                section_id,
                title=title,
                view="executive" if section_id in {"index", "executive_summary"} else "analyst",
            )

    def _control_nodes(self, checklist_coverage):

        coverage_by_id = {item["id"]: item for item in checklist_coverage}

        for item in self.knowledge.checklist_items:
            control_id = item.get("id")
            if not control_id:
                continue

            control_node = self.add_node(
                "CHECKLIST_CONTROL",
                control_id,
                title=item.get("title", ""),
                domain=item.get("domain", ""),
                check_area=item.get("check_area", ""),
                stride_category=item.get("stride_category", ""),
                priority_tier=item.get("priority_tier", ""),
                priority_score=item.get("priority_score", ""),
                evidence_type=item.get("evidence_type", ""),
                output_document=item.get("output_document", ""),
            )

            for source in self.knowledge._item_sources(item):
                source_key = f"{source.get('tool')}:{source.get('query_ref')}"
                source_node = self.add_node(
                    "EVIDENCE_SOURCE",
                    source_key,
                    tool=source.get("tool"),
                    query_ref=source.get("query_ref"),
                )
                self.add_edge(source_node, control_node, "VALIDATES_CONTROL")

                collector_node = self.add_node(
                    "COLLECTOR",
                    source.get("tool"),
                    collector=source.get("tool"),
                )
                self.add_edge(collector_node, source_node, "PRODUCES_EVIDENCE_SOURCE")

            checklist_workbook = self.add_node("WORKBOOK", "Checklist Workbook")
            master_sheet = self.add_node(
                "WORKSHEET",
                "Checklist Workbook::Master STRIDE-Checklist Map",
                workbook="Checklist Workbook",
                worksheet="Master STRIDE-Checklist Map",
            )
            evidence_sheet = self.add_node(
                "WORKSHEET",
                "Checklist Workbook::Evidence & Output Format",
                workbook="Checklist Workbook",
                worksheet="Evidence & Output Format",
            )
            mitre_sheet = self.add_node(
                "WORKSHEET",
                "Checklist Workbook::STRIDE Checklist Post-Val Log",
                workbook="Checklist Workbook",
                worksheet="STRIDE Checklist Post-Val Log",
            )
            self.add_edge(checklist_workbook, master_sheet, "CONTAINS_WORKSHEET")
            self.add_edge(checklist_workbook, evidence_sheet, "CONTAINS_WORKSHEET")
            self.add_edge(checklist_workbook, mitre_sheet, "CONTAINS_WORKSHEET")
            self.add_edge(master_sheet, control_node, "DEFINES_CONTROL")
            self.add_edge(evidence_sheet, control_node, "DEFINES_EVIDENCE")
            self.add_edge(mitre_sheet, control_node, "DEFINES_STRIDE_MAPPING")

            result = coverage_by_id.get(control_id, {})
            result_node = self.add_node(
                "ASSESSMENT_RESULT",
                f"CHECKLIST::{control_id}",
                status=result.get("status", "NOT_EVALUATED"),
                matched_findings=result.get("matched_findings", 0),
                manual_validation_required=result.get("manual_validation_required", False),
            )
            self.add_edge(control_node, result_node, "PRODUCES_RESULT")

    def _scenario_nodes(self, threat_scenarios):

        scenarios_by_id = {item.scenario_id: item for item in threat_scenarios}

        for scenario in self.knowledge.scenarios:
            scenario_node = self.add_node(
                "THREAT_SCENARIO",
                scenario.scenario_id,
                title=scenario.title,
                business_impact=scenario.business_impact,
                preconditions=scenario.preconditions,
                mitigation_strategy=scenario.mitigation_strategy,
                status=getattr(scenarios_by_id.get(scenario.scenario_id), "status", scenario.status),
            )

            threat_workbook = self.add_node("WORKBOOK", "Threat Scenario Workbook")
            refined_sheet = self.add_node(
                "WORKSHEET",
                "Threat Scenario Workbook::Refined Threat Scenarios",
                workbook="Threat Scenario Workbook",
                worksheet="Refined Threat Scenarios",
            )
            attack_path_sheet = self.add_node(
                "WORKSHEET",
                "Threat Scenario Workbook::Attack Path Linkage",
                workbook="Threat Scenario Workbook",
                worksheet="Attack Path Linkage",
            )
            self.add_edge(threat_workbook, refined_sheet, "CONTAINS_WORKSHEET")
            self.add_edge(threat_workbook, attack_path_sheet, "CONTAINS_WORKSHEET")
            self.add_edge(refined_sheet, scenario_node, "DEFINES_SCENARIO")
            self.add_edge(attack_path_sheet, scenario_node, "LINKS_SCENARIO")

            for checklist_id in scenario.prerequisite_checklists:
                self.add_edge(
                    self.add_node("CHECKLIST_CONTROL", checklist_id),
                    scenario_node,
                    "SUPPORTS_SCENARIO",
                )

            for attack_path in scenario.attack_path_refs:
                ap_node = self.add_node("ATTACK_PATH", attack_path)
                self.add_edge(scenario_node, ap_node, "IMPLEMENTS_TEMPLATE")

            for technique in scenario.mitre_techniques:
                tech_node = self.add_node("MITRE_TECHNIQUE", technique)
                self.add_edge(scenario_node, tech_node, "MAPS_TO")

    def _finding_chain(self, findings, assessment_register):

        register_by_id = {entry.register_id: entry for entry in assessment_register}

        for finding in findings:
            evidence_node = self.add_node(
                "EVIDENCE",
                finding.evidence_location or f"{finding.tool_source}:{finding.resource_id}",
                tool_source=finding.tool_source,
                evidence_location=finding.evidence_location,
            )
            finding_node = self.add_node(
                "FINDING",
                f"{finding.tool_source}:{getattr(finding, '_tool_check_id', 'unknown')}:{finding.resource_id}",
                title=finding.title,
                severity=finding.severity,
                tool_source=finding.tool_source,
                resource_id=finding.resource_id,
                mitre_tactics=list(getattr(finding, "mitre_tactics", []) or []),
                mitre_techniques=list(getattr(finding, "mitre_techniques", []) or []),
            )
            self.add_edge(evidence_node, finding_node, "NORMALIZES_TO")

            register_id = finding.assessment_register_id
            register = register_by_id.get(register_id)
            if register:
                register_node = self.add_node(
                    "ASSESSMENT_REGISTER_ENTRY",
                    register.register_id,
                    title=register.title,
                    source=register.source,
                    validation_status=register.validation_status,
                )
                self.add_edge(finding_node, register_node, "CAPTURED_BY")
            else:
                register_node = None

            for checklist_id in getattr(finding, "checklist_ids", []) or ([finding.checklist_id] if finding.checklist_id else []):
                if not checklist_id:
                    continue
                control_node = self.add_node("CHECKLIST_CONTROL", checklist_id)
                if register_node:
                    self.add_edge(register_node, control_node, "VALIDATES_CONTROL")
                else:
                    self.add_edge(finding_node, control_node, "VALIDATES_CONTROL")

            for scenario_id in getattr(finding, "threat_scenario_ids", []) or []:
                scenario_node = self.add_node("THREAT_SCENARIO", scenario_id)
                if register_node:
                    self.add_edge(register_node, scenario_node, "SUPPORTS_SCENARIO")
                else:
                    self.add_edge(finding_node, scenario_node, "SUPPORTS_SCENARIO")

            risk_node = self.add_node(
                "RISK_RECORD",
                register_id or finding.resource_id,
                score=getattr(finding, "_risk_score", 0) or 0,
                factors=getattr(finding, "_risk_factors", {}) or {},
                severity=finding.severity,
                crown_jewel=finding.crown_jewel,
            )
            if register_node:
                self.add_edge(register_node, risk_node, "ASSESSED_AS")
            else:
                self.add_edge(finding_node, risk_node, "ASSESSED_AS")

            for attack_path_id in getattr(finding, "attack_path_ids", []) or []:
                ap_node = self.add_node("ATTACK_PATH", attack_path_id)
                self.add_edge(ap_node, risk_node, "INFORMS_RISK")

            for recommendation_id in getattr(finding, "recommendation_ids", []) or []:
                rec_node = self.add_node("RECOMMENDATION", recommendation_id)
                self.add_edge(risk_node, rec_node, "JUSTIFIES_RECOMMENDATION")

    def _correlation_chain(self, correlated_threats):

        for threat in correlated_threats:
            corr_node = self.add_node(
                "CORRELATED_THREAT",
                threat.correlation_id,
                scenario_ids=list(threat.scenario_ids),
                attack_path_refs=list(threat.attack_path_refs),
                status=threat.status,
                source_resources=list(threat.source_resources),
                target_resources=list(threat.target_resources),
            )

            for scenario_id in threat.scenario_ids:
                self.add_edge(
                    self.add_node("THREAT_SCENARIO", scenario_id),
                    corr_node,
                    "CORRELATES_TO",
                )

            for attack_path_id in threat.attack_path_refs:
                ap_node = self.add_node("ATTACK_PATH", attack_path_id)
                self.add_edge(corr_node, ap_node, "REFINES_ATTACK_PATH")

    def _attack_path_chain(self, attack_path_candidates):

        for candidate in attack_path_candidates:
            ap_node = self.add_node(
                "ATTACK_PATH",
                candidate["id"],
                hop_count=candidate.get("hop_count", 0),
                label=candidate.get("label", ""),
                correlated_threats=list(candidate.get("correlated_threats", []) or []),
                template_refs=list(candidate.get("template_refs", []) or []),
            )

            for threat_id in candidate.get("correlated_threats", []) or []:
                corr_node = self.add_node("CORRELATED_THREAT", threat_id)
                self.add_edge(corr_node, ap_node, "GENERATES_ATTACK_PATH")

            for template_ref in candidate.get("template_refs", []) or []:
                template_node = self.add_node("ATTACK_PATH_TEMPLATE", template_ref)
                self.add_edge(template_node, ap_node, "DOCUMENTS_PATTERN")

    def _recommendation_chain(self, recommendations):

        for recommendation in recommendations:
            rec_node = self.add_node(
                "RECOMMENDATION",
                recommendation.recommendation_id,
                title=recommendation.title,
                status=recommendation.status,
            )

            for register_id in recommendation.assessment_register_ids:
                register_node = self.add_node("ASSESSMENT_REGISTER_ENTRY", register_id)
                self.add_edge(register_node, rec_node, "JUSTIFIES")

            for checklist_id in recommendation.checklist_ids:
                control_node = self.add_node("CHECKLIST_CONTROL", checklist_id)
                self.add_edge(control_node, rec_node, "RECOMMENDS_ACTION_FOR")

            for scenario_id in recommendation.threat_scenario_refs:
                scenario_node = self.add_node("THREAT_SCENARIO", scenario_id)
                self.add_edge(scenario_node, rec_node, "SUPPORTS_ACTION")

            for attack_path_id in recommendation.attack_path_refs:
                ap_node = self.add_node("ATTACK_PATH", attack_path_id)
                self.add_edge(ap_node, rec_node, "INFORMS_ACTION")

            for evidence_ref in recommendation.evidence_references:
                evidence_node = self.add_node("EVIDENCE", evidence_ref)
                self.add_edge(evidence_node, rec_node, "SUPPORTS_ACTION")

            section_ids = recommendation.report_sections or [
                "executive_summary",
                "analyst_traceability",
            ]
            for section_id in section_ids:
                section_node = self.add_node("REPORT_SECTION", section_id)
                self.add_edge(rec_node, section_node, "DISPLAYS_IN")

    def _report_section_chain(self):
        self._report_section_nodes()

        index = self.add_node("REPORT_SECTION", "index")
        sections = self.knowledge.report_section_catalog() or [
            {"id": "executive_summary"},
            {"id": "technical_findings"},
            {"id": "analyst_traceability"},
            {"id": "mitre_matrix"},
            {"id": "attack_path_summary"},
            {"id": "checklist_coverage"},
            {"id": "assessment_coverage"},
            {"id": "evidence_index"},
            {"id": "assessment_metadata"},
            {"id": "permission_report"},
            {"id": "capability_report"},
            {"id": "read_only_verification"},
            {"id": "risk_summary"},
            {"id": "recommendations"},
            {"id": "appendices"},
        ]
        for section in sections:
            section_id = section["id"]
            if section_id == "index":
                continue
            section_node = self.add_node("REPORT_SECTION", section_id)
            self.add_edge(index, section_node, "LINKS_REPORT")

    def build(
        self,
        findings,
        assessment_register,
        checklist_coverage,
        threat_scenarios,
        correlated_threats,
        attack_path_candidates,
        risk_summary,
        recommendations,
    ):

        self.graph.clear()
        self._report_section_chain()
        self._workbook_nodes()
        self._control_nodes(checklist_coverage)
        self._scenario_nodes(threat_scenarios)
        self._finding_chain(findings, assessment_register)
        self._correlation_chain(correlated_threats)
        self._attack_path_chain(attack_path_candidates)
        self._recommendation_chain(recommendations)

        # Tie the top-level report sections back to the recommendations for
        # explainability in the rendered report.
        for recommendation in recommendations:
            rec_node = self.add_node("RECOMMENDATION", recommendation.recommendation_id)
            for section_id in recommendation.report_sections or (
                "analyst_traceability",
                "executive_summary",
            ):
                section_node = self.add_node("REPORT_SECTION", section_id)
                self.add_edge(rec_node, section_node, "DISPLAYS_IN")

        self.risk_summary = risk_summary or {}
        self.save()
        return self.graph

    ###########################################################################
    # Query helpers
    ###########################################################################

    def _upstream_nodes(self, node_id):

        visited = set()
        stack = [node_id]

        while stack:
            current = stack.pop()
            for predecessor in self.graph.predecessors(current):
                if predecessor in visited:
                    continue
                visited.add(predecessor)
                stack.append(predecessor)

        return visited

    def _nodes_of_type(self, node_ids, node_type):

        rows = []
        for node_id in node_ids:
            data = self.graph.nodes[node_id]
            if data.get("type") == node_type:
                rows.append((node_id, data))
        return rows

    def recommendation_context(self, recommendation_id):

        node_id = self.node_id("RECOMMENDATION", recommendation_id)
        if not self.graph.has_node(node_id):
            return {}

        upstream = self._upstream_nodes(node_id)
        upstream.add(node_id)

        context = {
            "recommendation": self.graph.nodes[node_id],
            "evidence": [data for _, data in self._nodes_of_type(upstream, "EVIDENCE")],
            "findings": [data for _, data in self._nodes_of_type(upstream, "FINDING")],
            "register_entries": [data for _, data in self._nodes_of_type(upstream, "ASSESSMENT_REGISTER_ENTRY")],
            "checklist_controls": [data for _, data in self._nodes_of_type(upstream, "CHECKLIST_CONTROL")],
            "threat_scenarios": [data for _, data in self._nodes_of_type(upstream, "THREAT_SCENARIO")],
            "correlated_threats": [data for _, data in self._nodes_of_type(upstream, "CORRELATED_THREAT")],
            "attack_paths": [data for _, data in self._nodes_of_type(upstream, "ATTACK_PATH")],
            "risk_records": [data for _, data in self._nodes_of_type(upstream, "RISK_RECORD")],
            "report_sections": [data for _, data in self._nodes_of_type(upstream, "REPORT_SECTION")],
            "workbooks": [data for _, data in self._nodes_of_type(upstream, "WORKBOOK")],
            "worksheets": [data for _, data in self._nodes_of_type(upstream, "WORKSHEET")],
        }

        paths = []
        for evidence in context["evidence"]:
            evidence_node = self.node_id("EVIDENCE", evidence["identifier"])
            if self.graph.has_node(evidence_node) and nx.has_path(self.graph, evidence_node, node_id):
                try:
                    paths.append(nx.shortest_path(self.graph, evidence_node, node_id))
                except nx.NetworkXNoPath:
                    continue

        context["paths"] = paths
        return context

    def analyst_summary(self, recommendation_id):

        context = self.recommendation_context(recommendation_id)
        if not context:
            return {}

        recommendations = context.get("recommendation", {})
        risk = context.get("risk_records", [])

        return {
            "recommendation_id": recommendation_id,
            "title": recommendations.get("title", ""),
            "evidence": [item.get("identifier") for item in context.get("evidence", [])],
            "checklist_controls": [item.get("identifier") for item in context.get("checklist_controls", [])],
            "threat_scenarios": [item.get("identifier") for item in context.get("threat_scenarios", [])],
            "attack_paths": [item.get("identifier") for item in context.get("attack_paths", [])],
            "services": sorted({
                item.get("service")
                for item in context.get("findings", [])
                if item.get("service")
            } | {
                item.get("service")
                for item in context.get("register_entries", [])
                if item.get("service")
            }),
            "mitre_techniques": sorted({
                technique
                for scenario in context.get("threat_scenarios", [])
                for technique in (scenario.get("mitre_techniques") or [])
            }),
            "crown_jewel": sorted({
                item.get("crown_jewel")
                for item in context.get("risk_records", [])
                if item.get("crown_jewel")
            }),
            "risk_score": max((item.get("score", 0) or 0) for item in risk) if risk else 0,
            "risk_factors": [item.get("factors", {}) for item in risk],
            "assessment_register_entries": [item.get("identifier") for item in context.get("register_entries", [])],
            "workbooks": [item.get("identifier") for item in context.get("workbooks", [])],
            "worksheets": [item.get("identifier") for item in context.get("worksheets", [])],
            "paths": context.get("paths", []),
        }

    ###########################################################################
    # Save
    ###########################################################################

    def save(self):

        output_file = self.output_directory / "traceability_graph.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "nodes": [
                        {"id": node_id, **data}
                        for node_id, data in self.graph.nodes(data=True)
                    ],
                    "edges": [
                        {"source": source, "target": target, **data}
                        for source, target, data in self.graph.edges(data=True)
                    ],
                },
                f,
                indent=4,
                default=str,
            )

        logger.success(f"Traceability graph saved : {output_file}")
