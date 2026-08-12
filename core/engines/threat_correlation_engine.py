"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Threat Correlation Engine

Purpose
-------
Consumes validated threat scenarios and groups them into correlated threats
when they share attack-path context, resources, or evidence.
===============================================================================
"""

import json
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.schema.threats import CorrelatedThreat


console = Console()


class ThreatCorrelationEngine:

    def __init__(self, config, knowledge_engine=None):

        self.config = config
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)
        self.output_directory = Path(
            config.get("output", {}).get(
                "threat_directory", "output/threats"
            )
        )
        self.output_directory.mkdir(parents=True, exist_ok=True)

    def build_component(self, scenario, records):

        source_resources = set()
        target_resources = set()
        evidence = set(scenario.supporting_evidence)
        register_refs = set(scenario.validated_register_ids)
        attack_path_refs = set(getattr(scenario, "attack_path_refs", []) or [])

        if not attack_path_refs and self.knowledge.threat_scenario(scenario.scenario_id):
            attack_path_refs.update(
                self.knowledge.threat_scenario(scenario.scenario_id).attack_path_refs
            )

        for record in records:
            finding = getattr(record, "_finding", record)

            if not set(getattr(finding, "checklist_ids", []) or []).intersection(
                scenario.prerequisite_checklists
            ):
                continue

            if finding.internet_facing == "Yes":
                source_resources.add(finding.resource_id)

            if finding.crown_jewel == "Yes":
                target_resources.add(finding.resource_id)

            evidence.update(getattr(record, "evidence_references", []) or [])
            register_id = getattr(record, "register_id", None) or getattr(record, "assessment_register_id", None)
            if register_id:
                register_refs.add(register_id)

        if not source_resources and records:
            source_resources.update(
                record.resource for record in records
                if getattr(record, "resource", None)
                and getattr(record, "internet_facing", "No") == "Yes"
            )

        return CorrelatedThreat(
            correlation_id=scenario.scenario_id.replace("TS", "CT"),
            scenario_ids=[scenario.scenario_id],
            status="CORRELATED" if scenario.status == "VALIDATED" else scenario.status,
            attack_path_refs=sorted(attack_path_refs),
            source_resources=sorted(source_resources),
            target_resources=sorted(target_resources),
            supporting_evidence=sorted(evidence),
            validated_register_ids=sorted(register_refs),
            correlation_reason="Shared validated threat context",
        )

    def group_threats(self, threats):

        groups = []

        for threat in threats:
            merged = False

            for group in groups:
                if (
                    set(group.scenario_ids) & set(threat.scenario_ids)
                    or set(group.attack_path_refs) & set(threat.attack_path_refs)
                    or set(group.source_resources) & set(threat.source_resources)
                    or set(group.target_resources) & set(threat.target_resources)
                ):
                    group.scenario_ids = sorted(set(group.scenario_ids + threat.scenario_ids))
                    group.attack_path_refs = sorted(set(group.attack_path_refs + threat.attack_path_refs))
                    group.source_resources = sorted(set(group.source_resources + threat.source_resources))
                    group.target_resources = sorted(set(group.target_resources + threat.target_resources))
                    group.supporting_evidence = sorted(set(group.supporting_evidence + threat.supporting_evidence))
                    group.validated_register_ids = sorted(set(group.validated_register_ids + threat.validated_register_ids))
                    group.attack_path_refs = sorted(set(group.attack_path_refs + threat.attack_path_refs))
                    if threat.status == "CORRELATED":
                        group.status = "CORRELATED"
                    merged = True
                    break

            if not merged:
                groups.append(threat)

        for index, group in enumerate(groups, start=1):
            group.correlation_id = f"CT-{index:03d}"

        return groups

    def save(self, threats):

        output_file = self.output_directory / "correlated_threats.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([threat.to_dict() for threat in threats], f, indent=4, default=str)

        logger.success(f"Correlated threats saved : {output_file}")

    def run(self, scenarios, records):

        console.rule("[bold cyan]Threat Correlation")

        validated = [scenario for scenario in scenarios if scenario.status == "VALIDATED"]

        threats = [self.build_component(scenario, records) for scenario in validated]

        correlated = self.group_threats(threats)

        self.save(correlated)

        console.print(
            f"[green]Threat Correlation produced {len(correlated)} correlated threat object(s)[/green]"
        )

        return correlated
