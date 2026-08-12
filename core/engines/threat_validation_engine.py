"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Threat Validation Engine

Purpose
-------
Builds threat-scenario records from the workbook-backed checklist and only
marks a scenario VALIDATED after its prerequisite checklist controls have
been confirmed through checklist validation outputs.
===============================================================================
"""

import json
from pathlib import Path

import yaml
from rich.console import Console
from loguru import logger
import copy

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.schema.threats import ThreatScenarioRecord


console = Console()


class ThreatValidationEngine:

    def __init__(self, config, knowledge_engine=None):

        self.config = config
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)
        self.checklist_file = Path(
            config.get("checklist", {}).get(
                "file", "checklists/checklist.yaml"
            )
        )
        self.output_directory = Path(
            config.get("output", {}).get(
                "threat_directory", "output/threats"
            )
        )
        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.checklist_items = self.load_checklist()
        self.threat_scenarios = []

    def load_checklist(self):

        if not self.checklist_file.exists():
            return []

        with open(self.checklist_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return data.get("checklist", [])

    def _finding_from_record(self, record):

        return getattr(record, "_finding", record)

    def _register_id(self, record):

        return getattr(record, "register_id", None) or getattr(record, "assessment_register_id", None)

    def _scenario_key(self, item):

        text = item.get("threat_scenario") or item.get("title") or "Unspecified threat scenario"
        attack_paths = ",".join(item.get("related_attack_paths") or [])
        return f"{text}::{attack_paths}"

    def build_scenarios(self):

        return [copy.deepcopy(scenario) for scenario in self.knowledge.scenarios]

    def validate_scenario(self, scenario, coverage, records):

        scenario = self.knowledge.validate_scenario(scenario, coverage, records)

        for record in records:
            finding = self._finding_from_record(record)
            checklist_ids = set(getattr(finding, "checklist_ids", []) or [])

            if not checklist_ids.intersection(scenario.prerequisite_checklists):
                continue

            if hasattr(record, "threat_scenario_references"):
                if scenario.scenario_id not in record.threat_scenario_references:
                    record.threat_scenario_references.append(scenario.scenario_id)

            if hasattr(record, "attack_path_references"):
                for attack_path in getattr(scenario, "attack_path_refs", []) or []:
                    if attack_path and attack_path not in record.attack_path_references:
                        record.attack_path_references.append(attack_path)

        return scenario

    def run(self, coverage, records):

        console.rule("[bold cyan]Threat Validation")

        self.threat_scenarios = self.build_scenarios()

        for scenario in self.threat_scenarios:
            self.validate_scenario(scenario, coverage, records)

        self.save()

        validated = sum(1 for scenario in self.threat_scenarios if scenario.status == "VALIDATED")

        console.print(
            f"[green]Threat Validation completed: {validated}/{len(self.threat_scenarios)} scenario(s) validated[/green]"
        )

        return self.threat_scenarios

    def save(self):

        output_file = self.output_directory / "threat_scenarios.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([scenario.to_dict() for scenario in self.threat_scenarios], f, indent=4, default=str)

        logger.success(f"Threat scenarios saved : {output_file}")
