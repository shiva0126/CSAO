"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Assessment Register Engine

Purpose
-------
Converts normalized Findings into the central Assessment Register. This
register becomes the primary working area for the rest of the workflow.
===============================================================================
"""

import json
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.schema.assessment_register import AssessmentRegisterEntry


console = Console()


class AssessmentRegisterEngine:

    def __init__(self, config, assessment_id, knowledge_engine=None):

        self.config = config
        self.assessment_id = assessment_id
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)
        self.output_directory = Path(
            config.get("output", {}).get(
                "assessment_register_directory", "output/assessment_register"
            )
        )
        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.entries = []
        self._by_register_id = {}
        self._by_finding_id = {}

    def build_register_entry(self, index, finding):

        register_id = f"AR-{index:04d}"

        entry = AssessmentRegisterEntry.from_finding(
            self.assessment_id, register_id, finding
        )

        entry.finding_id = entry.finding_id or register_id
        entry._finding = finding
        finding.assessment_register_id = register_id

        candidate_checklists = self.knowledge.checklist_ids_for_finding(finding)
        finding.checklist_ids = list(
            dict.fromkeys(
                list(getattr(finding, "checklist_ids", []) or []) + candidate_checklists
            )
        )
        finding.threat_scenario_ids = list(
            dict.fromkeys(
                list(getattr(finding, "threat_scenario_ids", []) or [])
                + [
                    scenario_id
                    for checklist_id in finding.checklist_ids
                    for scenario_id in self.knowledge.scenario_ids_for_checklist(checklist_id)
                ]
            )
        )
        finding.attack_path_ids = list(
            dict.fromkeys(
                list(getattr(finding, "attack_path_ids", []) or [])
                + [
                    attack_path
                    for checklist_id in finding.checklist_ids
                    for attack_path in self.knowledge.attack_path_refs_for_checklist(checklist_id)
                ]
            )
        )
        finding.recommendation_ids = list(getattr(finding, "recommendation_ids", []) or [])

        if finding.evidence_location:
            entry.evidence_references = [finding.evidence_location]

        if finding.analyst_notes:
            entry.analyst_notes = finding.analyst_notes

        entry.checklist_references = list(getattr(finding, "checklist_ids", []) or [])
        entry.threat_scenario_references = list(getattr(finding, "threat_scenario_ids", []) or [])
        entry.attack_path_references = list(getattr(finding, "attack_path_ids", []) or [])

        self._by_register_id[register_id] = entry
        self._by_finding_id[entry.finding_id] = entry

        return entry

    def run(self, findings):

        console.rule("[bold cyan]Assessment Register")

        self.entries = [
            self.build_register_entry(index + 1, finding)
            for index, finding in enumerate(findings)
        ]

        self.save()

        console.print(
            f"[green]Assessment Register created with {len(self.entries)} entries[/green]"
        )

        return self.entries

    def save(self):

        output_file = self.output_directory / "assessment_register.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(
                [entry.to_dict() for entry in self.entries],
                f,
                indent=4,
                default=str,
            )

        logger.success(f"Assessment Register saved : {output_file}")

    def update_entry(self, register_id, **updates):

        entry = self._by_register_id.get(register_id)
        if not entry:
            return None

        for key, value in updates.items():
            if hasattr(entry, key):
                setattr(entry, key, value)

        return entry

    def entries_for_checklist(self, checklist_id):

        return [
            entry for entry in self.entries if checklist_id in entry.checklist_references
        ]
