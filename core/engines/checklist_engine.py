"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Checklist Validation Engine

Methodology step: Checklist Validation.

Purpose
-------
The checklist - not tool output - drives the assessment. Every checklist
item is query-driven via one or more `sources` ([{tool, query_ref}, ...],
see checklists/README.md); this engine determines each item's status and
tags every matching Finding with its checklist_id, so multiple findings
(from one or several tools) can satisfy/fail one checklist item. A single
`tool`/`query_ref` pair (legacy shorthand) is also accepted and normalized
into a one-element `sources` list.

Status rules (deterministic, evidence-index driven - never guessed):

  NOT_EVALUATED   the item's tool produced no evidence at all (tool
                   disabled / not run this assessment)
  MANUAL_REVIEW   the tool ran and the item is flagged
                   manual_validation_required (regardless of whether
                   findings exist - a human must confirm either way)
  FAIL            the tool ran, findings matched this check, and manual
                   review isn't required
  PASS            the tool ran, zero findings matched this check, and
                   manual review isn't required

READ ONLY

===============================================================================
"""

import json
import datetime
from pathlib import Path

import yaml

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.schema.evidence import EvidenceRecord


console = Console()


class ChecklistValidationEngine:

    def __init__(self, config, knowledge_engine=None):

        self.config = config
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)

        self.checklist_file = Path(
            config.get("checklist", {}).get(
                "file", "checklists/checklist.example.yaml"
            )
        )

        self.output_directory = Path("output/checklist")
        self.evidence_output_directory = Path("output/evidence")

        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.evidence_output_directory.mkdir(parents=True, exist_ok=True)

        self.items = self.knowledge.checklist_items or self.load_checklist()

        self.evidence_index = self.load_evidence_index()
        self.evidence_records = []

    ###########################################################################
    # Load Checklist
    ###########################################################################

    def load_checklist(self):

        if not self.checklist_file.exists():

            console.print(
                f"[yellow]Checklist file not found: {self.checklist_file}[/yellow]"
            )

            return []

        with open(self.checklist_file) as f:

            data = yaml.safe_load(f) or {}

        return data.get("checklist", [])

    def load_evidence_index(self):

        index_file = Path("output/evidence_index.json")

        if not index_file.exists():

            return {}

        try:

            return json.load(open(index_file)).get("evidence", {})

        except Exception:

            return {}

    ###########################################################################
    # Tool -> evidence directory name mapping
    ###########################################################################

    TOOL_EVIDENCE_DIR = {

        "steampipe": "steampipe",
        "prowler": "prowler",
        "cloudsplaining": "cloudsplaining",
        "access_analyzer": "access_analyzer",
        "config_aggregator": "config_aggregator",
        "cartography": "cartography",
        "tenable": "tenable",

    }

    def tool_has_evidence(self, tool):

        directory = self.TOOL_EVIDENCE_DIR.get(tool, tool)

        files = self.evidence_index.get(directory, [])

        return len(files) > 0

    ###########################################################################
    # Sources normalization
    #
    # A checklist item is validated by one or more (tool, query_ref) pairs.
    # Real assessment checklists routinely need more than one - e.g. one
    # control validated by both an SSH-open-to-world query AND an
    # RDP-open-to-world query, or by both a Steampipe query and a
    # Cloudsplaining finding type. `sources` is the general form; a bare
    # `tool`/`query_ref` pair is accepted as shorthand for a single source.
    ###########################################################################

    def get_sources(self, item):

        return self.knowledge._item_sources(item)

    ###########################################################################
    # Validate
    ###########################################################################

    def apply_mitre_mapping(self, finding, mitre_mapping):
        """
        Supports both mitre_mapping shapes a checklist item may carry:
          - list of {tactic, technique_id, technique} triplets (hand-authored)
          - {"tactics": [...], "techniques": [...]} flat lists (workbook import,
            where the source data doesn't cleanly pair each technique to a
            single tactic - see checklists/README.md)
        """

        if not mitre_mapping:

            return

        def append_unique(target, value):

            if value and value not in target:

                target.append(value)

        if isinstance(mitre_mapping, dict):

            for tactic in mitre_mapping.get("tactics") or []:

                append_unique(finding.mitre_tactics, tactic)

            for technique in mitre_mapping.get("techniques") or []:

                append_unique(finding.mitre_techniques, technique)

        else:

            for mapping in mitre_mapping:

                append_unique(finding.mitre_tactics, mapping.get("tactic"))
                append_unique(
                    finding.mitre_techniques,
                    mapping.get("technique_id") or mapping.get("technique"),
                )

    def _finding_from_record(self, record):

        return getattr(record, "_finding", record)

    def _register_id(self, record):

        return getattr(record, "register_id", None) or getattr(record, "assessment_register_id", None)

    def _append_unique(self, target, value):

        if value and value not in target:

            target.append(value)

    def _evidence_files_for_tool(self, tool):

        directory = self.TOOL_EVIDENCE_DIR.get(tool, tool)
        return list(self.evidence_index.get(directory, []) or [])

    def _finding_id(self, finding):

        return (
            f"{finding.tool_source}:{getattr(finding, '_tool_check_id', 'unknown')}:"
            f"{finding.resource_id}"
        )

    def _make_evidence_records(self, item, status, matched, sources):

        records = []
        control_id = item.get("id", "")
        scenario_refs = self.knowledge.scenario_ids_for_checklist(control_id)
        attack_refs = self.knowledge.attack_path_refs_for_checklist(control_id)
        now = datetime.datetime.utcnow().isoformat() + "Z"

        if sources:
            for index, source in enumerate(sources, start=1):
                files = self._evidence_files_for_tool(source["tool"])
                automatic = bool(files)
                result = status if automatic else "NOT_EVALUATED"
                records.append(
                    EvidenceRecord(
                        evidence_id=f"EVID-{control_id}-{index:02d}",
                        checklist_control_id=control_id,
                        collector=source["tool"],
                        raw_evidence=files,
                        evidence_type=item.get("evidence_type", ""),
                        evidence_format=item.get("evidence_format", ""),
                        collection_method=item.get("collection_method", ""),
                        timestamp=now,
                        source=source.get("query_ref", ""),
                        result=result,
                        automatic=automatic,
                        finding_ids=[
                            self._finding_id(self._finding_from_record(record))
                            for record in matched
                        ],
                        register_ids=[
                            self._register_id(record)
                            for record in matched
                            if self._register_id(record)
                        ],
                        attack_path_refs=attack_refs,
                        threat_scenario_refs=scenario_refs,
                        notes=item.get("pass_criteria", "") or item.get("fail_indicator", ""),
                    )
                )

        if not records:
            records.append(
                EvidenceRecord(
                    evidence_id=f"EVID-{control_id}-MANUAL",
                    checklist_control_id=control_id,
                    collector="manual_review",
                    raw_evidence=[],
                    evidence_type=item.get("evidence_type", ""),
                    evidence_format=item.get("evidence_format", ""),
                    collection_method=item.get("collection_method", ""),
                    timestamp=now,
                    source="manual",
                    result=status,
                    automatic=False,
                    finding_ids=[
                        self._finding_id(self._finding_from_record(record))
                        for record in matched
                    ],
                    register_ids=[
                        self._register_id(record)
                        for record in matched
                        if self._register_id(record)
                    ],
                    attack_path_refs=attack_refs,
                    threat_scenario_refs=scenario_refs,
                    notes=item.get("pass_criteria", "") or item.get("fail_indicator", ""),
                )
            )

        return records

    def evaluate_item(self, item, records):

        sources = self.get_sources(item)
        status, matched, sources = self.knowledge.evaluate_checklist_item(item, records)

        evidence_records = self._make_evidence_records(item, status, matched, sources)
        evidence_ids = [record.evidence_id for record in evidence_records]
        evidence_refs = sorted({
            path
            for record in evidence_records
            for path in record.raw_evidence
        })
        self.evidence_records.extend(evidence_records)

        for record in matched:

            finding = self._finding_from_record(record)

            if item.get("id") not in getattr(finding, "checklist_ids", []):
                finding.checklist_ids.append(item.get("id"))

            finding.checklist_id = item.get("id")
            finding.validation_status = status
            finding.related_threat_scenario = item.get("threat_scenario") or finding.related_threat_scenario
            for scenario_id in self.knowledge.scenario_ids_for_checklist(item.get("id")):
                self._append_unique(finding.threat_scenario_ids, scenario_id)
                self._append_unique(record.threat_scenario_references, scenario_id)

            for attack_path in self.knowledge.attack_path_refs_for_checklist(item.get("id")):
                self._append_unique(finding.attack_path_ids, attack_path)
                self._append_unique(record.attack_path_references, attack_path)

            for evidence_id in evidence_ids:
                self._append_unique(getattr(finding, "evidence_ids", []), evidence_id)
                self._append_unique(getattr(record, "evidence_ids", []), evidence_id)

            for evidence_ref in evidence_refs:
                self._append_unique(getattr(record, "evidence_references", []), evidence_ref)

            if hasattr(record, "checklist_references") and item.get("id") not in record.checklist_references:
                record.checklist_references.append(item.get("id"))

            record.validation_status = status
            if hasattr(record, "mitre_tactics"):
                self.apply_mitre_mapping(record, item.get("mitre_mapping"))
            if hasattr(record, "mitre_techniques"):
                self.apply_mitre_mapping(record, item.get("mitre_mapping"))

            self.apply_mitre_mapping(finding, item.get("mitre_mapping"))

        return {

            "id": item.get("id"),
            "title": item.get("title"),
            "tools": [s["tool"] for s in sources],
            "sources": sources,
            "status": status,
            "manual_validation_required": bool(item.get("manual_validation_required")),
            "matched_findings": len(matched),
            "register_ids": [self._register_id(record) for record in matched if self._register_id(record)],
            "checklist_ids": [item.get("id")] if item.get("id") else [],
            "related_attack_paths": self.knowledge.attack_path_refs_for_checklist(item.get("id")),
            "evidence_ids": evidence_ids,
            "evidence_records": [record.to_dict() for record in evidence_records],

        }

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, coverage):

        output_file = self.output_directory / "checklist_coverage.json"

        with open(output_file, "w") as f:

            json.dump(coverage, f, indent=4, default=str)

        logger.success(
            f"Checklist coverage saved : {output_file}"
        )

        evidence_output = self.evidence_output_directory / "evidence_records.json"

        with open(evidence_output, "w", encoding="utf-8") as f:
            json.dump(
                [record.to_dict() for record in self.evidence_records],
                f,
                indent=4,
                default=str,
            )

        logger.success(
            f"Canonical evidence saved : {evidence_output}"
        )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self, records):

        console.rule(
            "[bold cyan]Checklist Validation"
        )

        coverage = [
            self.evaluate_item(item, records)
            for item in self.items
        ]

        self.save(coverage)

        summary = {
            "PASS": sum(1 for c in coverage if c["status"] == "PASS"),
            "FAIL": sum(1 for c in coverage if c["status"] == "FAIL"),
            "MANUAL_REVIEW": sum(1 for c in coverage if c["status"] == "MANUAL_REVIEW"),
            "NOT_EVALUATED": sum(1 for c in coverage if c["status"] == "NOT_EVALUATED"),
        }

        console.print(
            f"[green]Checklist : {summary['PASS']} PASS, "
            f"[red]{summary['FAIL']} FAIL[/red], "
            f"[yellow]{summary['MANUAL_REVIEW']} MANUAL_REVIEW[/yellow], "
            f"{summary['NOT_EVALUATED']} NOT_EVALUATED[/green]"
        )

        return coverage
