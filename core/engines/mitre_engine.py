"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

MITRE Mapping Engine

Methodology step: MITRE ATT&CK Mapping.

Purpose
-------
Maps every Finding to MITRE ATT&CK tactics/techniques via the predefined
lookup table in data/mitre_mappings.yaml, keyed by "<tool>:<check_id>".
This replaces the old keyword-in-filename heuristic entirely - if a
finding's tool/check_id isn't in the table, the Checklist Validation Engine
may already have populated a fallback from the checklist item's own
mitre_mapping field; if neither exists, the finding is left unmapped rather
than guessed.

One finding may map to multiple techniques.

READ ONLY

===============================================================================
"""

import json
from pathlib import Path

import yaml

from rich.console import Console
from loguru import logger


console = Console()


class MitreMappingEngine:

    def __init__(self, mappings_file="data/mitre_mappings.yaml"):

        self.mappings_file = Path(mappings_file)

        self.output_directory = Path("output/mitre")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.mappings = self.load_mappings()

    ###########################################################################
    # Load
    ###########################################################################

    def load_mappings(self):

        if not self.mappings_file.exists():

            console.print(
                f"[yellow]MITRE mapping file not found: {self.mappings_file}[/yellow]"
            )

            return {}

        with open(self.mappings_file) as f:

            data = yaml.safe_load(f) or {}

        return data.get("mappings", {})

    ###########################################################################
    # Map
    ###########################################################################

    def map_finding(self, finding):

        tool_key = finding.tool_source.lower().replace(" ", "_")

        check_id = getattr(finding, "_tool_check_id", None)

        lookup_key = f"{tool_key}:{check_id}" if check_id else None

        techniques = self.mappings.get(lookup_key, []) if lookup_key else []

        for technique in techniques:

            if technique.get("tactic") not in finding.mitre_tactics:

                finding.mitre_tactics.append(technique.get("tactic"))

            if technique.get("technique_id") not in finding.mitre_techniques:

                finding.mitre_techniques.append(technique.get("technique_id"))

        # Fallback: keep whatever the Checklist Validation Engine already
        # seeded from the checklist item's own mitre_mapping field - do
        # not overwrite it.

        return finding

    ###########################################################################
    # Summary
    ###########################################################################

    def summarize(self, findings):

        tactics = {}

        techniques = {}

        mapped = 0

        for finding in findings:

            if finding.mitre_tactics or finding.mitre_techniques:

                mapped += 1

            for tactic in finding.mitre_tactics:

                tactics[tactic] = tactics.get(tactic, 0) + 1

            for technique in finding.mitre_techniques:

                techniques[technique] = techniques.get(technique, 0) + 1

        return {
            "total_findings": len(findings),
            "mapped_findings": mapped,
            "tactics": tactics,
            "techniques": techniques,
        }

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, findings, summary):

        with open(self.output_directory / "mitre_findings.json", "w") as f:

            json.dump(
                [f.to_dict(include_internal=True) for f in findings],
                f,
                indent=4,
                default=str,
            )

        with open(self.output_directory / "mitre_summary.json", "w") as f:

            json.dump(summary, f, indent=4)

    ###########################################################################
    # Run
    ###########################################################################

    def run(self, findings):

        console.rule(
            "[bold cyan]MITRE ATT&CK Mapping"
        )

        for finding in findings:

            self.map_finding(finding)

        summary = self.summarize(findings)

        self.save(findings, summary)

        logger.success(
            f"Mapped {summary['mapped_findings']}/{summary['total_findings']} findings "
            f"to {len(summary['techniques'])} MITRE techniques"
        )

        console.print(
            f"[green]MITRE : {summary['mapped_findings']} findings mapped, "
            f"{len(summary['tactics'])} tactics, "
            f"{len(summary['techniques'])} techniques[/green]"
        )

        return summary
