"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Crown Jewel Correlation Engine

Methodology step: Crown Jewel Identification / Correlation.

Purpose
-------
Loads the manually maintained Crown Jewel inventory (crown_jewels/*.yaml)
and determines whether each Finding's affected resource is a Crown Jewel.
This never auto-discovers "importance" - it only matches against the
externally supplied inventory, by design (business criticality is a human
judgment, not something inferrable from cloud metadata).

Matching order (first match wins):
  1. Exact resource_id match
  2. Exact resource_name match
  3. Glob pattern match (fnmatch) against resource_id or resource_name

READ ONLY

===============================================================================
"""

import fnmatch
import json
from pathlib import Path

import yaml

from rich.console import Console
from loguru import logger


console = Console()

ASSET_ID_FIELDS = (
    "InstanceId", "GroupId", "VpcId", "FunctionName", "FunctionArn",
    "RoleName", "Arn", "UserName", "Name", "DBInstanceIdentifier",
)


class CrownJewelEngine:

    def __init__(self, config):

        self.config = config

        self.inventory_file = Path(
            config.get("crown_jewels", {}).get(
                "file", "crown_jewels/crown_jewels.example.yaml"
            )
        )

        self.output_directory = Path("output/crown_jewel")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.entries = self.load_inventory()

    ###########################################################################
    # Load
    ###########################################################################

    def load_inventory(self):

        if not self.inventory_file.exists():

            console.print(
                f"[yellow]Crown Jewel inventory not found: {self.inventory_file}[/yellow]"
            )

            return []

        with open(self.inventory_file) as f:

            data = yaml.safe_load(f) or {}

        return data.get("crown_jewels", [])

    ###########################################################################
    # Match
    ###########################################################################

    def match(self, resource_id, resource_name):

        for entry in self.entries:

            criteria = entry.get("match", {})

            if criteria.get("resource_id") and criteria["resource_id"] == resource_id:

                return entry

            if criteria.get("resource_name") and criteria["resource_name"] == resource_name:

                return entry

        for entry in self.entries:

            pattern = entry.get("match", {}).get("pattern")

            if not pattern:

                continue

            if fnmatch.fnmatch(str(resource_id), pattern) or fnmatch.fnmatch(str(resource_name), pattern):

                return entry

        return None

    def is_crown_jewel(self, resource_id, resource_name):
        """
        Reused by the Attack Path Engine when tagging graph nodes, so
        crown-jewel matching logic lives in exactly one place.
        """

        return self.match(resource_id, resource_name) is not None

    ###########################################################################
    # Crown Jewel Identification
    #
    # Standalone methodology step (before Evidence Collection even runs):
    # cross-references the Discovery Engine's raw asset inventory against
    # the Crown Jewel inventory, independent of any findings. Findings-level
    # tagging happens later, in tag()/run(), once Normalization has produced
    # Finding objects for Threat Correlation.
    ###########################################################################

    def identify_in_inventory(self, inventory_dir="output/raw/aws_inventory"):

        directory = Path(inventory_dir)

        identified = []

        if not directory.exists():

            return identified

        for file in directory.glob("*.json"):

            try:

                records = json.load(open(file))

            except Exception:

                continue

            if not isinstance(records, list):

                continue

            for record in records:

                if not isinstance(record, dict):

                    continue

                for field in ASSET_ID_FIELDS:

                    value = record.get(field)

                    if not value:

                        continue

                    entry = self.match(value, value)

                    if entry:

                        identified.append({

                            "resource": str(value),
                            "asset_type": file.stem,
                            "crown_jewel": entry.get("name"),
                            "criticality": entry.get("criticality"),

                        })

                        break

        output_file = self.output_directory / "identified_assets.json"

        with open(output_file, "w") as f:

            json.dump(identified, f, indent=4, default=str)

        return identified

    ###########################################################################
    # Tag Findings
    ###########################################################################

    def tag(self, finding):

        entry = self.match(finding.resource_id, finding.resource_name)

        if entry:

            finding.crown_jewel = "Yes"
            finding._crown_jewel_proximity = 0

            finding.business_unit = entry.get("business_unit", finding.business_unit)
            finding.environment = entry.get("environment", finding.environment)

            note = f"Crown Jewel match: {entry.get('name')} ({entry.get('criticality', 'UNKNOWN')})"

            if note not in finding.analyst_notes:

                finding.analyst_notes = (
                    f"{finding.analyst_notes} | {note}".strip(" |")
                )

        else:

            finding.crown_jewel = "No"

        return finding

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, findings):

        with open(self.output_directory / "crown_jewel_findings.json", "w") as f:

            json.dump(
                [f.to_dict(include_internal=True) for f in findings],
                f,
                indent=4,
                default=str,
            )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self, findings):

        console.rule(
            "[bold cyan]Crown Jewel Correlation"
        )

        for finding in findings:

            self.tag(finding)

        matched = sum(1 for f in findings if f.crown_jewel == "Yes")

        self.save(findings)

        logger.success(
            f"{matched}/{len(findings)} findings touch a Crown Jewel resource"
        )

        console.print(
            f"[green]Crown Jewel matches : {matched}/{len(findings)}[/green]"
        )

        return findings
