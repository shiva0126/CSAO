"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Environment Discovery Engine

Methodology step 1-2: Architecture Understanding / Asset Inventory.

Responsibilities
----------------
✔ Enumerate account(s), regions and services in scope via the CloudProvider
✔ Collect resource inventory (reuses modules/aws_inventory.py's read-only
  collectors instead of duplicating boto3 calls)
✔ Produce a single asset inventory summary that later engines (Attack Path,
  Crown Jewel, Risk) use as their "what exists / how is it connected" source

READ ONLY

===============================================================================
"""

import json
import datetime
from pathlib import Path

from rich.console import Console
from loguru import logger

from modules.aws_inventory import AWSInventory


console = Console()


class DiscoveryEngine:

    def __init__(self, config, provider):

        self.config = config

        self.provider = provider

        self.output_directory = Path("output/discovery")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.raw_inventory_directory = Path("output/raw/aws_inventory")

    ###########################################################################
    # Run resource collection
    ###########################################################################

    def collect_resources(self):

        if not self.config.get("modules", {}).get("aws_inventory"):

            console.print(
                "[yellow]Resource inventory collection disabled in config[/yellow]"
            )

            return False

        if not self.provider.available:

            console.print(
                "[yellow]Skipping resource inventory collection - "
                "provider unavailable[/yellow]"
            )

            return False

        if self.provider.platform_name != "aws":

            console.print(
                f"[yellow]No inventory collector implemented for "
                f"'{self.provider.platform_name}' yet[/yellow]"
            )

            return False

        inventory = AWSInventory(self.config, self.provider)

        inventory.run()

        return True

    ###########################################################################
    # Summarize what was collected into an asset inventory
    ###########################################################################

    def resource_counts(self):

        counts = {}

        if not self.raw_inventory_directory.exists():

            return counts

        for file in self.raw_inventory_directory.glob("*.json"):

            try:

                data = json.load(open(file))

            except Exception:

                continue

            counts[file.stem] = len(data) if isinstance(data, list) else 1

        return counts

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, summary):

        output_file = self.output_directory / "asset_inventory.json"

        with open(output_file, "w") as f:

            json.dump(summary, f, indent=4, default=str)

        logger.success(
            f"Discovery summary saved : {output_file}"
        )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self):

        console.rule(
            "[bold cyan]Environment Discovery / Asset Inventory"
        )

        collected = self.collect_resources()

        summary = {

            "platform": self.provider.platform_name,

            "account": self.provider.account_id() if self.provider.available else None,

            "regions": self.provider.regions() if self.provider.available else [],

            "resource_counts": self.resource_counts() if collected else {},

            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",

        }

        self.save(summary)

        console.print(
            f"[green]Discovered {sum(summary['resource_counts'].values())} "
            f"resources across {len(summary['regions'])} region(s)[/green]"
        )

        return summary
