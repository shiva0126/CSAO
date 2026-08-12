"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Evidence Collection Engine

Methodology step 4: Evidence Collection.

Responsibilities
----------------
✔ Run every enabled evidence-provider tool (Prowler, Steampipe,
  Cloudsplaining, Access Analyzer, AWS Config Aggregator, Cartography,
  Tenable Cloud Security - optional)
✔ Preserve raw evidence exactly as each tool wrote it (JSON/CSV/HTML) under
  output/raw/<tool>/
✔ Build an evidence index so every normalized Finding can point back to the
  exact file it came from (Finding.evidence_location)

Tools here are pure evidence providers - none of them produce an independent
report; that happens later, in the Reporting Engine, from normalized
Findings only.

READ ONLY

===============================================================================
"""

import json
import datetime
from pathlib import Path

from rich.console import Console
from loguru import logger

from modules.prowler_runner import ProwlerRunner
from modules.cloudsplaining_runner import CloudsplainingRunner
from modules.steampipe_runner import SteampipeRunner
from modules.access_analyzer import AccessAnalyzerRunner
from modules.config_aggregator import ConfigAggregatorRunner
from modules.cartography_runner import CartographyRunner
from modules.tenable_runner import TenableRunner


console = Console()


# Registry of evidence providers keyed by the config.yaml `modules:` flag
# that enables them. Order matters only for console readability - each
# provider is independent.
EVIDENCE_PROVIDERS = {

    "prowler": ProwlerRunner,

    "cloudsplaining": CloudsplainingRunner,

    "steampipe": SteampipeRunner,

    "access_analyzer": AccessAnalyzerRunner,

    "config_aggregator": ConfigAggregatorRunner,

    "cartography": CartographyRunner,

    "tenable": TenableRunner,

}


class EvidenceCollectionEngine:

    def __init__(self, config, provider):

        self.config = config

        self.provider = provider

        self.modules = []

        self.execution_status = {}

        self.raw_directory = Path("output/raw")

        self.load_modules()

    ###########################################################################
    # Module Registration
    ###########################################################################

    def load_modules(self):

        enabled = self.config.get("modules", {})

        for key, module_class in EVIDENCE_PROVIDERS.items():

            if not enabled.get(key):

                continue

            try:

                self.modules.append(
                    module_class(self.config, self.provider)
                )

            except Exception as e:

                logger.warning(
                    f"Could not register evidence provider '{key}': {e}"
                )

    ###########################################################################
    # Execute Modules
    ###########################################################################

    def collect(self):

        console.rule(
            "[bold cyan]Evidence Collection"
        )

        for module in self.modules:

            name = module.name

            if not self.provider.available:

                console.print(
                    f"[yellow]Skipping {name} - "
                    f"{self.provider.platform_name.upper()} unavailable[/yellow]"
                )

                self.execution_status[name] = "SKIPPED"

                continue

            try:

                console.print(
                    f"[green]Running {name}[/green]"
                )

                module.run()

                console.print(
                    f"[bold green]{name} Completed[/bold green]\n"
                )

                self.execution_status[name] = "SUCCESS"

            except Exception as e:

                logger.exception(e)

                console.print(
                    f"[red]{name} Failed[/red]"
                )

                self.execution_status[name] = "FAILED"

        self.build_evidence_index()

        return self.execution_status

    ###########################################################################
    # Evidence Index
    #
    # Maps tool -> raw evidence files collected, so the Normalization
    # Engine can stamp Finding.evidence_location with a concrete path
    # instead of a tool name.
    ###########################################################################

    def build_evidence_index(self):

        index = {}

        if self.raw_directory.exists():

            for tool_dir in sorted(self.raw_directory.iterdir()):

                if not tool_dir.is_dir():

                    continue

                files = [
                    str(f) for f in sorted(tool_dir.rglob("*"))
                    if f.is_file()
                ]

                index[tool_dir.name] = files

        output_file = Path("output/evidence_index.json")

        with open(output_file, "w") as f:

            json.dump(
                {
                    "generated": datetime.datetime.utcnow().isoformat() + "Z",
                    "evidence": index,
                },
                f,
                indent=4,
            )

        logger.success(
            f"Evidence index saved : {output_file}"
        )

        return index

    ###########################################################################
    # Run
    ###########################################################################

    def run(self):

        return self.collect()
