#!/usr/bin/env python3

"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Main Enterprise Orchestrator

Version : 2.0.0

Drives the fixed assessment methodology end to end. Tools are evidence
providers only - every correlation, validation, mapping and prioritization
decision happens inside the framework's own engines, over one canonical
Finding schema.

The 14-stage engine sequence itself lives in core/orchestrator.py, shared
with the web control plane's background runner (workbench/control_plane.py)
so the two entry points can no longer drift out of sync with each other.

Security Model
--------------
READ ONLY. The client provides Super Administrator READ-ONLY access; no
module in this framework ever calls a create/update/delete API.

===============================================================================
"""

import json
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_loader import load_config
from core.dependency_checker import DependencyChecker
from core.logger import setup_logger
from core.providers.registry import get_provider
from core.orchestrator import STAGES, run_pipeline


console = Console()


class CloudSecurityOrchestrator:

    ###########################################################################
    # Initialize
    ###########################################################################

    def __init__(self):
        self.start_time = time.time()
        self.assessment_id = time.strftime("ASSESS-%Y%m%d-%H%M%S", time.gmtime())

        self.config = load_config()
        self.logger = setup_logger()

        self.provider = get_provider(self.config)
        self.provider_available = False
        self.result = None

        self.initialize()

    def initialize(self):
        console.print(
            "\n[cyan]Initializing Cloud Security Assessment Orchestrator...[/cyan]"
        )
        self.provider_available = self.provider.authenticate()
        self.create_session_file()

    ###########################################################################
    # Banner
    ###########################################################################

    def banner(self):
        console.print(
            Panel.fit(
"""
Cloud Security Assessment Orchestrator (CSAO)

Version : 2.0.0


Assessment Methodology

1. Architecture Understanding
2. Asset Inventory
3. Crown Jewel Identification
4. Evidence Collection
5. Checklist Validation
6. MITRE ATT&CK Mapping
7. Threat Correlation
8. Attack Path Identification
9. Risk Prioritization
10. Reporting

Evidence Providers : Prowler, Steampipe, Cloudsplaining,
IAM Access Analyzer, AWS Config Aggregator, Cartography,
Tenable Cloud Security (optional)

Platform : """ + self.provider.platform_name.upper() + """  (READ ONLY)

""",
                title="CSAO",
                border_style="cyan",
            )
        )

    ###########################################################################
    # Dependency Validation
    ###########################################################################

    def check_dependencies(self):
        console.print("\n[cyan]Checking Dependencies...[/cyan]")
        checker = DependencyChecker(self.config)
        return checker.run()

    ###########################################################################
    # Session Snapshot
    ###########################################################################

    def create_session_file(self):
        data = {
            "framework": "CSAO",
            "version": "2.0.0",
            "assessment_id": self.assessment_id,
            "platform": self.provider.platform_name,
            "provider": self.provider.status(),
            "modules": {},
        }
        with open("output/session.json", "w") as f:
            json.dump(data, f, indent=4, default=str)

    ###########################################################################
    # Architecture Understanding
    ###########################################################################

    def architecture_understanding(self):
        console.rule("[bold cyan]Step 1 : Architecture Understanding")
        if self.provider_available:
            console.print(
                f"[green]{self.provider.platform_name.upper()} account "
                f"{self.provider.account_id()} authenticated - "
                f"{len(self.provider.regions())} region(s) in scope[/green]"
            )
        else:
            console.print(
                f"[yellow]{self.provider.platform_name.upper()} unavailable - "
                f"subsequent steps will run in degraded mode[/yellow]"
            )

    ###########################################################################
    # Console progress adapter for the shared pipeline
    ###########################################################################

    def _console_stage_hook(
        self,
        stage_key: str,
        status: str,
        current_collector: str = "",
        current_api: str = "",
        resources_processed=None,
    ) -> None:
        label = next((name for key, name in STAGES if key == stage_key), stage_key)
        if status == "RUNNING":
            console.rule(f"[bold cyan]{label}")
            if current_api:
                console.print(f"[cyan]{current_api}[/cyan]")
        elif status == "COMPLETED":
            detail = f" ({resources_processed} processed)" if resources_processed is not None else ""
            console.print(f"[green]{label} completed{detail}[/green]")
        elif status == "FAILED":
            console.print(f"[red]{label} failed[/red]")

    ###########################################################################
    # Finish
    ###########################################################################

    def finish(self):
        elapsed = round(time.time() - self.start_time, 2)
        result = self.result

        table = Table(title="Evidence Collection Summary")
        table.add_column("Module")
        table.add_column("Status")
        for k, v in result.execution_status.items():
            table.add_row(k, v)
        console.print(table)

        posture = result.risk_summary.get("security_posture_score", "N/A")
        console.print(
            Panel.fit(
f"""
Assessment Completed

Security Posture Score : {posture}/100

Findings                : {len(result.findings)}
Attack Path Candidates  : {len(result.attack_path_candidates)}

Execution Time : {elapsed} seconds

Reports : output/reports/
Logs    : logs/
""",
                title="Completed",
                border_style="green",
            )
        )

    ###########################################################################
    # Run Framework
    ###########################################################################

    def run(self):
        self.banner()
        self.check_dependencies()
        self.architecture_understanding()

        self.result = run_pipeline(
            self.config,
            self.assessment_id,
            stage_hook=self._console_stage_hook,
        )

        self.finish()


def main():
    orchestrator = CloudSecurityOrchestrator()
    orchestrator.run()


if __name__ == "__main__":
    main()
