"""
===============================================================================
Cloud Security Assessment Framework (CSAO)

Tenable Cloud Security Runner (Optional)

Purpose
-------
Optional evidence provider. Pulls exposure/misconfiguration findings from
Tenable Cloud Security when the client has it deployed. Disabled by default
(`modules.tenable: false` in config.yaml) - most engagements will not have
Tenable credentials available.

Security Model
--------------
READ ONLY. Only calls Tenable's read/list APIs.

Credentials
-----------
Expected via environment variables (never hardcoded / committed):
  TENABLE_ACCESS_KEY
  TENABLE_SECRET_KEY

If the `pyTenable` package isn't installed, or credentials aren't present,
this module skips cleanly (matches SteampipeRunner's "not installed" skip
pattern) rather than failing the whole assessment run.
===============================================================================
"""

import os
import time

from rich.console import Console
from loguru import logger

from core.base_module import BaseModule


console = Console()


class TenableRunner(BaseModule):

    name = "Tenable Cloud Security"

    def __init__(self, config, aws_session=None):

        super().__init__(config)

        self.aws_session = aws_session

        self.output_directory = self.create_output_directory(
            "tenable"
        )

        self.access_key = os.getenv("TENABLE_ACCESS_KEY")
        self.secret_key = os.getenv("TENABLE_SECRET_KEY")

    ###########################################################################
    # Availability Check
    ###########################################################################

    def installed(self):

        try:

            import tenable  # noqa: F401

            return True

        except ImportError:

            return False

    def configured(self):

        return bool(self.access_key and self.secret_key)

    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):

        if not self.installed():

            console.print(
                "[yellow]pyTenable not installed - skipping "
                "Tenable Cloud Security[/yellow]"
            )

            return

        if not self.configured():

            console.print(
                "[yellow]TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY not set - "
                "skipping Tenable Cloud Security[/yellow]"
            )

            return

        from tenable.io import TenableIO

        client = TenableIO(
            self.access_key,
            self.secret_key,
        )

        findings = list(
            client.exports.assets()
        )

        self.save_json(
            "tenable_assets.json",
            findings,
        )

        logger.success(
            f"Saved {len(findings)} Tenable Cloud Security assets"
        )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self):

        console.rule(
            "[bold cyan]Tenable Cloud Security"
        )

        if not self.installed() or not self.configured():

            self.execute()

            return

        start = time.time()

        try:

            self.execute()

            elapsed = round(time.time() - start, 2)

            console.print(
                f"[green]Tenable Cloud Security Completed ({elapsed}s)[/green]"
            )

        except Exception as e:

            logger.exception(e)

            console.print(
                f"[red]Tenable Cloud Security Failed: {e}[/red]"
            )

            raise
