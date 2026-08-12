"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Steampipe Runner v2.0

Purpose
-------
Enterprise wrapper for Steampipe AWS security queries.

Security Model
--------------
READ ONLY

No AWS resource modification.

Features
--------
✓ Shared AWS Session Support
✓ Automatic Query Discovery
✓ Recursive SQL Discovery
✓ JSON Output
✓ Error Handling
✓ Execution Timer
✓ Enterprise Output Structure
✓ Compatible with CSAF Main Engine

===============================================================================
"""


import shutil
import time

from pathlib import Path

from rich.console import Console
from loguru import logger

from core.base_module import BaseModule


console = Console()



class SteampipeRunner(BaseModule):


    name = "Steampipe"



    ###########################################################################
    # Initialize
    ###########################################################################

    def __init__(
            self,
            config,
            aws_session=None
    ):


        super().__init__(config)


        self.config = config


        self.aws_session = aws_session
        if not self.aws_session or not getattr(self.aws_session, "available", False):
            raise RuntimeError(
                "Steampipe requires a validated shared AWS session."
            )



        self.query_directory = Path(
            "queries"
        )



        self.output_directory = (
            self.create_output_directory(
                "steampipe"
            )
        )



        logger.info(
            "Steampipe Runner Initialized"
        )



    ###########################################################################
    # Installation Check
    ###########################################################################

    def installed(self):

        return shutil.which(
            "steampipe"
        ) is not None



    ###########################################################################
    # Version Check
    ###########################################################################

    def version(self):

        try:

            result = subprocess.run(

                [
                    "steampipe",
                    "--version"
                ],

                capture_output=True,

                text=True

            )


            console.print(
                result.stdout.strip()
            )


        except Exception as e:

            logger.warning(
                f"Steampipe version check failed: {e}"
            )



    ###########################################################################
    # Query Discovery
    ###########################################################################

    def discover_queries(self):


        if not self.query_directory.exists():

            logger.warning(
                "Queries directory not found"
            )

            return []



        queries = sorted(

            self.query_directory.rglob(
                "*.sql"
            )

        )


        return queries



    ###########################################################################
    # Execute Query
    ###########################################################################

    def execute_query(
            self,
            query_file
    ):


        relative = (
            query_file.relative_to(
                self.query_directory
            )
        )


        output_file = (

            self.output_directory /

            relative.with_suffix(
                ".json"
            )

        )


        output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )



        command = [

            "steampipe",

            "query",

            str(query_file),

            "--output",

            "json"

        ]



        logger.info(
            f"Executing query {query_file}"
        )



        output = self.execute_command(
            command
        )


        output_file.write_text(
            output,
            encoding="utf-8"
        )



        logger.success(
            f"Completed {query_file.name}"
        )



    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):


        if not self.installed():

            raise RuntimeError(
                "Steampipe is not installed"
            )



        queries = self.discover_queries()



        if not queries:

            logger.warning(
                "No SQL queries found. Skipping Steampipe."
            )

            return



        for query in queries:

            self.execute_query(
                query
            )



    ###########################################################################
    # Run
    ###########################################################################

    def run(self):


        console.rule(
            "[bold cyan]Steampipe Assessment"
        )



        if not self.installed():

            console.print(
                "[yellow]Steampipe not installed[/yellow]"
            )

            return



        self.version()



        start = time.time()



        try:


            self.execute()



            elapsed = round(

                time.time()-start,

                2

            )


            console.print(

                f"[green]Steampipe Completed ({elapsed}s)[/green]"

            )



        except Exception as e:


            logger.exception(e)


            console.print(

                f"[red]Steampipe Failed: {e}[/red]"

            )

            raise
