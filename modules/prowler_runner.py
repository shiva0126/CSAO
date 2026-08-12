"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Prowler Runner v2.0

Purpose
-------
Enterprise wrapper for Prowler AWS security assessment.

Security Model
--------------
READ ONLY

No AWS resource modification.

Features
--------
✓ Shared AWS Session Integration
✓ Version Detection
✓ JSON Output
✓ CSV Output
✓ HTML Output
✓ Execution Logging
✓ Error Handling
✓ Execution Timer
✓ Enterprise Output Structure

===============================================================================
"""


import subprocess
import shutil
import time

from pathlib import Path

from core.base_module import BaseModule
from rich.console import Console
from loguru import logger


console = Console()



class ProwlerRunner(BaseModule):


    name = "Prowler"



    ###########################################################################
    # Initialize
    ###########################################################################

    def __init__(self, config, aws_session=None):
        super().__init__(config)


        self.config = config


        self.aws_session = aws_session


        if self.aws_session is None or not getattr(self.aws_session, "available", False):

            raise Exception(
                "AWS Session unavailable for Prowler"
            )



        self.output = Path(
            "output/raw/prowler"
        )


        self.output.mkdir(
            parents=True,
            exist_ok=True
        )


        self.profile = (
            config["aws"].get(
                "profile",
                "default"
            )
        )



    ###########################################################################
    # Installation Check
    ###########################################################################

    def check_installation(self):

        path = shutil.which(
            "prowler"
        )


        if path:

            return True


        return False



    ###########################################################################
    # Version
    ###########################################################################

    def version(self):

        try:

            result = subprocess.run(

                [
                    "prowler",
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
                f"Prowler version check failed: {e}"
            )



    ###########################################################################
    # Build Command
    ###########################################################################

    def build_command(self):


        command = [

            "prowler",

            "aws",


            "--output-modes",

            "json-ocsf",

            "csv",

            "html",


            "--output-directory",

            str(self.output)

        ]


        return command



    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):


        command = self.build_command()


        logger.info(
            "Executing Prowler Assessment"
        )


        console.print(
            "[cyan]Running Prowler AWS Security Scan..."
        )


        self.execute_command(
            command
        )



    ###########################################################################
    # Run
    ###########################################################################

    def run(self):


        console.rule(
            "[bold cyan]Prowler Assessment"
        )



        if not self.check_installation():


            raise Exception(
                "Prowler is not installed"
            )



        self.version()



        start=time.time()



        try:


            self.execute()



            elapsed = round(
                time.time()-start,
                2
            )


            logger.success(
                f"Prowler completed in {elapsed}s"
            )



            console.print(

                f"[bold green]Prowler Completed ({elapsed}s)"

            )



        except subprocess.CalledProcessError as e:


            logger.error(
                f"Prowler execution failed: {e}"
            )


            console.print(
                f"[red]Prowler Failed: {e}"
            )


            raise
