"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

AWS Access Analyzer Runner v2.0

Security Model
--------------
READ ONLY

Purpose
-------
Detect externally accessible AWS resources using
AWS IAM Access Analyzer.

Features
--------
✓ Shared AWS Session Support
✓ Profile Support
✓ Multi Region Support
✓ Read Only APIs
✓ JSON Export
✓ Error Handling
✓ Enterprise Logging

===============================================================================
"""


import json
import time

from pathlib import Path
from botocore.exceptions import ClientError

from rich.console import Console
from loguru import logger

from core.base_module import BaseModule



console = Console()



class AccessAnalyzerRunner(BaseModule):


    name = "Access Analyzer"



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


        self.profile = (
            config["aws"].get(
                "profile",
                "default"
            )
        )


        self.regions = (
            config["aws"].get(
                "regions",
                []
            )
        )


        self.output_directory = (

            self.create_output_directory(
                "access_analyzer"
            )

        )


        logger.info(
            "Access Analyzer Runner Initialized"
        )



    ###########################################################################
    # Client
    ###########################################################################

    def get_client(self, region):


        if not self.aws_session or not self.aws_session.available:

            raise RuntimeError(
                "Access Analyzer requires a validated shared AWS session."
            )


        return self.aws_session.client(

            "accessanalyzer",

            region

        )



    ###########################################################################
    # Get Analyzer
    ###########################################################################

    def get_analyzers(
            self,
            client
    ):


        analyzers = []


        paginator = client.get_paginator(
            "list_analyzers"
        )


        for page in paginator.paginate():


            analyzers.extend(
                page.get(
                    "analyzers",
                    []
                )
            )


        return analyzers



    ###########################################################################
    # Collect Findings
    ###########################################################################

    def collect_findings(
            self,
            client,
            analyzer
    ):


        findings=[]


        paginator = client.get_paginator(
            "list_findings"
        )


        for page in paginator.paginate(

            analyzerArn=analyzer["arn"]

        ):


            findings.extend(

                page.get(
                    "findings",
                    []
                )

            )


        return findings



    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):


        all_findings=[]



        for region in self.regions:


            console.print(

                f"[cyan]Scanning Access Analyzer {region}[/cyan]"

            )


            try:


                client = self.get_client(
                    region
                )


                analyzers = self.get_analyzers(
                    client
                )


                for analyzer in analyzers:


                    findings = self.collect_findings(

                        client,

                        analyzer

                    )


                    all_findings.extend(
                        findings
                    )


            except ClientError as e:


                logger.warning(

                    f"{region}: {e}"

                )


            except Exception as e:


                logger.warning(

                    f"{region}: {e}"

                )



        output_file = (

            self.output_directory /

            "access_analyzer_findings.json"

        )



        with open(
            output_file,
            "w"
        ) as f:


            json.dump(

                all_findings,

                f,

                indent=4,

                default=str

            )



        logger.success(

            f"Saved {len(all_findings)} findings"

        )



    ###########################################################################
    # Run
    ###########################################################################

    def run(self):


        console.rule(

            "[bold cyan]AWS Access Analyzer"

        )


        start=time.time()


        try:


            self.execute()



            elapsed=round(

                time.time()-start,

                2

            )


            console.print(

                f"[green]Access Analyzer Completed ({elapsed}s)[/green]"

            )


        except Exception as e:


            logger.exception(e)


            console.print(

                f"[red]Access Analyzer Failed: {e}[/red]"

            )
