"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Cloudsplaining Runner v2.0

Purpose:
--------
IAM privilege risk analysis using Cloudsplaining.

Security:
---------
READ ONLY AWS APIs ONLY

Workflow:

AWS IAM
   |
   |
Export Authorization Details
   |
   |
Cloudsplaining Analysis
   |
   |
HTML / JSON Report

===============================================================================
"""

import shutil


from rich.console import Console
from loguru import logger


from core.base_module import BaseModule


console = Console()



class CloudsplainingRunner(BaseModule):


    name = "Cloudsplaining"



    def __init__(
        self,
        config,
        aws_session=None
    ):


        super().__init__(
            config
        )


        self.config = config


        self.aws_session = aws_session



        self.profile = (
            config["aws"]["profile"]
        )



        self.output_directory = (
            self.create_output_directory(
                "cloudsplaining"
            )
        )



        self.authorization_file = (
            self.output_directory /
            "authorization-details.json"
        )



        self.report_directory = (
            self.output_directory /
            "report"
        )



        self.report_directory.mkdir(
            exist_ok=True
        )



        console.print(
            "[green]Cloudsplaining Session Ready"
        )



    ###########################################################################
    # Installation Check
    ###########################################################################


    def installed(self):


        return (
            shutil.which(
                "cloudsplaining"
            )
            is not None
        )



    ###########################################################################
    # AWS Credential Validation
    ###########################################################################


    def validate_session(self):


        if not self.aws_session or not self.aws_session.available:


            console.print(
                "[yellow]AWS authentication unavailable"
            )


            return False



        return True




    ###########################################################################
    # Export IAM Authorization Details
    ###########################################################################


    def export_authorization_details(self):


        console.print(
            "[cyan]Exporting IAM Authorization Details..."
        )


        command = [


            "aws",

            "iam",

            "get-account-authorization-details",


            "--output",

            "json"


        ]



        try:


            output = self.execute_command(
                command
            )


            self.authorization_file.write_text(
                output,
                encoding="utf-8"
            )



            logger.info(
                "IAM authorization details exported"
            )



            return True



        except Exception as e:



            logger.error(
                str(e)
            )


            return False




    ###########################################################################
    # Run Cloudsplaining
    ###########################################################################


    def execute_scan(self):


        console.print(
            "[cyan]Running Cloudsplaining Analysis..."
        )



        command = [


            "cloudsplaining",


            "scan",


            "--input-file",


            str(
                self.authorization_file
            ),


            "--output",


            str(
                self.report_directory
            )

        ]



        try:


            self.execute_command(
                command
            )



            logger.success(
                "Cloudsplaining scan completed"
            )


            return True



        except Exception as e:


            logger.error(
                e
            )


            return False




    ###########################################################################
    # Execute Module
    ###########################################################################


    def execute(self):


        if not self.installed():


            raise RuntimeError(
                "Cloudsplaining is not installed"
            )



        if not self.validate_session():


            console.print(
                "[yellow]Skipping Cloudsplaining - AWS unavailable"
            )


            return



        exported = (
            self.export_authorization_details()
        )



        if not exported:


            console.print(
                "[yellow]Unable to export IAM details"
            )


            return



        self.execute_scan()
