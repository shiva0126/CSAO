"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Cartography Runner

Author : D Praveen

Description
-----------
Runs Cartography to build an AWS attack graph in Neo4j.

Features
--------
✓ Neo4j Connection Validation
✓ AWS Sync
✓ Output Logging
✓ Execution Summary
===============================================================================
"""

import shutil

from core.base_module import BaseModule


class CartographyRunner(BaseModule):

    name = "Cartography"

    def __init__(self, config, aws_session=None):

        super().__init__(config)

        self.aws_session = aws_session

        self.output_directory = self.create_output_directory(
            "cartography"
        )

        self.neo4j_uri = config["cartography"]["neo4j_uri"]

        self.neo4j_user = config["cartography"]["username"]

        self.neo4j_password = config["cartography"]["password"]

    ###########################################################################
    # Installation Check
    ###########################################################################

    def installed(self):

        return shutil.which("cartography") is not None

    ###########################################################################
    # Execute Cartography
    ###########################################################################

    def sync(self):

        if not self.aws_session or not getattr(self.aws_session, "available", False):

            raise RuntimeError(
                "Cartography requires a validated shared AWS session."
            )

        command = [

            "cartography",

            "--neo4j-uri",

            self.neo4j_uri,

            "--neo4j-user",

            self.neo4j_user,

            "--neo4j-password",

            self.neo4j_password,

            "--update"

        ]

        self.execute_command(command)

    ###########################################################################
    # Export Metadata
    ###########################################################################

    def summary(self):

        summary = {

            "tool": "Cartography",

            "status": "Completed"

        }

        self.save_json(
            "summary.json",
            summary
        )

    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):

        if not self.installed():

            raise RuntimeError(
                "Cartography is not installed."
            )

        self.sync()

        self.summary()
