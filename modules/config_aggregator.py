"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

AWS Config Aggregator Module

Author : D Praveen
Version : 1.0

Description
-----------
Collect AWS Config Aggregator data including compliance status,
resource inventory, conformance packs, and configuration history.

Features
--------
✓ Discover Aggregators
✓ Resource Inventory
✓ Compliance Status
✓ Config Rules
✓ Conformance Packs
✓ Output JSON
===============================================================================
"""

import json
from pathlib import Path

from botocore.exceptions import ClientError

from core.base_module import BaseModule


class ConfigAggregatorRunner(BaseModule):

    name = "AWS Config Aggregator"

    def __init__(self, config, aws_session=None):

        super().__init__(config)

        self.profile = config["aws"]["profile"]

        self.region = config["aws"]["regions"][0]

        self.output_directory = self.create_output_directory(
            "config_aggregator"
        )

        if not aws_session or not aws_session.available:

            raise RuntimeError(
                "AWS Config Aggregator requires a validated shared AWS session."
            )

        session = aws_session.session

        self.client = session.client(
            "config",
            region_name=self.region
        )

    ###########################################################################
    # Save JSON
    ###########################################################################

    def save(self, filename, data):

        self.save_json(filename, data)

    ###########################################################################
    # Discover Aggregators
    ###########################################################################

    def discover_aggregators(self):

        aggregators = []

        paginator = self.client.get_paginator(
            "describe_configuration_aggregators"
        )

        for page in paginator.paginate():

            aggregators.extend(
                page.get(
                    "ConfigurationAggregators",
                    []
                )
            )

        self.save("aggregators.json", aggregators)

        return aggregators

    ###########################################################################
    # Compliance Summary
    ###########################################################################

    def compliance_summary(self):

        rows = []

        paginator = self.client.get_paginator(
            "describe_compliance_by_config_rule"
        )

        for page in paginator.paginate():

            rows.extend(
                page.get("ComplianceByConfigRules", [])
            )

        self.save(
            "config_rule_compliance.json",
            rows
        )

    ###########################################################################
    # Config Rules
    ###########################################################################

    def config_rules(self):

        rows = []

        paginator = self.client.get_paginator(
            "describe_config_rules"
        )

        for page in paginator.paginate():

            rows.extend(
                page.get("ConfigRules", [])
            )

        self.save(
            "config_rules.json",
            rows
        )

    ###########################################################################
    # Conformance Packs
    ###########################################################################

    def conformance_packs(self):

        rows = []

        paginator = self.client.get_paginator(
            "describe_conformance_packs"
        )

        for page in paginator.paginate():

            rows.extend(
                page.get("ConformancePackDetails", [])
            )

        self.save(
            "conformance_packs.json",
            rows
        )

    ###########################################################################
    # Aggregated Resource Inventory
    ###########################################################################

    def aggregated_resources(self, aggregator_name):

        paginator = self.client.get_paginator(
            "list_aggregate_discovered_resources"
        )

        resources = []

        for page in paginator.paginate(
            ConfigurationAggregatorName=aggregator_name,
            ResourceType="AWS::EC2::Instance"
        ):

            resources.extend(
                page.get("ResourceIdentifiers", [])
            )

        self.save("ec2_inventory.json", resources)

    ###########################################################################
    # Execute
    ###########################################################################

    def execute(self):

        aggregators = self.discover_aggregators()

        self.compliance_summary()

        self.config_rules()

        self.conformance_packs()

        if aggregators:

            self.aggregated_resources(
                aggregators[0]["ConfigurationAggregatorName"]
            )
