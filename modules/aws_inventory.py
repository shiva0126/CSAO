"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

AWS Inventory Collector v2.0

Purpose:
--------
Read-only AWS inventory collection.

Resources:
----------
EC2
VPC
Subnet
Security Groups
S3
IAM Users
IAM Roles
Lambda
RDS

Security:
---------
READ ONLY APIs ONLY
No create/update/delete actions
===============================================================================
"""


import json
from pathlib import Path

import boto3

from botocore.exceptions import ClientError

from loguru import logger
from rich.console import Console


console = Console()



class AWSInventory:


    name = "AWS Inventory"



    def __init__(
        self,
        config,
        aws_session=None
    ):


        self.config = config

        self.aws_session = aws_session


        self.profile = (
            config["aws"]["profile"]
        )


        self.regions = (
            config["aws"]["regions"]
        )


        self.output = Path(
            "output/raw/aws_inventory"
        )


        self.output.mkdir(
            parents=True,
            exist_ok=True
        )



        #
        # Enterprise AWS Session Handling
        #

        if not aws_session or not getattr(aws_session, "available", False):

            raise RuntimeError(
                "AWS Inventory requires a validated shared AWS session."
            )


        self.session = aws_session.session



        self.ec2 = self.session.client(
            "ec2",
            region_name=self.regions[0]
        )


        self.iam = self.session.client(
            "iam"
        )


        self.s3 = self.session.client(
            "s3"
        )



        console.print(
            "[green]AWS Inventory Session Ready"
        )



    ###################################################################
    # Save JSON
    ###################################################################


    def save(
        self,
        filename,
        data
    ):


        file = (
            self.output / filename
        )


        with open(
            file,
            "w"
        ) as f:


            json.dump(
                data,
                f,
                indent=4,
                default=str
            )


        logger.info(
            f"Saved {file}"
        )

    def _paginate(
        self,
        client,
        operation,
        result_key
    ):


        paginator = client.get_paginator(
            operation
        )


        result = []


        for page in paginator.paginate():


            result.extend(
                page.get(
                    result_key,
                    []
                )
            )


        return result



    ###################################################################
    # EC2
    ###################################################################


    def collect_ec2(self):


        console.print(
            "[cyan]Collecting EC2..."
        )


        result=[]


        for region in self.regions:


            try:


                client = self.session.client(
                    "ec2",
                    region_name=region
                )


                for reservation in self._paginate(
                    client,
                    "describe_instances",
                    "Reservations"
                ):


                    result.extend(
                        reservation.get(
                            "Instances",
                            []
                        )
                    )


            except ClientError as e:


                logger.warning(
                    f"EC2 {region}: {e}"
                )


        self.save(
            "ec2.json",
            result
        )



    ###################################################################
    # VPC
    ###################################################################


    def collect_vpc(self):


        console.print(
            "[cyan]Collecting VPC..."
        )


        result=[]


        for region in self.regions:


            try:


                client=self.session.client(
                    "ec2",
                    region_name=region
                )


                result.extend(
                    self._paginate(
                        client,
                        "describe_vpcs",
                        "Vpcs"
                    )
                )


            except ClientError as e:


                logger.warning(
                    str(e)
                )


        self.save(
            "vpc.json",
            result
        )



    ###################################################################
    # Security Groups
    ###################################################################


    def collect_security_groups(self):


        console.print(
            "[cyan]Collecting Security Groups..."
        )


        result=[]


        for region in self.regions:


            try:


                client=self.session.client(
                    "ec2",
                    region_name=region
                )


                result.extend(
                    self._paginate(
                        client,
                        "describe_security_groups",
                        "SecurityGroups"
                    )
                )


            except ClientError as e:


                logger.warning(
                    str(e)
                )


        self.save(
            "security_groups.json",
            result
        )



    ###################################################################
    # S3
    ###################################################################


    def collect_s3(self):


        console.print(
            "[cyan]Collecting S3..."
        )


        try:


            response=self.s3.list_buckets()


            self.save(
                "s3.json",
                response.get(
                    "Buckets",
                    []
                )
            )


        except ClientError as e:


            logger.warning(
                str(e)
            )



    ###################################################################
    # IAM Users
    ###################################################################


    def collect_iam_users(self):


        console.print(
            "[cyan]Collecting IAM Users..."
        )


        try:


            self.save(
                "iam_users.json",
                self._paginate(
                    self.iam,
                    "list_users",
                    "Users"
                )
            )


        except ClientError as e:


            logger.warning(
                str(e)
            )



    ###################################################################
    # IAM Roles
    ###################################################################


    def collect_roles(self):


        console.print(
            "[cyan]Collecting IAM Roles..."
        )


        try:


            self.save(
                "iam_roles.json",
                self._paginate(
                    self.iam,
                    "list_roles",
                    "Roles"
                )
            )


        except ClientError as e:


            logger.warning(
                str(e)
            )



    ###################################################################
    # Lambda
    ###################################################################


    def collect_lambda(self):


        console.print(
            "[cyan]Collecting Lambda..."
        )


        result=[]


        for region in self.regions:


            try:


                client=self.session.client(
                    "lambda",
                    region_name=region
                )


                result.extend(
                    self._paginate(
                        client,
                        "list_functions",
                        "Functions"
                    )
                )


            except ClientError as e:


                logger.warning(
                    str(e)
                )


        self.save(
            "lambda.json",
            result
        )



    ###################################################################
    # RDS
    ###################################################################


    def collect_rds(self):


        console.print(
            "[cyan]Collecting RDS..."
        )


        result=[]


        for region in self.regions:


            try:


                client=self.session.client(
                    "rds",
                    region_name=region
                )


                result.extend(
                    self._paginate(
                        client,
                        "describe_db_instances",
                        "DBInstances"
                    )
                )


            except ClientError as e:


                logger.warning(
                    str(e)
                )


        self.save(
            "rds.json",
            result
        )



    ###################################################################
    # Run
    ###################################################################


    def run(self):


        console.rule(
            "[bold cyan]AWS Inventory"
        )


        self.collect_ec2()

        self.collect_vpc()

        self.collect_security_groups()

        self.collect_s3()

        self.collect_iam_users()

        self.collect_roles()

        self.collect_lambda()

        self.collect_rds()


        console.print(
            "[bold green]AWS Inventory Completed"
        )
