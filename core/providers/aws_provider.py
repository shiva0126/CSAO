"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

AWS Provider

Responsibilities:

✔ AWS credential validation
✔ boto3 session creation
✔ Account discovery
✔ Region discovery
✔ Shared AWS clients
✔ Credential state management

Security Model
--------------
READ ONLY. Only STS get-caller-identity is called here; every other AWS API
call made anywhere in the framework must be a read/describe/list/get call.

===============================================================================
"""

import datetime as dt
import boto3

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)

from rich.console import Console

from core.providers.base import CloudProvider


console = Console()


class AWSProvider(CloudProvider):

    platform_name = "aws"

    def __init__(self, config):

        super().__init__(config)

        self.profile = (
            config
            .get("aws", {})
            .get("profile", "default")
        )

        self.region_list = (
            config
            .get("aws", {})
            .get("regions", [])
        )
        self.auth_type = (
            config
            .get("aws", {})
            .get("auth_type", "profile")
        )
        self.credentials = dict(
            config
            .get("aws", {})
            .get("credentials", {})
            or {}
        )

        self.session = None
        self.account = None
        self.identity = None
        self.session_expiration = None

    ###################################################################
    # Authenticate
    ###################################################################

    def authenticate(self):

        console.print(
            "[cyan]Initializing AWS Session...[/cyan]"
        )

        try:
            self.session, self.session_expiration = self._build_session()

            sts = self.session.client("sts")

            self.identity = sts.get_caller_identity()

            self.account = self.identity["Account"]

            self.available = True

            console.print(
                "[green]AWS Authentication Successful[/green]"
            )

            console.print(
                f"Account : {self.account}"
            )

            return True

        except ProfileNotFound:

            console.print(
                "[red]AWS Profile Not Found[/red]"
            )

        except NoCredentialsError:

            console.print(
                "[red]AWS Credentials Missing[/red]"
            )

        except ClientError as e:

            console.print(
                f"[red]AWS Authentication Failed: {e}[/red]"
            )

        except BotoCoreError as e:

            console.print(
                f"[red]AWS Authentication Failed: {e}[/red]"
            )

        return False

    def _build_session(self):
        auth_type = str(self.auth_type or "profile").lower()
        credentials = self.credentials
        if auth_type in {"profile", "sso"}:
            return boto3.Session(profile_name=credentials.get("profile") or self.profile), None
        if auth_type == "access_keys":
            return (
                boto3.Session(
                    aws_access_key_id=credentials.get("access_key_id"),
                    aws_secret_access_key=credentials.get("secret_access_key"),
                    aws_session_token=credentials.get("session_token") or None,
                ),
                None,
            )
        if auth_type == "assume_role":
            source_profile = credentials.get("source_profile") or credentials.get("profile") or self.profile
            base_session = boto3.Session(profile_name=source_profile or None)
            sts = base_session.client("sts")
            response = sts.assume_role(
                RoleArn=credentials.get("role_arn"),
                RoleSessionName="csao-provider-session",
                **(
                    {"ExternalId": credentials.get("external_id")}
                    if credentials.get("external_id")
                    else {}
                ),
            )
            assumed = response["Credentials"]
            expiration = assumed.get("Expiration")
            if isinstance(expiration, dt.datetime):
                expiration = expiration.astimezone(dt.UTC)
            return (
                boto3.Session(
                    aws_access_key_id=assumed["AccessKeyId"],
                    aws_secret_access_key=assumed["SecretAccessKey"],
                    aws_session_token=assumed["SessionToken"],
                ),
                expiration,
            )
        raise ValueError(f"Unsupported AWS auth type: {auth_type}")

    ###################################################################
    # Identity
    ###################################################################

    def account_id(self):

        return self.account

    def regions(self):

        return self.region_list

    ###################################################################
    # Client Factory
    ###################################################################

    def client(self, service, region=None):

        if not self.available:

            raise Exception(
                "AWS Session unavailable"
            )

        return self.session.client(
            service,
            region_name=region
        )

    def exported_credentials(self):
        if not self.session:
            raise RuntimeError("AWS Session unavailable")
        credentials = self.session.get_credentials()
        if credentials is None:
            raise RuntimeError("AWS credentials unavailable")
        frozen = credentials.get_frozen_credentials()
        return {
            "AWS_ACCESS_KEY_ID": frozen.access_key,
            "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
            "AWS_SESSION_TOKEN": frozen.token or "",
        }

    ###################################################################
    # Backward-compatible status snapshot
    # (matches the shape modules/main.py historically expected)
    ###################################################################

    def status(self):

        return {
            "available": self.available,
            "account": self.account,
            "profile": self.profile,
            "regions": self.region_list,
        }
