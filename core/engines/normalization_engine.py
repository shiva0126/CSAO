"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Normalization Engine

Methodology step: Evidence Collection -> Normalization.

Purpose
-------
Converts raw evidence from every tool into the single canonical Finding
schema (core/schema/finding.py). This is the only place in the framework
that knows each tool's raw output shape - every engine after this one only
ever touches Finding objects.

Assumption note
----------------
Field-name assumptions for Prowler OCSF / Cloudsplaining / Steampipe /
Access Analyzer / Config Aggregator raw output are marked below. This
sandbox has no live AWS credentials, so exact upstream field names are
best-effort based on each tool's documented output format; adjust the
`.get(...)` chains here once real evidence is available without touching
any other engine.

READ ONLY

===============================================================================
"""

import json
import datetime
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.schema.finding import Finding


console = Console()


COMMON_RESOURCE_ID_COLUMNS = (
    "arn",
    "resource",
    "resource_id",
    "instance_id",
    "bucket_name",
    "role_name",
    "user_name",
    "policy_name",
    "db_instance_identifier",
    "function_name",
    "group_id",
    "vpc_id",
    "trail_name",
    "detector_id",
)

PUBLIC_KEYWORDS = ("public", "open", "0.0.0.0/0", "internet", "external")


class NormalizationEngine:

    def __init__(self):

        self.output_directory = Path("output/normalized")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.findings = []

        self.evidence_index = self.load_evidence_index()

    ###########################################################################
    # Evidence Index
    ###########################################################################

    def load_evidence_index(self):

        index_file = Path("output/evidence_index.json")

        if not index_file.exists():

            return {}

        try:

            return json.load(open(index_file)).get("evidence", {})

        except Exception:

            return {}

    ###########################################################################
    # Helpers
    ###########################################################################

    def now(self):

        return datetime.datetime.utcnow().isoformat() + "Z"

    def extract_resource_id(self, row):

        if not isinstance(row, dict):

            return "Unknown"

        for column in COMMON_RESOURCE_ID_COLUMNS:

            for key in row.keys():

                if key.lower() == column:

                    return str(row[key])

        return "Unknown"

    def looks_internet_facing(self, *values):

        text = " ".join(str(v) for v in values if v).lower()

        return "Yes" if any(k in text for k in PUBLIC_KEYWORDS) else "No"

    def add_finding(self, **kwargs):

        finding = Finding(**kwargs)

        self.findings.append(finding)

        return finding

    ###########################################################################
    # Prowler
    #
    # Supports both the flat CSV-like field names Prowler's JSON has used
    # historically (CheckID/CheckTitle/ServiceName/ResourceId/Severity/
    # Region) and falls back gracefully if a field is absent.
    ###########################################################################

    def parse_prowler(self):

        directory = Path("output/raw/prowler")

        if not directory.exists():

            return

        for file in directory.rglob("*.json"):

            try:

                data = json.load(open(file))

            except Exception:

                continue

            if isinstance(data, dict):

                data = [data]

            for row in data:

                if not isinstance(row, dict):

                    continue

                check_id = row.get("CheckID") or row.get("check_id") or "unknown_check"

                resource_id = (
                    row.get("ResourceId")
                    or row.get("resource_uid")
                    or "Unknown"
                )

                self.add_finding(

                    cloud_platform="aws",
                    account=str(row.get("AccountId", row.get("account_uid", "Unknown"))),
                    region=row.get("Region", row.get("region", "Unknown")),
                    service=row.get("ServiceName", row.get("service_name", "AWS")),

                    resource_id=resource_id,
                    resource_name=row.get("ResourceName", resource_id),
                    resource_type=row.get("ResourceType", row.get("resource_type", "Unknown")),

                    title=row.get("CheckTitle", row.get("title", "Prowler Finding")),
                    description=row.get("Description", row.get("description", "")),
                    severity=str(row.get("Severity", "Low")).upper(),

                    tool_source="Prowler",
                    evidence_location=str(file),
                    timestamp=self.now(),

                    internet_facing=self.looks_internet_facing(check_id, row.get("CheckTitle", "")),

                ).set_check_id(check_id)

    ###########################################################################
    # Cloudsplaining
    #
    # Walks the report JSON looking for the known finding-type buckets
    # rather than assuming one fixed nesting - Cloudsplaining's report
    # shape varies by scan scope (account-wide vs per-principal).
    ###########################################################################

    CLOUDSPLAINING_FINDING_TYPES = (
        "PrivilegeEscalation",
        "ResourceExposure",
        "DataExfiltration",
        "ServiceWildcard",
        "CredentialsExposure",
    )

    def walk_cloudsplaining(self, node, path=""):

        results = []

        if isinstance(node, dict):

            for key, value in node.items():

                if key in self.CLOUDSPLAINING_FINDING_TYPES and isinstance(value, list) and value:

                    results.append((key, path, value))

                results.extend(
                    self.walk_cloudsplaining(value, f"{path}/{key}")
                )

        elif isinstance(node, list):

            for item in node:

                results.extend(
                    self.walk_cloudsplaining(item, path)
                )

        return results

    def parse_cloudsplaining(self):

        report_dir = Path("output/raw/cloudsplaining/report")

        if not report_dir.exists():

            return

        for file in report_dir.rglob("*.json"):

            try:

                data = json.load(open(file))

            except Exception:

                continue

            for finding_type, principal_path, items in self.walk_cloudsplaining(data):

                for item in items:

                    resource_id = principal_path.strip("/") or "Unknown"

                    if isinstance(item, dict):

                        resource_id = (
                            item.get("PolicyName")
                            or item.get("PolicyArn")
                            or resource_id
                        )

                    self.add_finding(

                        cloud_platform="aws",
                        service="IAM",

                        resource_id=str(resource_id),
                        resource_name=str(resource_id),
                        resource_type="IAM Policy",

                        title=f"Cloudsplaining: {finding_type}",
                        description=f"Cloudsplaining flagged {finding_type} on {resource_id}",
                        severity="HIGH" if finding_type in (
                            "PrivilegeEscalation", "CredentialsExposure"
                        ) else "MEDIUM",

                        tool_source="Cloudsplaining",
                        evidence_location=str(file),
                        timestamp=self.now(),

                    ).set_check_id(finding_type)

    ###########################################################################
    # Steampipe
    #
    # One JSON file per executed query (path mirrors queries/aws/**/*.sql).
    # check_id = file path relative to the steampipe output root, matching
    # the key format used in data/mitre_mappings.yaml and checklist.yaml
    # ("aws/iam/wildcard_permissions").
    ###########################################################################

    def parse_steampipe(self):

        report_dir = Path("output/raw/steampipe")

        if not report_dir.exists():

            return

        for file in report_dir.rglob("*.json"):

            check_id = file.relative_to(report_dir).with_suffix("").as_posix()

            try:

                data = json.load(open(file))

            except Exception:

                continue

            rows = data if isinstance(data, list) else data.get("rows", [])

            if not isinstance(rows, list):

                continue

            for row in rows:

                resource_id = self.extract_resource_id(row)

                self.add_finding(

                    cloud_platform="aws",
                    service=check_id.split("/")[1] if "/" in check_id else "AWS",
                    region=row.get("region", "Unknown") if isinstance(row, dict) else "Unknown",

                    resource_id=resource_id,
                    resource_name=resource_id,
                    resource_type=check_id.split("/")[1] if "/" in check_id else "Unknown",

                    title=check_id.split("/")[-1].replace("_", " ").title(),
                    description=json.dumps(row) if isinstance(row, dict) else str(row),
                    severity="MEDIUM",

                    tool_source="Steampipe",
                    evidence_location=str(file),
                    timestamp=self.now(),

                    internet_facing=self.looks_internet_facing(check_id, json.dumps(row) if isinstance(row, dict) else ""),

                ).set_check_id(check_id)

    ###########################################################################
    # Access Analyzer
    ###########################################################################

    def parse_access_analyzer(self):

        file = Path("output/raw/access_analyzer/access_analyzer_findings.json")

        if not file.exists():

            return

        try:

            findings = json.load(open(file))

        except Exception:

            return

        for row in findings:

            if not isinstance(row, dict):

                continue

            if str(row.get("status", "ACTIVE")).upper() != "ACTIVE":

                continue

            resource_id = row.get("resource", "Unknown")

            self.add_finding(

                cloud_platform="aws",
                service=row.get("resourceType", "Unknown"),

                resource_id=resource_id,
                resource_name=resource_id,
                resource_type=row.get("resourceType", "Unknown"),

                title="Externally Accessible Resource",
                description=f"Access Analyzer flagged external access from {row.get('principal', 'unknown principal')}",
                severity="HIGH",

                tool_source="Access Analyzer",
                evidence_location=str(file),
                timestamp=self.now(),

                internet_facing="Yes" if row.get("isPublic") else "Unknown",

            ).set_check_id("external_access")

    ###########################################################################
    # Config Aggregator
    ###########################################################################

    def parse_config_aggregator(self):

        file = Path("output/raw/config_aggregator/config_rule_compliance.json")

        if not file.exists():

            return

        try:

            rules = json.load(open(file))

        except Exception:

            return

        for rule in rules:

            if not isinstance(rule, dict):

                continue

            compliance = rule.get("Compliance", {}).get("ComplianceType")

            if compliance != "NON_COMPLIANT":

                continue

            rule_name = rule.get("ConfigRuleName", "Unknown")

            self.add_finding(

                cloud_platform="aws",
                service="AWS Config",

                resource_id=rule_name,
                resource_name=rule_name,
                resource_type="Config Rule",

                title=f"Config Rule Non-Compliant: {rule_name}",
                description=f"AWS Config rule '{rule_name}' reports NON_COMPLIANT resources",
                severity="MEDIUM",

                tool_source="Config Aggregator",
                evidence_location=str(file),
                timestamp=self.now(),

            ).set_check_id(rule_name)

    ###########################################################################
    # Save
    ###########################################################################

    def save(self):

        output = self.output_directory / "findings.json"

        with open(output, "w") as outfile:

            json.dump(
                [f.to_dict(include_internal=True) for f in self.findings],
                outfile,
                indent=4,
                default=str,
            )

        logger.success(
            f"Normalized {len(self.findings)} findings"
        )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self):

        console.rule(
            "[bold cyan]Normalization Engine"
        )

        self.parse_prowler()

        self.parse_cloudsplaining()

        self.parse_steampipe()

        self.parse_access_analyzer()

        self.parse_config_aggregator()

        self.save()

        console.print(
            f"[bold green]{len(self.findings)} findings normalized "
            f"into the canonical schema[/bold green]"
        )

        return self.findings
