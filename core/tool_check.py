from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

# Shared by workbench/runtime.py (legacy live-check path, kept for
# compatibility) and workbench/worker.py (the process that actually runs
# scans, and thus the one whose environment this check should reflect --
# see MIGRATION_LEDGER.md for why the check moved here).

# Per-tool metadata for the Tools page and its in-browser terminal
# (workbench/api/terminal.py). `help_command` is what the terminal runs
# first when opened for that tool, so the analyst sees the tool's own
# --help/usage guide instead of having to know commands up front or type
# anything to discover them.
TOOL_USAGE: Dict[str, Dict[str, Any]] = {
    "aws": {
        "name": "AWS CLI",
        "purpose": "Validates AWS credentials/session and is the underlying client every other collector authenticates through.",
        "help_command": "aws help",
    },
    "prowler": {
        "name": "Prowler",
        "purpose": "Runs AWS security and compliance checks (CIS, best practices) and reports pass/fail per check.",
        "help_command": "prowler --help",
    },
    "steampipe": {
        "name": "Steampipe",
        "purpose": "Exposes AWS resources as SQL-queryable tables via the `aws` plugin, used to run the queries under queries/aws/*.sql.",
        "help_command": "steampipe query --help",
    },
    "cloudsplaining": {
        "name": "Cloudsplaining",
        "purpose": "Analyzes IAM policies for privilege-escalation and over-permissive access risks.",
        "help_command": "cloudsplaining --help",
    },
    "cartography": {
        "name": "Cartography",
        "purpose": "Maps AWS resource relationships into a Neo4j graph for reachability/blast-radius analysis.",
        "help_command": "cartography --help",
    },
    "access-analyzer": {
        "name": "IAM Access Analyzer",
        "purpose": "AWS-native analyzer that finds resources shared with external principals -- no separate binary to install.",
        "help_command": "aws accessanalyzer help",
    },
}


def check_external_tools() -> List[Dict[str, Any]]:
    checks = [
        ("aws", ["aws", "--version"], True),
        ("prowler", ["prowler", "--version"], True),
        ("steampipe", ["steampipe", "--version"], True),
        ("cloudsplaining", ["cloudsplaining", "--help"], True),
        ("cartography", ["cartography", "--help"], False),
    ]
    rows: List[Dict[str, Any]] = []
    for key, version_cmd, required in checks:
        meta = TOOL_USAGE[key]
        label = meta["name"]
        path = shutil.which(key)
        if not path:
            rows.append(
                {
                    "key": key,
                    "name": label,
                    "purpose": meta["purpose"],
                    "installed": False,
                    "compatible": False,
                    "version": "",
                    "read_only_mode": "Review Required" if label == "Cartography" else "Expected",
                    "required": required,
                }
            )
            continue
        version = ""
        try:
            result = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            output = (result.stdout or result.stderr) or ""
            version = output.strip().splitlines()[0] if output else ""
        except Exception:
            version = ""
        rows.append(
            {
                "key": key,
                "name": label,
                "purpose": meta["purpose"],
                "installed": True,
                "compatible": True,
                "version": version,
                "read_only_mode": (
                    "External Graph Write Only" if label == "Cartography" else "Read Only"
                ),
                "required": required,
            }
        )
    rows.append(
        {
            "key": "access-analyzer",
            "name": "IAM Access Analyzer",
            "purpose": TOOL_USAGE["access-analyzer"]["purpose"],
            "installed": True,
            "compatible": True,
            "version": "AWS Native",
            "read_only_mode": "Read Only",
            "required": False,
        }
    )
    return rows
