from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

# Shared by workbench/runtime.py (legacy live-check path, kept for
# compatibility) and workbench/worker.py (the process that actually runs
# scans, and thus the one whose environment this check should reflect --
# see MIGRATION_LEDGER.md for why the check moved here).


def check_external_tools() -> List[Dict[str, Any]]:
    checks = [
        ("aws", "AWS CLI", ["aws", "--version"], True),
        ("prowler", "Prowler", ["prowler", "--version"], True),
        ("steampipe", "Steampipe", ["steampipe", "--version"], True),
        ("cloudsplaining", "Cloudsplaining", ["cloudsplaining", "--help"], True),
        ("cartography", "Cartography", ["cartography", "--help"], False),
    ]
    rows: List[Dict[str, Any]] = []
    for command, label, version_cmd, required in checks:
        path = shutil.which(command)
        if not path:
            rows.append(
                {
                    "name": label,
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
                "name": label,
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
            "name": "IAM Access Analyzer",
            "installed": True,
            "compatible": True,
            "version": "AWS Native",
            "read_only_mode": "Read Only",
            "required": False,
        }
    )
    return rows
