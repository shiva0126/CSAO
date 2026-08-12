from __future__ import annotations

import ast
from pathlib import Path


MUTATING_PREFIXES = (
    "create",
    "update",
    "put",
    "delete",
    "modify",
    "attach",
    "detach",
    "authorize",
    "revoke",
    "start",
    "stop",
    "run",
    "execute",
    "passrole",
)

ALLOWED_SPECIAL_CALLS = {
    "assume_role",
    "get_caller_identity",
}

AWS_EXECUTION_FILES = [
    Path("modules/aws_inventory.py"),
    Path("modules/access_analyzer.py"),
    Path("modules/config_aggregator.py"),
    Path("core/providers/aws_provider.py"),
    Path("workbench/control_plane.py"),
]


def _root_name(node):
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id.lower()
    return ""


def test_no_mutating_aws_api_calls_in_execution_paths():
    findings = []
    for path in AWS_EXECUTION_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            name = func.attr.lower()
            root = _root_name(func.value)
            if name in ALLOWED_SPECIAL_CALLS:
                continue
            if root not in {"client", "session", "sts", "ec2", "iam", "s3", "base"}:
                continue
            if any(name.startswith(prefix) for prefix in MUTATING_PREFIXES):
                findings.append(f"{path}:{node.lineno}:{func.attr}")

    assert findings == []
