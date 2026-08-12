from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml
from fastapi import APIRouter, Depends, HTTPException

from workbench.api.deps import require_role
from workbench.auth import ROLE_READ_ONLY

router = APIRouter(tags=["docs"])

ROOT = Path(__file__).resolve().parent.parent.parent

# Allow-listed by id -> real path. The frontend never sends a filesystem
# path, only one of these ids, so there's no traversal surface.
DOC_LIBRARY: Dict[str, Dict[str, str]] = {
    "readme": {"title": "Project Overview", "category": "Guides", "path": "README.md",
               "description": "What CSAO is, the current architecture, and how to run it."},
    "assessment-workflow": {"title": "Assessment Workflow", "category": "Guides", "path": "ASSESSMENT_WORKFLOW.md",
                             "description": "Step-by-step: add an account, launch, monitor, validate, report."},
    "installation": {"title": "Installation", "category": "Guides", "path": "INSTALLATION.md",
                      "description": "Requirements, setup, and launch commands."},
    "configuration-guide": {"title": "Configuration Guide", "category": "Guides", "path": "CONFIGURATION_GUIDE.md",
                             "description": "How runtime configuration is managed via Settings vs. YAML files."},
    "deployment-guide": {"title": "Deployment Guide", "category": "Guides", "path": "DEPLOYMENT_GUIDE.md",
                          "description": "Deployment model, systemd service setup, health endpoints."},
    "troubleshooting": {"title": "Troubleshooting Guide", "category": "Guides", "path": "TROUBLESHOOTING_GUIDE.md",
                         "description": "Common issues (access denied, degraded mode, slow dashboard) and fixes."},
    "workbench-readme": {"title": "Analyst Console Guide", "category": "Guides", "path": "workbench/README.md",
                          "description": "How the FastAPI-based Analyst Console and control plane fit together."},
    "checklist-format": {"title": "Checklist Format", "category": "Guides", "path": "checklists/README.md",
                          "description": "How the checklist validation engine reads checklist.yaml."},
    "dev-setup": {"title": "Local Development", "category": "Guides", "path": "docs/DEVELOPMENT.md",
                  "description": "Local dev environment setup and validation commands."},
    "git-workflow": {"title": "Git Workflow", "category": "Guides", "path": "docs/GIT_WORKFLOW.md",
                      "description": "Branching strategy, commit conventions, release process."},

    "least-privilege-design": {"title": "Least Privilege Design", "category": "Security & Permissions",
                                "path": "LEAST_PRIVILEGE_DESIGN.md",
                                "description": "How the read-only IAM policy is generated from collector metadata."},
    "permission-model": {"title": "Permission Model", "category": "Security & Permissions", "path": "PERMISSION_MODEL.md",
                          "description": "Summary of the least-privilege, read-only permission model."},
    "security-transparency": {"title": "Security Transparency", "category": "Security & Permissions",
                               "path": "SECURITY_TRANSPARENCY.md",
                               "description": "Customer-facing summary of exactly what CSAO can and can't do."},
    "iam-permission-matrix": {"title": "IAM Permission Matrix", "category": "Security & Permissions",
                               "path": "IAM_PERMISSION_MATRIX.md",
                               "description": "Every IAM action each collector requests, and why."},
    "collector-permission-matrix": {"title": "Collector Permission Matrix", "category": "Security & Permissions",
                                     "path": "COLLECTOR_PERMISSION_MATRIX.md",
                                     "description": "Collector-to-permission mapping reference."},

    "methodology-audit": {"title": "Methodology Audit", "category": "Audit Reports", "path": "METHODOLOGY_AUDIT_RC.md",
                           "description": "Point-in-time audit of the assessment methodology."},
    "read-only-security-audit": {"title": "Read-Only Security Audit", "category": "Audit Reports",
                                  "path": "READ_ONLY_SECURITY_AUDIT.md",
                                  "description": "Point-in-time audit confirming the read-only operating model."},
    "assessment-coverage-report": {"title": "Assessment Coverage Report", "category": "Audit Reports",
                                    "path": "ASSESSMENT_COVERAGE_REPORT_RC.md",
                                    "description": "Point-in-time report on checklist/control coverage."},
    "performance-report": {"title": "Performance Report", "category": "Audit Reports", "path": "PERFORMANCE_REPORT.md",
                            "description": "Point-in-time assessment performance report."},
    "capability-validation-report": {"title": "Capability Validation Report", "category": "Audit Reports",
                                      "path": "CAPABILITY_VALIDATION_REPORT.md",
                                      "description": "Point-in-time capability validation report."},
    "capability-validation-report-rc": {"title": "Capability Validation Report (RC)", "category": "Audit Reports",
                                         "path": "CAPABILITY_VALIDATION_REPORT_RC.md",
                                         "description": "Release-candidate capability validation report."},
    "read-only-safety-report": {"title": "Read-Only Safety Report", "category": "Audit Reports",
                                 "path": "READ_ONLY_SAFETY_REPORT_RC.md",
                                 "description": "Release-candidate read-only safety report."},
    "authentication-design-summary": {"title": "Authentication Design Summary", "category": "Audit Reports",
                                       "path": "AUTHENTICATION_DESIGN_SUMMARY_RC.md",
                                       "description": "Release-candidate authentication design summary."},
    "release-readiness-report": {"title": "Release Readiness Report", "category": "Audit Reports",
                                  "path": "RELEASE_READINESS_REPORT_RC.md",
                                  "description": "Release-candidate release readiness report."},

    "migration-ledger": {"title": "Migration Ledger", "category": "Engineering Log", "path": "MIGRATION_LEDGER.md",
                          "description": "Dated log of the architecture history and every bug found and fixed."},
    "developer-notes": {"title": "Developer Notes", "category": "Engineering Log", "path": "DEVELOPER_NOTES.md",
                         "description": "Architectural constraints and console design notes for developers."},
}


@router.get("/docs")
def list_docs(user=Depends(require_role(ROLE_READ_ONLY))):
    rows: List[Dict[str, Any]] = []
    for doc_id, meta in DOC_LIBRARY.items():
        full_path = ROOT / meta["path"]
        rows.append(
            {
                "id": doc_id,
                "title": meta["title"],
                "category": meta["category"],
                "description": meta["description"],
                "exists": full_path.is_file(),
            }
        )
    return {"rows": rows}


@router.get("/docs/{doc_id}")
def get_doc(doc_id: str, user=Depends(require_role(ROLE_READ_ONLY))):
    meta = DOC_LIBRARY.get(doc_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Unknown document")
    full_path = ROOT / meta["path"]
    if not full_path.is_file():
        raise HTTPException(status_code=404, detail="Document not found on disk")
    return {
        "id": doc_id,
        "title": meta["title"],
        "category": meta["category"],
        "content": full_path.read_text(encoding="utf-8"),
    }


@router.get("/docs/reference/mitre")
def get_mitre_reference(user=Depends(require_role(ROLE_READ_ONLY))):
    path = ROOT / "data" / "mitre_mappings.yaml"
    if not path.is_file():
        return {"rows": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows: List[Dict[str, Any]] = []
    for check_key, techniques in (data.get("mappings") or {}).items():
        tool, _, check_id = check_key.partition(":")
        for entry in techniques or []:
            rows.append(
                {
                    "tool": tool,
                    "check_id": check_id,
                    "tactic": entry.get("tactic", ""),
                    "technique_id": entry.get("technique_id", ""),
                    "technique": entry.get("technique", ""),
                }
            )
    return {"rows": rows}


@router.get("/docs/reference/attack-paths")
def get_attack_path_catalog(user=Depends(require_role(ROLE_READ_ONLY))):
    path = ROOT / "data" / "attack_path_catalog.yaml"
    if not path.is_file():
        return {"rows": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {"rows": data.get("attack_paths") or []}
