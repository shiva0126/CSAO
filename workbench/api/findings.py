from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from workbench.api.deps import require_role
from workbench.auth import ROLE_ANALYST, ROLE_READ_ONLY
from workbench.singletons import runtime

router = APIRouter(tags=["findings"])


def _strip_objects(row: dict) -> dict:
    """register_rows() embeds raw Finding/RegisterEntry dataclass instances
    under 'finding'/'entry' for Jinja template convenience -- the row is
    already fully flattened otherwise, so the JSON API just drops them."""
    return {k: v for k, v in row.items() if k not in ("finding", "entry")}


@router.get("/findings")
def list_findings(
    high_risk: bool = False,
    needs_review: bool = False,
    manual_validation: bool = False,
    crown_jewel: bool = False,
    internet_facing: bool = False,
    search: str = "",
    user=Depends(require_role(ROLE_READ_ONLY)),
):
    runtime.refresh(view_name="register")
    filters = {
        "high_risk": "1" if high_risk else "",
        "needs_review": "1" if needs_review else "",
        "manual_validation": "1" if manual_validation else "",
        "crown_jewel": "1" if crown_jewel else "",
        "internet_facing": "1" if internet_facing else "",
        "search": search,
    }
    rows = runtime.register_rows(filters)
    return {
        "rows": [_strip_objects(row) for row in rows],
        "validation_statuses": runtime.validation_statuses(),
    }


class ValidateBody(BaseModel):
    validation_status: str = ""
    analyst_notes: str = ""


@router.post("/findings/{register_id}/validate")
def validate_finding(register_id: str, body: ValidateBody, user=Depends(require_role(ROLE_ANALYST))):
    runtime.save_validation(register_id, body.validation_status, body.analyst_notes)
    return {"status": "ok"}


@router.get("/checklist")
def list_checklist(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="checklist")
    return {"rows": runtime.checklist_rows()}


@router.get("/threats/scenarios")
def list_threat_scenarios(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="threat_scenarios")
    return {"rows": runtime.scenario_rows()}


@router.get("/threats/correlated")
def list_correlated_threats(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="threat_correlation")
    return {"rows": runtime.correlated_rows()}


@router.get("/attack-paths")
def get_attack_paths(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="attack_paths")
    return runtime.attack_path_graph()


@router.get("/risk")
def list_risk(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="risk")
    return {"rows": runtime.risk_rows()}


@router.get("/recommendations")
def list_recommendations(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="recommendations")
    return {"rows": runtime.recommendation_rows()}


@router.get("/evidence")
def list_evidence(source: str = "", search: str = "", user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="evidence")
    return {
        "sources": runtime.evidence_sources(source_filter=source, search=search),
        "source_options": runtime.evidence_sources_grouped(),
    }


@router.get("/evidence/preview")
def preview_evidence(path: str, search: str = "", user=Depends(require_role(ROLE_READ_ONLY))):
    return runtime.evidence_preview(path, search)
