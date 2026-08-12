from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from workbench.api.deps import require_role
from workbench.auth import ROLE_ANALYST, ROLE_READ_ONLY
from workbench.singletons import runtime

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/wizard-defaults")
def wizard_defaults(user=Depends(require_role(ROLE_ANALYST))):
    return runtime.assessment_wizard_view_model()


@router.get("/capability-validation")
def capability_validation(cloud_account_id: str = "", user=Depends(require_role(ROLE_READ_ONLY))):
    return runtime.capability_validation_view_model(cloud_account_id)


@router.get("/validate")
def validate_selection(
    cloud_account_id: str = "", collectors: str = "", user=Depends(require_role(ROLE_ANALYST))
):
    return runtime.pre_assessment_validation(
        cloud_account_id, [item.strip() for item in collectors.split(",") if item.strip()]
    )


class StartAssessmentBody(BaseModel):
    name: str = ""
    client: str = ""
    description: str = ""
    assessment_type: str = ""
    cloud_account_id: str = ""
    regions: List[str] = []
    collectors: List[str] = []
    services: List[str] = []
    output_location: str = ""
    risk_profile: str = ""
    report_types: List[str] = []


@router.post("")
def start_assessment(body: StartAssessmentBody, user=Depends(require_role(ROLE_ANALYST))):
    safety = runtime.safety_validation()
    if safety["status"] != "PASSED":
        raise HTTPException(
            status_code=400,
            detail="Safety Validation Failed. An enabled collector appears to require write access.",
        )
    # Preserves the exact legacy payload shape (regions joined back into a
    # comma string) that runtime.start_assessment()/_build_run_config()
    # already expect -- see control_plane.py, not changing that contract here.
    payload = {
        "name": body.name,
        "client": body.client,
        "description": body.description,
        "assessment_type": body.assessment_type,
        "cloud_account_id": body.cloud_account_id,
        "regions": ",".join(body.regions),
        "collectors": body.collectors,
        "services": body.services,
        "output_location": body.output_location,
        "risk_profile": body.risk_profile,
        "report_types": body.report_types,
    }
    try:
        runtime.start_assessment(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "monitor": runtime.active_monitor()}


@router.post("/cancel")
def cancel_assessment(user=Depends(require_role(ROLE_ANALYST))):
    runtime.cancel_assessment()
    return {"status": "ok"}


@router.get("/active")
def active_monitor(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="progress")
    return runtime.active_monitor()


@router.get("/progress")
def progress(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="progress")
    return {
        "stages": [
            {
                "key": s.key,
                "label": s.label,
                "status": s.status,
                "start_time": s.start_time,
                "finish_time": s.finish_time,
                "duration": s.duration,
                "errors": s.errors,
                "retryable": s.retryable,
                "artifacts": s.artifacts,
            }
            for s in runtime.progress()
        ],
        "logs": runtime.recent_logs(),
    }


@router.post("/stages/{stage_key}/retry")
def retry_stage(stage_key: str, user=Depends(require_role(ROLE_ANALYST))):
    try:
        result = runtime.retry_stage(stage_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "ok", "stage": stage_key, "result": result}


@router.get("/history")
def history(user=Depends(require_role(ROLE_READ_ONLY))):
    return {
        "history": runtime.assessment_history(),
        "active_assessment": runtime.active_assessment(),
    }


@router.post("/{assessment_id}/open")
def open_assessment(assessment_id: str, user=Depends(require_role(ROLE_READ_ONLY))):
    try:
        runtime.open_assessment(assessment_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "ok"}


@router.get("/access-requirements")
def access_requirements(
    trust_account_id: str = "",
    assessment_role_name: str = "",
    use_root_trust: bool = False,
    use_external_id: bool = False,
    external_id: str = "",
    user=Depends(require_role(ROLE_READ_ONLY)),
):
    return runtime.access_requirements_view_model(
        trust_account_id=trust_account_id,
        assessment_role_name=assessment_role_name,
        use_root_trust=use_root_trust,
        use_external_id=use_external_id,
        external_id=external_id,
    )
