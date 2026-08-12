from __future__ import annotations

from fastapi import APIRouter, Depends

from workbench.api.deps import require_role
from workbench.auth import ROLE_READ_ONLY
from workbench.singletons import runtime

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def get_dashboard(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="dashboard")
    return runtime.dashboard()


@router.get("/coverage")
def get_coverage(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="coverage")
    return runtime.coverage_summary()


@router.get("/trust-center")
def get_trust_center(user=Depends(require_role(ROLE_READ_ONLY))):
    runtime.refresh(view_name="trust_center")
    return runtime.trust_center_view_model()
