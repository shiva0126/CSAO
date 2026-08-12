from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from workbench.api.deps import require_role
from workbench.auth import ROLE_ANALYST, ROLE_READ_ONLY
from workbench.singletons import runtime

router = APIRouter(prefix="/reports", tags=["reports"])

# Report files themselves are served by the existing plain file-serving
# routes in workbench/app.py (GET /reports/{filename}, GET
# /diagnostics/download) -- those aren't template pages, just FileResponse
# downloads, so the SPA links to them directly rather than duplicating here.


@router.get("")
def list_reports(user=Depends(require_role(ROLE_READ_ONLY))):
    return {"rows": runtime.report_rows()}


@router.post("/{filename}/archive")
def archive_report(filename: str, user=Depends(require_role(ROLE_ANALYST))):
    try:
        runtime.archive_report(filename)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}
