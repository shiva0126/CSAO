from __future__ import annotations

from fastapi import APIRouter

from workbench.api import accounts, admin, assessments, auth, dashboard, findings, reports

router = APIRouter()
router.include_router(auth.router)
router.include_router(dashboard.router)
router.include_router(findings.router)
router.include_router(assessments.router)
router.include_router(accounts.router)
router.include_router(admin.router)
router.include_router(reports.router)
