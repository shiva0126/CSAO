from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from workbench.api.deps import require_role
from workbench.auth import ROLE_ADMIN, ROLE_READ_ONLY
from workbench.singletons import runtime

router = APIRouter(prefix="/accounts", tags=["accounts"])


class AccountPayload(BaseModel):
    id: str = ""
    name: str = ""
    account_id: str = ""
    alias: str = ""
    auth_type: str = ""
    profile: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    role_arn: str = ""
    external_id: str = ""
    source_profile: str = ""
    sso_start_url: str = ""
    sso_account_id: str = ""
    sso_role_name: str = ""
    sso_region: str = ""
    regions: str = ""
    notes: str = ""


@router.get("")
def list_accounts(user=Depends(require_role(ROLE_ADMIN))):
    return {"accounts": runtime.account_records()}


@router.post("/validate")
def validate_account(body: AccountPayload, user=Depends(require_role(ROLE_ADMIN))):
    try:
        result = runtime.validate_cloud_account_payload(body.model_dump())
        return {
            "status": result.get("status", "FAILED"),
            "validated_at": result.get("validated_at", ""),
            "error": result.get("error", ""),
            "metadata": result.get("metadata", {}) or {},
            "can_save": result.get("status") == "VALIDATED",
        }
    except Exception as exc:
        return {"status": "FAILED", "validated_at": "", "error": str(exc), "metadata": {}, "can_save": False}


@router.post("")
def save_account(body: AccountPayload, user=Depends(require_role(ROLE_ADMIN))):
    try:
        account = runtime.save_cloud_account(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return account


@router.post("/{account_id}/remove")
def remove_account(account_id: str, user=Depends(require_role(ROLE_ADMIN))):
    if not runtime.account_vault.get_account(account_id):
        raise HTTPException(status_code=404, detail=f"Unknown account {account_id}.")
    runtime.delete_cloud_account(account_id)
    return {"status": "ok"}


@router.post("/{account_id}/test")
def test_account(account_id: str, user=Depends(require_role(ROLE_ADMIN))):
    try:
        result = runtime.test_cloud_account(account_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "result": result}
