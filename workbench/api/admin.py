from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from workbench.api.deps import require_role
from workbench.auth import ROLE_ADMIN
from workbench.singletons import auth_manager, runtime

router = APIRouter(tags=["admin"])


@router.get("/settings")
def get_settings(user=Depends(require_role(ROLE_ADMIN))):
    return {
        "config": runtime.config,
        "settings_payload": runtime.settings_payload(),
        "settings_model": runtime.settings_view_model(),
        "collectors": runtime.available_collectors(),
    }


class SettingsBody(BaseModel):
    collectors: List[str] = []
    regions: str = ""
    default_region: str = ""
    additional_regions: str = ""
    max_threads: str = ""
    retry_count: str = ""
    timeout: str = ""
    parallel_execution: str = ""
    log_level: str = ""
    output_folder: str = ""
    reports_directory: str = ""
    report_formats: List[str] = []
    threat_correlation: str = ""
    risk_enabled: str = ""
    theme: str = ""


@router.post("/settings")
def save_settings(body: SettingsBody, user=Depends(require_role(ROLE_ADMIN))):
    try:
        runtime.save_settings(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}


@router.get("/users")
def list_users(user=Depends(require_role(ROLE_ADMIN))):
    return {"users": auth_manager.list_users(), "login_history": auth_manager.login_history()}


class CreateUserBody(BaseModel):
    username: str
    display_name: str = ""
    role: str
    password: str


@router.post("/users")
def create_user(body: CreateUserBody, current=Depends(require_role(ROLE_ADMIN))):
    try:
        auth_manager.create_user(current.user_id, body.username, body.display_name, body.role, body.password)
    except (ValueError, IntegrityError) as exc:
        message = "A user with that username already exists." if isinstance(exc, IntegrityError) else str(exc)
        raise HTTPException(status_code=400, detail=message) from exc
    return {"status": "ok"}


class UpdateUserBody(BaseModel):
    display_name: str = ""
    role: str = ""
    account_status: str = ""


@router.post("/users/{user_id}/update")
def update_user(user_id: int, body: UpdateUserBody, current=Depends(require_role(ROLE_ADMIN))):
    try:
        auth_manager.update_user(
            current.user_id, user_id, body.display_name, body.role, body.account_status != "disabled"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}


class ResetPasswordBody(BaseModel):
    new_password: str


@router.post("/users/{user_id}/reset-password")
def reset_user_password(user_id: int, body: ResetPasswordBody, current=Depends(require_role(ROLE_ADMIN))):
    try:
        auth_manager.reset_password(current.user_id, user_id, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}


@router.post("/users/{user_id}/delete")
def delete_user(user_id: int, current=Depends(require_role(ROLE_ADMIN))):
    try:
        auth_manager.delete_user(current.user_id, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}
