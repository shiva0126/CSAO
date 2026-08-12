from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from workbench.auth import SESSION_COOKIE, SESSION_TIMEOUT_SECONDS
from workbench.api.deps import get_current_user
from workbench.singletons import auth_manager

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class SetupBody(BaseModel):
    username: str
    display_name: str = ""
    password: str
    confirm_password: str


def _secure_cookie(request: Request) -> bool:
    host = str(request.headers.get("host", "")).split(":", 1)[0].lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return False
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return forwarded_proto.lower() == "https" if forwarded_proto else True


@router.get("/me")
def me(request: Request):
    if auth_manager.user_count() == 0:
        return {"authenticated": False, "needs_setup": True, "user": None}
    token = request.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    if user is None:
        return {"authenticated": False, "needs_setup": False, "user": None}
    return {
        "authenticated": True,
        "needs_setup": False,
        "must_change_password": user.must_change_password,
        "user": {
            "user_id": user.user_id,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
        },
    }


@router.post("/setup")
def setup(body: SetupBody):
    if auth_manager.user_count():
        raise HTTPException(status_code=409, detail="Setup already completed")
    if body.password != body.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    try:
        auth_manager.bootstrap_admin(body.username, body.display_name, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    remote_addr = request.headers.get("x-forwarded-for") or request.headers.get("host", "")
    user_agent = request.headers.get("user-agent", "")
    token, user = auth_manager.create_session(body.username, body.password, remote_addr, user_agent)
    if not token or not user:
        raise HTTPException(status_code=401, detail="Invalid credentials or disabled account")
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TIMEOUT_SECONDS,
        secure=_secure_cookie(request),
        httponly=True,
        samesite="strict",
    )
    return {
        "user": {
            "user_id": user.user_id,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
        },
        "must_change_password": user.must_change_password,
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    auth_manager.logout(token, user.user_id if user else None)
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "ok"}


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


@router.post("/password")
def change_password(body: ChangePasswordBody, user=Depends(get_current_user)):
    if body.new_password != body.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    try:
        auth_manager.change_password(user.user_id, body.current_password, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}
