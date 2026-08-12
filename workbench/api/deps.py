from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from workbench.auth import ROLE_READ_ONLY, SESSION_COOKIE, SessionUser, has_role
from workbench.singletons import auth_manager


def get_current_user(request: Request) -> SessionUser:
    # Deliberately does NOT block on must_change_password here (unlike the
    # legacy HTML routes' path-allowlist approach) -- the SPA reads
    # `must_change_password` from GET /auth/me and routes to a change-password
    # screen client-side instead. Simpler than replicating an endpoint
    # allowlist across every API router.
    token = request.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_role(minimum_role: str = ROLE_READ_ONLY):
    def _dep(user: SessionUser = Depends(get_current_user)) -> SessionUser:
        if not has_role(user, minimum_role):
            raise HTTPException(status_code=403, detail="Access denied")
        return user

    return _dep
