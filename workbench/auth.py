from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Request
from sqlalchemy import func, select

from workbench.db.base import Base, SyncSessionLocal, sync_engine
from workbench.db.models import LoginAudit, SessionToken, User

SESSION_COOKIE = "csao_session"
SESSION_TIMEOUT_SECONDS = 1800

ROLE_ADMIN = "ADMINISTRATOR"
ROLE_ANALYST = "ANALYST"
ROLE_READ_ONLY = "READ_ONLY"
ROLE_RANK = {
    ROLE_READ_ONLY: 1,
    ROLE_ANALYST: 2,
    ROLE_ADMIN: 3,
}
DEV_BOOTSTRAP_USERNAME = os.environ.get("CSAO_DEV_BOOTSTRAP_USERNAME", "Devd")
FAILED_LOGIN_THRESHOLD = int(os.environ.get("CSAO_FAILED_LOGIN_THRESHOLD", "5"))
LOCKOUT_MINUTES = int(os.environ.get("CSAO_LOCKOUT_MINUTES", "15"))


def development_mode_enabled() -> bool:
    return os.environ.get("CSAO_DEV_MODE", "").lower() in {"1", "true", "yes"}


def secure_cookie_required(request: Request) -> bool:
    """Single source of truth for whether the session cookie gets `Secure`.

    Every login/setup endpoint must call this -- a second, drifted copy of
    this logic previously lived in workbench/api/auth.py and never learned
    about CSAO_COOKIE_SECURE, so the JSON API kept marking cookies Secure
    over plain HTTP even after the env var was set to disable that.
    """
    configured = os.environ.get("CSAO_COOKIE_SECURE", "").lower()
    if configured in {"0", "false", "no"}:
        return False
    if configured in {"1", "true", "yes"}:
        return True
    if development_mode_enabled():
        return False
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto:
        return forwarded_proto.lower() == "https"
    host = str(request.headers.get("host", "")).split(":", 1)[0].lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return False
    return True


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def development_bootstrap_username() -> str:
    return os.environ.get("CSAO_DEV_BOOTSTRAP_USERNAME", DEV_BOOTSTRAP_USERNAME).strip()


def development_bootstrap_password() -> str:
    return os.environ.get("CSAO_DEV_BOOTSTRAP_PASSWORD", "").strip()


@dataclass
class SessionUser:
    user_id: int
    username: str
    display_name: str
    role: str
    must_change_password: bool = False


def _user_to_dict(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": bool(user.is_active),
        "must_change_password": bool(user.must_change_password),
        "created_at": user.created_at.isoformat().replace("+00:00", "Z"),
        "updated_at": user.updated_at.isoformat().replace("+00:00", "Z"),
        "last_login_at": (
            user.last_login_at.isoformat().replace("+00:00", "Z")
            if user.last_login_at
            else ""
        ),
    }


class LocalAuthManager:
    """Postgres-backed auth manager. Same public API as the original
    SQLite-backed implementation -- callers (workbench/app.py,
    workbench/runtime.py) do not need to change."""

    def __init__(self):
        self.password_hasher = PasswordHasher()
        Base.metadata.create_all(sync_engine, tables=[
            User.__table__, SessionToken.__table__, LoginAudit.__table__,
        ])

    def _hash_password(self, password: str) -> str:
        return self.password_hasher.hash(password)

    def _verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return bool(self.password_hasher.verify(password_hash, password))
        except VerifyMismatchError:
            return False

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def user_count(self) -> int:
        with SyncSessionLocal() as db:
            return db.scalar(select(func.count()).select_from(User)) or 0

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        normalized = username.strip().lower()
        with SyncSessionLocal() as db:
            user = db.scalar(select(User).where(User.username == normalized))
            return _user_to_dict(user) if user else None

    def bootstrap_admin(self, username: str, display_name: str, password: str) -> None:
        if self.user_count():
            raise ValueError("Bootstrap is unavailable after the first user is created.")
        self.create_user(
            actor_user_id=None,
            username=username,
            display_name=display_name,
            role=ROLE_ADMIN,
            password=password,
        )

    def list_users(self) -> List[Dict[str, Any]]:
        with SyncSessionLocal() as db:
            users = db.scalars(
                select(User).order_by(User.role.desc(), User.username.asc())
            ).all()
            return [_user_to_dict(user) for user in users]

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with SyncSessionLocal() as db:
            user = db.get(User, user_id)
            return _user_to_dict(user) if user else None

    def create_user(
        self,
        actor_user_id: Optional[int],
        username: str,
        display_name: str,
        role: str,
        password: str,
    ) -> Dict[str, Any]:
        username = username.strip().lower()
        display_name = display_name.strip() or username
        role = role.strip().upper()
        if role not in ROLE_RANK:
            raise ValueError(f"Unsupported role {role}")
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters.")
        now = utc_now()
        with SyncSessionLocal() as db:
            user = User(
                username=username,
                display_name=display_name,
                role=role,
                password_hash=self._hash_password(password),
                created_at=now,
                updated_at=now,
            )
            db.add(user)
            db.commit()
            user_id = user.id
        self.log_login_event(username, actor_user_id, "USER_CREATED", True, detail=role)
        return self.get_user(user_id) or {}

    def ensure_development_user(self) -> Dict[str, Any]:
        username = development_bootstrap_username()
        password = development_bootstrap_password()
        if not username or not password:
            raise ValueError("Development bootstrap credentials are not configured.")
        existing = self.get_user_by_username(username)
        if existing:
            return existing
        normalized_username = username.lower()
        now = utc_now()
        with SyncSessionLocal() as db:
            user = User(
                username=normalized_username,
                display_name=username,
                role=ROLE_ADMIN,
                password_hash=self._hash_password(password),
                created_at=now,
                updated_at=now,
            )
            db.add(user)
            db.commit()
            user_id = user.id
        self.log_login_event(normalized_username, None, "USER_CREATED", True, detail=ROLE_ADMIN)
        return self.get_user(user_id) or {}

    def update_user(
        self,
        actor_user_id: int,
        user_id: int,
        display_name: str,
        role: str,
        is_active: bool,
    ) -> Dict[str, Any]:
        role = role.strip().upper()
        if role not in ROLE_RANK:
            raise ValueError(f"Unsupported role {role}")
        with SyncSessionLocal() as db:
            if not is_active and self._active_admin_count(db) <= 1:
                current = db.get(User, user_id)
                if current and current.role == ROLE_ADMIN and current.is_active:
                    raise ValueError("At least one active administrator is required.")
            row = db.get(User, user_id)
            row.display_name = display_name.strip()
            row.role = role
            row.is_active = is_active
            row.updated_at = utc_now()
            db.commit()
        self.log_login_event("", actor_user_id, "USER_UPDATED", True, detail=str(user_id))
        return self.get_user(user_id) or {}

    def delete_user(self, actor_user_id: int, user_id: int) -> None:
        with SyncSessionLocal() as db:
            current = db.get(User, user_id)
            if (
                current
                and current.role == ROLE_ADMIN
                and current.is_active
                and self._active_admin_count(db) <= 1
            ):
                raise ValueError("The last active administrator cannot be deleted.")
            if current:
                db.delete(current)
                db.commit()
        self.log_login_event("", actor_user_id, "USER_DELETED", True, detail=str(user_id))

    def reset_password(self, actor_user_id: int, user_id: int, new_password: str) -> None:
        if len(new_password) < 12:
            raise ValueError("Password must be at least 12 characters.")
        with SyncSessionLocal() as db:
            row = db.get(User, user_id)
            row.password_hash = self._hash_password(new_password)
            row.must_change_password = True
            row.updated_at = utc_now()
            db.execute(
                SessionToken.__table__.delete().where(SessionToken.user_id == user_id)
            )
            db.commit()
        self.log_login_event("", actor_user_id, "PASSWORD_RESET", True, detail=str(user_id))

    def change_password(self, user_id: int, current_password: str, new_password: str) -> None:
        if len(new_password) < 12:
            raise ValueError("Password must be at least 12 characters.")
        with SyncSessionLocal() as db:
            row = db.get(User, user_id)
            if not row or not self._verify_password(row.password_hash, current_password):
                raise ValueError("Current password is incorrect.")
            username = row.username
            row.password_hash = self._hash_password(new_password)
            row.must_change_password = False
            row.updated_at = utc_now()
            db.commit()
        self.log_login_event(username, user_id, "PASSWORD_CHANGED", True)

    def create_session(
        self, username: str, password: str, remote_addr: str = "", user_agent: str = ""
    ) -> tuple[Optional[str], Optional[SessionUser]]:
        username = username.strip().lower()
        with SyncSessionLocal() as db:
            row = db.scalar(select(User).where(User.username == username))
            if not row:
                self.log_login_event(username, None, "LOGIN", False, remote_addr, user_agent, "Unknown user")
                self._failed_login_delay(1)
                return None, None
            if not row.is_active:
                self.log_login_event(username, row.id, "LOGIN", False, remote_addr, user_agent, "Disabled user")
                self._failed_login_delay(1)
                return None, None
            if self._is_locked(row):
                detail = f"Locked until {row.locked_until}"
                self.log_login_event(username, row.id, "LOGIN", False, remote_addr, user_agent, detail)
                self._failed_login_delay(int(row.failed_login_attempts or 1))
                return None, None
            if not self._verify_password(row.password_hash, password):
                attempts = self._record_failed_login(db, row)
                self.log_login_event(username, row.id, "LOGIN", False, remote_addr, user_agent, "Invalid password")
                self._failed_login_delay(attempts)
                return None, None
            token = secrets.token_urlsafe(48)
            now = utc_now()
            expires = now + timedelta(seconds=SESSION_TIMEOUT_SECONDS)
            db.add(
                SessionToken(
                    user_id=row.id,
                    token_hash=self._token_hash(token),
                    created_at=now,
                    last_seen_at=now,
                    expires_at=expires,
                )
            )
            row.last_login_at = now
            row.failed_login_attempts = 0
            row.locked_until = None
            row.updated_at = now
            user_id, user_role, user_display_name, must_change = (
                row.id, row.role, row.display_name, row.must_change_password,
            )
            db.commit()
        self.log_login_event(username, user_id, "LOGIN", True, remote_addr, user_agent, "")
        return token, SessionUser(
            user_id=user_id,
            username=username,
            display_name=user_display_name,
            role=user_role,
            must_change_password=bool(must_change),
        )

    def session_user(self, token: str) -> Optional[SessionUser]:
        if not token:
            return None
        hashed = self._token_hash(token)
        with SyncSessionLocal() as db:
            session = db.scalar(select(SessionToken).where(SessionToken.token_hash == hashed))
            if not session:
                return None
            user = db.get(User, session.user_id)
            if not user or not user.is_active:
                db.delete(session)
                db.commit()
                return None
            now = utc_now()
            if session.expires_at <= now:
                db.delete(session)
                db.commit()
                return None
            session.last_seen_at = now
            session.expires_at = now + timedelta(seconds=SESSION_TIMEOUT_SECONDS)
            result = SessionUser(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
                role=user.role,
                must_change_password=bool(user.must_change_password),
            )
            db.commit()
            return result

    def logout(self, token: str, user_id: Optional[int] = None) -> None:
        if not token:
            return
        with SyncSessionLocal() as db:
            db.execute(
                SessionToken.__table__.delete().where(
                    SessionToken.token_hash == self._token_hash(token)
                )
            )
            db.commit()
        self.log_login_event("", user_id, "LOGOUT", True)

    def log_login_event(
        self,
        username: str,
        user_id: Optional[int],
        action: str,
        success: bool,
        remote_addr: str = "",
        user_agent: str = "",
        detail: str = "",
    ) -> None:
        with SyncSessionLocal() as db:
            db.add(
                LoginAudit(
                    username=username,
                    user_id=user_id,
                    action=action,
                    success=success,
                    remote_addr=remote_addr,
                    user_agent=user_agent,
                    detail=detail,
                    created_at=utc_now(),
                )
            )
            db.commit()

    def login_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with SyncSessionLocal() as db:
            rows = db.scalars(
                select(LoginAudit).order_by(LoginAudit.id.desc()).limit(limit)
            ).all()
            return [
                {
                    "id": row.id,
                    "username": row.username,
                    "user_id": row.user_id,
                    "action": row.action,
                    "success": bool(row.success),
                    "remote_addr": row.remote_addr or "",
                    "user_agent": row.user_agent or "",
                    "detail": row.detail or "",
                    "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
                }
                for row in rows
            ]

    def _active_admin_count(self, db) -> int:
        return (
            db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == ROLE_ADMIN, User.is_active.is_(True))
            )
            or 0
        )

    def _is_locked(self, row: User) -> bool:
        if not row.locked_until:
            return False
        return row.locked_until > utc_now()

    def _record_failed_login(self, db, row: User) -> int:
        attempts = int(row.failed_login_attempts or 0) + 1
        locked_until = None
        if attempts >= FAILED_LOGIN_THRESHOLD:
            locked_until = utc_now() + timedelta(minutes=LOCKOUT_MINUTES)
        row.failed_login_attempts = attempts
        row.locked_until = locked_until
        row.updated_at = utc_now()
        db.commit()
        return attempts

    def _failed_login_delay(self, attempts: int) -> None:
        delay_seconds = min(3.0, 0.25 * max(1, attempts))
        time.sleep(delay_seconds)


def has_role(user: Optional[SessionUser], minimum_role: str) -> bool:
    if user is None:
        return False
    return ROLE_RANK.get(user.role, 0) >= ROLE_RANK.get(minimum_role, 0)
