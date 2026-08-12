from __future__ import annotations

import workbench.auth as auth_module

from workbench.auth import (
    ROLE_ADMIN,
    LocalAuthManager,
)


def test_bootstrap_and_login_session(tmp_path):
    manager = LocalAuthManager(tmp_path / "auth.db")
    manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    token, user = manager.create_session("admin", "super-secure-password")

    assert token
    assert user
    assert user.role == ROLE_ADMIN

    session_user = manager.session_user(token)

    assert session_user
    assert session_user.username == "admin"


def test_password_reset_forces_change(tmp_path):
    manager = LocalAuthManager(tmp_path / "auth.db")
    manager.bootstrap_admin("admin", "Admin User", "super-secure-password")
    created = manager.create_user(
        actor_user_id=1,
        username="analyst",
        display_name="Analyst",
        role="ANALYST",
        password="another-secure-password",
    )

    manager.reset_password(1, created["id"], "reset-secure-password")
    token, user = manager.create_session("analyst", "reset-secure-password")

    assert token
    assert user
    assert user.must_change_password is True


def test_multiple_users_can_hold_concurrent_sessions(tmp_path):
    manager = LocalAuthManager(tmp_path / "auth.db")
    manager.bootstrap_admin("admin", "Admin User", "super-secure-password")
    manager.create_user(
        actor_user_id=1,
        username="analyst",
        display_name="Analyst User",
        role="ANALYST",
        password="another-secure-password",
    )

    admin_token, admin_user = manager.create_session("admin", "super-secure-password")
    analyst_token, analyst_user = manager.create_session(
        "analyst", "another-secure-password"
    )

    assert admin_token
    assert analyst_token
    assert admin_token != analyst_token
    assert admin_user
    assert analyst_user
    assert manager.session_user(admin_token).username == "admin"
    assert manager.session_user(analyst_token).username == "analyst"


def test_failed_logins_trigger_lockout(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_module, "FAILED_LOGIN_THRESHOLD", 3)
    monkeypatch.setattr(auth_module, "LOCKOUT_MINUTES", 1)
    manager = LocalAuthManager(tmp_path / "auth.db")
    manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    for _ in range(3):
        token, user = manager.create_session("admin", "wrong-password")
        assert token is None
        assert user is None

    token, user = manager.create_session("admin", "super-secure-password")
    assert token is None
    assert user is None
