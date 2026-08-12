from __future__ import annotations

import io
import os
from http.cookies import SimpleCookie
import zipfile

from workbench.app import (
    DEV_BOOTSTRAP_USERNAME,
    app,
    auth_manager,
    health_checker,
    runtime,
    stability_manager,
)
from workbench.health import probe_request, run_lifespan


def _set_cookie_value(response) -> str:
    header = response.headers.get("Set-Cookie", "")
    jar = SimpleCookie()
    jar.load(header)
    morsel = jar.get("csao_session")
    assert morsel is not None
    return morsel.value


def test_startup_validation_and_health_endpoints(tmp_path, monkeypatch):
    original_db_path = auth_manager.db_path
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()

    startup_messages = run_lifespan(app, "startup")
    assert any(
        message["type"] == "lifespan.startup.complete" for message in startup_messages
    )

    health_response = probe_request(app, "GET", "/health")
    assert health_response.status_code == 200
    payload = health_response.json()
    assert payload["status"] == "healthy"
    assert payload["server"] is True
    assert payload["templates"] is True
    assert payload["static"] is True
    assert payload["routes"] is True
    assert payload["authentication"] is True
    assert payload["runtime"] is True
    assert payload["collectors"] is True

    ui_response = probe_request(app, "GET", "/health/ui")
    assert ui_response.status_code == 200
    ui_payload = ui_response.json()
    assert ui_payload["status"] == "healthy"
    assert ui_payload["results"]["dashboard"]["status_code"] == 200
    assert ui_payload["results"]["cloud_accounts"]["status_code"] == 200
    assert ui_payload["results"]["assessment_workspace"]["status_code"] == 200

    status_response = probe_request(app, "GET", "/runtime/status")
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["startup_validated"] is True
    assert status_payload["components"]["routes"]["ok"] is True
    auth_manager.db_path = original_db_path


def test_ui_smoke_flow_with_authentication_and_htmx(tmp_path, monkeypatch):
    original_db_path = auth_manager.db_path
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()

    assert auth_manager.user_count() == 0
    auth_manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    login_page = probe_request(app, "GET", "/login")
    assert login_page.status_code == 200
    assert "Login" in login_page.text

    login_response = probe_request(
        app,
        "POST",
        "/api/login",
        form={"username": "admin", "password": "super-secure-password"},
        headers={"host": "127.0.0.1:2909"},
    )
    assert login_response.status_code == 303
    assert "Secure" not in login_response.headers.get("Set-Cookie", "")
    session_token = _set_cookie_value(login_response)
    cookies = {"csao_session": session_token}

    dashboard = probe_request(app, "GET", "/dashboard", cookies=cookies)
    assert dashboard.status_code == 200
    assert "Dashboard" in dashboard.text
    assert "Navigation" in dashboard.text
    assert "Assessment Health" in dashboard.text

    assessments = probe_request(app, "GET", "/assessments", cookies=cookies)
    assert assessments.status_code == 200
    assert "New Assessment" in assessments.text
    assert "Assessment Workspace" in assessments.text

    access_requirements = probe_request(
        app, "GET", "/access-requirements", cookies=cookies
    )
    assert access_requirements.status_code == 200
    assert "Customer Access Pack" in access_requirements.text

    workspace = probe_request(app, "GET", "/progress", cookies=cookies)
    assert workspace.status_code == 200
    assert "Assessment Workspace" in workspace.text

    htmx_dashboard = probe_request(
        app,
        "GET",
        "/dashboard",
        cookies=cookies,
        headers={"hx-request": "true"},
    )
    assert htmx_dashboard.status_code == 200
    assert "hx-swap-oob" in htmx_dashboard.text

    context_response = probe_request(app, "GET", "/api/context", cookies=cookies)
    assert context_response.status_code == 200
    context_payload = context_response.json()
    assert "dashboard" in context_payload
    assert "monitor" in context_payload

    css_response = probe_request(app, "GET", "/static/css/workbench.css")
    assert css_response.status_code == 200
    assert ":root" in css_response.text

    js_response = probe_request(app, "GET", "/static/js/workbench.js")
    assert js_response.status_code == 200
    assert "bindWizardState" in js_response.text

    ui_health = health_checker.ui_health().to_dict()
    assert ui_health["status"] == "healthy"
    auth_manager.db_path = original_db_path


def test_login_cookie_remains_secure_for_https_proxy(tmp_path):
    original_db_path = auth_manager.db_path
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()
    auth_manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    login_response = probe_request(
        app,
        "POST",
        "/api/login",
        form={"username": "admin", "password": "super-secure-password"},
        headers={"x-forwarded-proto": "https", "host": "csao.example.internal"},
    )
    assert login_response.status_code == 303
    assert "Secure" in login_response.headers.get("Set-Cookie", "")
    auth_manager.db_path = original_db_path


def test_access_requirements_exports_and_onboarding_package(tmp_path):
    original_db_path = auth_manager.db_path
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()
    auth_manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    login_response = probe_request(
        app,
        "POST",
        "/api/login",
        form={"username": "admin", "password": "super-secure-password"},
    )
    session_token = _set_cookie_value(login_response)
    cookies = {"csao_session": session_token}

    policy_response = probe_request(
        app,
        "GET",
        "/access-requirements/policy.json",
        cookies=cookies,
        query={
            "trust_account_id": "111122223333",
            "assessment_role_name": "CSAO-Assessor",
            "use_external_id": "true",
        },
    )
    assert policy_response.status_code == 200
    policy_payload = policy_response.json()
    assert policy_payload["PolicyName"] == "CSAO_Assessment_ReadOnly"

    package_response = probe_request(
        app,
        "GET",
        "/access-requirements/onboarding-package.zip",
        cookies=cookies,
        query={
            "trust_account_id": "111122223333",
            "assessment_role_name": "CSAO-Assessor",
            "use_external_id": "true",
        },
    )
    assert package_response.status_code == 200
    assert package_response.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(package_response.body)) as archive:
        assert "assessment-policy.json" in archive.namelist()
        assert "trust-policy.json" in archive.namelist()
        assert "README.md" in archive.namelist()
        assert "collector-permission-matrix.csv" in archive.namelist()
        assert "collector-permission-matrix.json" in archive.namelist()
        assert "permission-guide.md" in archive.namelist()
        assert "services-covered.json" in archive.namelist()

    auth_manager.db_path = original_db_path


def test_watchdog_cycle_and_exception_capture(tmp_path):
    original_status_file = stability_manager.status_file
    original_watchdog_log = stability_manager.watchdog_log
    stability_manager.status_file = tmp_path / "runtime_status.json"
    stability_manager.watchdog_log = tmp_path / "runtime_watchdog.jsonl"

    cycle = stability_manager.run_watchdog_cycle()
    assert cycle["status"] == "healthy"
    assert stability_manager.status_file.exists()
    assert stability_manager.watchdog_log.exists()

    def broken_route():
        raise RuntimeError("boom")

    app.get("/__test_broken")(broken_route)
    response = probe_request(app, "GET", "/__test_broken")
    assert response.status_code == 500

    status = stability_manager.snapshot()
    assert status["components"]["request_handler"]["ok"] is False
    assert "boom" in status["components"]["request_handler"]["detail"]

    stability_manager.status_file = original_status_file
    stability_manager.watchdog_log = original_watchdog_log


def test_mutation_routes_render_validation_errors_instead_of_500(tmp_path):
    original_db_path = auth_manager.db_path
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()
    auth_manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    login_response = probe_request(
        app,
        "POST",
        "/api/login",
        form={"username": "admin", "password": "super-secure-password"},
    )
    session_token = _set_cookie_value(login_response)
    cookies = {"csao_session": session_token}

    bad_account = probe_request(
        app,
        "POST",
        "/api/accounts",
        cookies=cookies,
        form={
            "name": "Bad Account",
            "account_id": "1234",
            "auth_type": "profile",
            "profile": "default",
        },
    )
    assert bad_account.status_code == 200
    assert "AWS account ID must be a 12-digit number." in bad_account.text

    bad_assessment = probe_request(
        app,
        "POST",
        "/api/assessments",
        cookies=cookies,
        form={
            "name": "Test Assessment",
            "client": "Client",
            "assessment_type": "full",
            "cloud_account_id": "missing",
            "regions": "us-east-1",
            "collectors": "aws_inventory",
            "services": "ec2",
            "output_location": "output",
            "risk_profile": "balanced",
            "report_types": "generate_json",
        },
    )
    assert bad_assessment.status_code == 200
    assert "A validated cloud account is required." in bad_assessment.text

    missing_test = probe_request(
        app,
        "POST",
        "/api/accounts/does-not-exist/test",
        cookies=cookies,
    )
    assert missing_test.status_code == 200
    assert "Unknown account does-not-exist" in missing_test.text

    missing_open = probe_request(
        app,
        "POST",
        "/api/assessments/does-not-exist/open",
        cookies=cookies,
    )
    assert missing_open.status_code == 200
    assert "Unknown assessment does-not-exist" in missing_open.text

    bad_settings = probe_request(
        app,
        "POST",
        "/api/settings",
        cookies=cookies,
        form={
            "collectors": "aws_inventory",
            "regions": "us-east-1",
            "max_threads": "abc",
            "retry_count": "2",
            "parallel_execution": "false",
            "log_level": "warning",
            "report_formats": "generate_json",
        },
    )
    assert bad_settings.status_code == 200
    assert "invalid literal for int() with base 10" in bad_settings.text

    create_user = probe_request(
        app,
        "POST",
        "/api/users",
        cookies=cookies,
        form={
            "username": "analyst",
            "display_name": "Analyst User",
            "role": "ANALYST",
            "password": "another-secure-password",
        },
    )
    assert create_user.status_code == 200
    assert "Analyst User" in create_user.text

    duplicate_user = probe_request(
        app,
        "POST",
        "/api/users",
        cookies=cookies,
        form={
            "username": "analyst",
            "display_name": "Duplicate Analyst",
            "role": "ANALYST",
            "password": "another-secure-password",
        },
    )
    assert duplicate_user.status_code == 200
    assert "already exists" in duplicate_user.text

    missing_archive = probe_request(
        app,
        "POST",
        "/api/reports/nope.html/archive",
        cookies=cookies,
    )
    assert missing_archive.status_code == 200
    assert "nope.html" in missing_archive.text

    missing_remove = probe_request(
        app,
        "POST",
        "/api/accounts/does-not-exist/remove",
        cookies=cookies,
    )
    assert missing_remove.status_code == 200
    assert "Unknown account does-not-exist." in missing_remove.text

    auth_manager.db_path = original_db_path


def test_development_user_bootstrap_and_reset(tmp_path, monkeypatch):
    original_db_path = auth_manager.db_path
    monkeypatch.setenv("CSAO_DEV_MODE", "1")
    monkeypatch.setenv("CSAO_DEV_BOOTSTRAP_USERNAME", DEV_BOOTSTRAP_USERNAME)
    monkeypatch.setenv("CSAO_DEV_BOOTSTRAP_PASSWORD", "DevModeSecure1!")
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()

    run_lifespan(app, "startup")
    login_page = probe_request(app, "GET", "/login")
    assert login_page.status_code == 200

    dev_user = auth_manager.get_user_by_username(DEV_BOOTSTRAP_USERNAME)
    assert dev_user is not None
    assert dev_user["role"] == "ADMINISTRATOR"
    assert auth_manager.user_count() == 1

    run_lifespan(app, "startup")
    assert auth_manager.user_count() == 1

    assert "Reset Development Password" in login_page.text

    login_response = probe_request(
        app,
        "POST",
        "/api/login",
        form={
            "username": DEV_BOOTSTRAP_USERNAME,
            "password": os.environ["CSAO_DEV_BOOTSTRAP_PASSWORD"],
        },
    )
    assert login_response.status_code == 303

    auth_manager.reset_password(None, dev_user["id"], "AnotherSecure1!")
    bad_login = probe_request(
        app,
        "POST",
        "/api/login",
        form={"username": DEV_BOOTSTRAP_USERNAME, "password": os.environ["CSAO_DEV_BOOTSTRAP_PASSWORD"]},
    )
    assert bad_login.status_code == 200
    assert "Invalid credentials or disabled account." in bad_login.text

    reset_response = probe_request(app, "POST", "/api/dev/reset-password")
    assert reset_response.status_code == 200
    assert f"Development password reset for {DEV_BOOTSTRAP_USERNAME}." in reset_response.text

    restored_login = probe_request(
        app,
        "POST",
        "/api/login",
        form={
            "username": DEV_BOOTSTRAP_USERNAME,
            "password": os.environ["CSAO_DEV_BOOTSTRAP_PASSWORD"],
        },
    )
    assert restored_login.status_code == 303
    auth_manager.db_path = original_db_path


def test_development_reset_hidden_outside_dev_mode(tmp_path, monkeypatch):
    original_db_path = auth_manager.db_path
    monkeypatch.delenv("CSAO_DEV_MODE", raising=False)
    auth_manager.db_path = tmp_path / "auth.db"
    auth_manager._ensure_schema()
    runtime.refresh()
    auth_manager.bootstrap_admin("admin", "Admin User", "super-secure-password")

    login_page = probe_request(app, "GET", "/login")
    assert login_page.status_code == 200
    assert "Reset Development Password" not in login_page.text

    disabled = probe_request(app, "POST", "/api/dev/reset-password")
    assert disabled.status_code == 404
    auth_manager.db_path = original_db_path
