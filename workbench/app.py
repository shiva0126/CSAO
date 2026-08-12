from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from workbench.auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_READ_ONLY,
    SESSION_COOKIE,
    SESSION_TIMEOUT_SECONDS,
    development_bootstrap_username,
    has_role,
)
from workbench.db.base import sync_engine
from workbench.singletons import auth_manager, runtime

APP_DIR = Path(__file__).parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    with sync_engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    import redis as redis_client

    redis_client.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), socket_timeout=2
    ).ping()
    ensure_development_auth()
    print("CSAO startup: Postgres and Redis reachable, application ready.")
    yield
    sync_engine.dispose()


app = FastAPI(title="CSAO Analyst Workbench", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

from workbench.api import router as api_router  # noqa: E402

app.include_router(api_router, prefix="/api/v1")

# New React/TypeScript SPA (Phase 3), served alongside the legacy Jinja/HTMX
# UI at /app rather than replacing "/" -- lets the new UI be checked in a
# real browser before the old templates are retired. See MIGRATION_LEDGER.md.
SPA_DIST_DIR = APP_DIR.parent / "frontend" / "dist"
if (SPA_DIST_DIR / "index.html").exists():
    app.mount("/app/assets", StaticFiles(directory=SPA_DIST_DIR / "assets"), name="spa-assets")

    @app.get("/app/favicon.svg")
    def spa_favicon():
        return FileResponse(SPA_DIST_DIR / "favicon.svg")

    @app.get("/app/icons.svg")
    def spa_icons():
        return FileResponse(SPA_DIST_DIR / "icons.svg")

    @app.get("/app")
    @app.get("/app/{full_path:path}")
    def serve_spa(full_path: str = ""):
        return FileResponse(SPA_DIST_DIR / "index.html")


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    from loguru import logger

    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        {"error": "Internal server error", "detail": str(exc)}, status_code=500
    )


def development_mode_enabled() -> bool:
    return os.environ.get("CSAO_DEV_MODE", "").lower() in {"1", "true", "yes"}


def ensure_development_auth() -> None:
    if development_mode_enabled():
        auth_manager.ensure_development_user()


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request", "").lower() == "true"


def request_metadata(request: Request) -> tuple[str, str]:
    return (
        request.headers.get("x-forwarded-for")
        or request.headers.get("host", "")
        or str(request.scope.get("client", "")),
        request.headers.get("user-agent", ""),
    )


def secure_cookie_required(request: Request) -> bool:
    configured = os.environ.get("CSAO_COOKIE_SECURE", "").lower()
    if configured in {"0", "false", "no"}:
        return False
    if development_mode_enabled():
        return configured in {"1", "true", "yes"}
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto:
        return forwarded_proto.lower() == "https"
    host = str(request.headers.get("host", "")).split(":", 1)[0].lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return False
    return True


def session_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    return token, user


@app.get("/health")
def health():
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    try:
        import redis as redis_client

        redis_client.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"), socket_timeout=2
        ).ping()
        redis_ok = True
    except Exception:
        redis_ok = False
    templates_ok = (TEMPLATES_DIR / "base.html").exists()
    static_ok = (STATIC_DIR / "css" / "workbench.css").exists()
    status = "healthy" if (db_ok and redis_ok and templates_ok and static_ok) else "unhealthy"
    return JSONResponse(
        {
            "status": status,
            "database": db_ok,
            "redis": redis_ok,
            "templates": templates_ok,
            "static": static_ok,
        }
    )


def filtered_nav_items(user):
    sections = runtime.nav_sections()
    hidden = set()
    if not has_role(user, ROLE_ANALYST):
        hidden.add("assessments")
    if not has_role(user, ROLE_ADMIN):
        hidden.update({"accounts", "accounts_add", "settings", "runtime_status"})
    if user and user.role != ROLE_ADMIN:
        hidden.add("users")
    filtered_sections = []
    for section in sections:
        items = [item for item in section["items"] if item["key"] not in hidden]
        if items:
            filtered_sections.append({**section, "items": items})
    return filtered_sections


def auth_state(request: Request, minimum_role: str = ROLE_READ_ONLY):
    ensure_development_auth()
    path = request.url.path
    if auth_manager.user_count() == 0 and path not in {"/setup", "/api/setup"}:
        return None, RedirectResponse("/setup")
    token, user = session_user(request)
    if user is None:
        if path not in {"/login", "/api/login", "/setup", "/api/setup"}:
            return None, RedirectResponse("/login")
        return None, None
    if user.must_change_password and path not in {"/password", "/api/password", "/api/logout"}:
        return user, RedirectResponse("/password")
    if not has_role(user, minimum_role):
        if request.method.upper() == "GET":
            return user, RedirectResponse("/dashboard")
        raise HTTPException(status_code=403, detail="Access denied")
    return user, None


def render_page(request: Request, view_name: str, title: str, template_context: dict):
    runtime.refresh(view_name=view_name)
    context = runtime.page_context(request, view_name, title, **template_context)
    token, user = session_user(request)
    context["current_user"] = user
    context["nav_sections"] = filtered_nav_items(user)
    context["role_admin"] = has_role(user, ROLE_ADMIN)
    context["role_analyst"] = has_role(user, ROLE_ANALYST)
    context["role_read_only"] = has_role(user, ROLE_READ_ONLY)
    context["session_timeout_seconds"] = SESSION_TIMEOUT_SECONDS
    context["development_mode"] = development_mode_enabled()
    context["development_user_username"] = development_bootstrap_username()
    context.pop("request", None)
    template_name = "partials/page_swap.html" if is_htmx(request) else "page.html"
    return templates.TemplateResponse(request, template_name, context)


def page_action(request: Request, view_name: str, title: str, data: dict):
    return render_page(request, view_name, title, data)


def render_login(request: Request, template_name: str, context: dict):
    payload = {
        "page_title": context.get("page_title", "Login"),
        "development_mode": development_mode_enabled(),
        "development_user_username": development_bootstrap_username(),
        **context,
    }
    payload.pop("request", None)
    return templates.TemplateResponse(request, template_name, payload)


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    ensure_development_auth()
    if auth_manager.user_count():
        return RedirectResponse("/login")
    return render_login(
        request,
        "setup.html",
        {"page_title": "Initial Setup", "message": "", "error": ""},
    )


@app.post("/api/setup", response_class=HTMLResponse)
def bootstrap_admin(
    request: Request,
    username: Annotated[str, Form()] = "",
    display_name: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    confirm_password: Annotated[str, Form()] = "",
):
    if auth_manager.user_count():
        return RedirectResponse("/login")
    if password != confirm_password:
        return render_login(
            request,
            "setup.html",
            {"page_title": "Initial Setup", "message": "", "error": "Passwords do not match."},
        )
    try:
        auth_manager.bootstrap_admin(username, display_name, password)
    except ValueError as exc:
        return render_login(
            request,
            "setup.html",
            {"page_title": "Initial Setup", "message": "", "error": str(exc)},
        )
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    ensure_development_auth()
    if auth_manager.user_count() == 0:
        return RedirectResponse("/setup")
    _, user = session_user(request)
    if user:
        return RedirectResponse("/dashboard")
    return render_login(
        request, "login.html", {"page_title": "Login", "message": "", "error": ""}
    )


@app.post("/api/dev/reset-password", response_class=HTMLResponse)
def reset_development_password(request: Request):
    if not development_mode_enabled():
        return HTMLResponse("Not found", status_code=404)
    auth_manager.reset_development_password()
    _, current_user = session_user(request)
    message = f"Development password reset for {development_bootstrap_username()}."
    if current_user and has_role(current_user, ROLE_ADMIN):
        return page_action(
            request,
            "users",
            "User Management",
            {
                "users": auth_manager.list_users(),
                "login_history": auth_manager.login_history(),
                "message": message,
            },
        )
    return render_login(
        request, "login.html", {"page_title": "Login", "message": message, "error": ""}
    )


@app.post("/api/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
):
    remote_addr, user_agent = request_metadata(request)
    token, user = auth_manager.create_session(username, password, remote_addr, user_agent)
    if not token or not user:
        return render_login(
            request,
            "login.html",
            {"page_title": "Login", "message": "", "error": "Invalid credentials or disabled account."},
        )
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TIMEOUT_SECONDS,
        secure=secure_cookie_required(request),
        httponly=True,
        samesite="Strict",
    )
    return response


@app.post("/api/logout", response_class=HTMLResponse)
def logout(request: Request):
    token, user = session_user(request)
    auth_manager.logout(token, user.user_id if user else None)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return RedirectResponse("/dashboard")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request, "dashboard", "Executive Dashboard", {"dashboard": runtime.dashboard()}
    )


@app.get("/coverage", response_class=HTMLResponse)
def coverage(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request, "coverage", "Assessment Coverage", {"coverage": runtime.coverage_summary()}
    )


@app.get("/assessments", response_class=HTMLResponse)
def assessments(request: Request):
    user, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    wizard = runtime.assessment_wizard_view_model()
    return page_action(
        request,
        "assessments",
        "New Assessment",
        {
            **wizard,
            "history": runtime.assessment_history()[:5],
            "monitor": runtime.active_monitor(),
            "message": "",
        },
    )


@app.get("/capability-validation", response_class=HTMLResponse)
def capability_validation(request: Request, cloud_account_id: str = ""):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request,
        "capability_validation",
        "Pre-Assessment Validation",
        runtime.capability_validation_view_model(cloud_account_id),
    )


@app.get("/api/capability-validation", response_class=HTMLResponse)
def capability_validation_partial(request: Request, cloud_account_id: str = ""):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request,
        "capability_validation",
        "Pre-Assessment Validation",
        runtime.capability_validation_view_model(cloud_account_id),
    )


@app.get("/access-requirements", response_class=HTMLResponse)
def access_requirements(
    request: Request,
    trust_account_id: str = "",
    assessment_role_name: str = "",
    use_root_trust: bool = False,
    use_external_id: bool = False,
    external_id: str = "",
):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request,
        "access_requirements",
        "Customer Access Pack",
        runtime.access_requirements_view_model(
            trust_account_id=trust_account_id,
            assessment_role_name=assessment_role_name,
            use_root_trust=use_root_trust,
            use_external_id=use_external_id,
            external_id=external_id,
        ),
    )


@app.get("/trust-center", response_class=HTMLResponse)
def trust_center(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "trust_center", "Read-Only Assurance", runtime.trust_center_view_model())


@app.get("/access-requirements/policy.json")
def access_requirements_policy(
    request: Request,
    trust_account_id: str = "",
    assessment_role_name: str = "",
    use_root_trust: bool = False,
    use_external_id: bool = False,
    external_id: str = "",
):
    _, response = auth_state(request)
    if response:
        return response
    data = runtime.access_requirements_view_model(
        trust_account_id=trust_account_id,
        assessment_role_name=assessment_role_name,
        use_root_trust=use_root_trust,
        use_external_id=use_external_id,
        external_id=external_id,
    )
    validation = data.get("policy_validation", {})
    if validation.get("status") == "FAIL":
        return JSONResponse({"errors": validation.get("errors", [])}, status_code=400)
    return JSONResponse(
        data["policy"],
        headers={"Content-Disposition": 'attachment; filename="csao-access-requirements-policy.json"'},
    )


@app.get("/access-requirements/guide.md")
def access_requirements_markdown(
    request: Request,
    trust_account_id: str = "",
    assessment_role_name: str = "",
    use_root_trust: bool = False,
    use_external_id: bool = False,
    external_id: str = "",
):
    _, response = auth_state(request)
    if response:
        return response
    data = runtime.access_requirements_view_model(
        trust_account_id=trust_account_id,
        assessment_role_name=assessment_role_name,
        use_root_trust=use_root_trust,
        use_external_id=use_external_id,
        external_id=external_id,
    )
    return HTMLResponse(
        content=data["policy_markdown"],
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="csao-access-requirements.md"'},
    )


@app.get("/access-requirements/onboarding-package.zip")
def access_requirements_onboarding_package(
    request: Request,
    trust_account_id: str = "",
    assessment_role_name: str = "",
    use_root_trust: bool = False,
    use_external_id: bool = False,
    external_id: str = "",
):
    _, response = auth_state(request)
    if response:
        return response
    data = runtime.access_requirements_view_model(
        trust_account_id=trust_account_id,
        assessment_role_name=assessment_role_name,
        use_root_trust=use_root_trust,
        use_external_id=use_external_id,
        external_id=external_id,
    )
    validation = data.get("policy_validation", {})
    if validation.get("status") == "FAIL":
        return JSONResponse({"errors": validation.get("errors", [])}, status_code=400)
    package = Path(data["onboarding_package"]["path"])
    response = FileResponse(path=str(package))
    response.headers["content-type"] = "application/zip"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{data["onboarding_package"]["filename"]}"'
    )
    response.media_type = "application/zip"
    return response


@app.post("/api/assessments", response_class=HTMLResponse)
def start_assessment(
    request: Request,
    name: Annotated[str, Form()] = "",
    client: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    assessment_type: Annotated[str, Form()] = "",
    cloud_account_id: Annotated[str, Form()] = "",
    regions: Annotated[str, Form()] = "",
    collectors: Annotated[str, Form()] = "",
    services: Annotated[str, Form()] = "",
    output_location: Annotated[str, Form()] = "",
    risk_profile: Annotated[str, Form()] = "",
    report_types: Annotated[str, Form()] = "",
):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    safety = runtime.safety_validation()
    if safety["status"] != "PASSED":
        return page_action(
            request,
            "assessments",
            "New Assessment",
            {
                **runtime.assessment_wizard_view_model(),
                "history": runtime.assessment_history()[:5],
                "monitor": runtime.active_monitor(),
                "message": "",
                "error": "Safety Validation Failed. An enabled collector appears to require write access.",
                "safety_validation": safety,
            },
        )
    payload = {
        "name": name,
        "client": client,
        "description": description,
        "assessment_type": assessment_type,
        "cloud_account_id": cloud_account_id,
        "regions": regions,
        "collectors": [item.strip() for item in collectors.split(",") if item.strip()],
        "services": [item.strip() for item in services.split(",") if item.strip()],
        "output_location": output_location,
        "risk_profile": risk_profile,
        "report_types": [item.strip() for item in report_types.split(",") if item.strip()],
    }
    try:
        runtime.start_assessment(payload)
    except ValueError as exc:
        return page_action(
            request,
            "assessments",
            "New Assessment",
            {
                **runtime.assessment_wizard_view_model(),
                "history": runtime.assessment_history()[:5],
                "monitor": runtime.active_monitor(),
                "message": "",
                "error": str(exc),
                "safety_validation": safety,
            },
        )
    return page_action(
        request,
        "assessments",
        "New Assessment",
        {
            **runtime.assessment_wizard_view_model(),
            "history": runtime.assessment_history()[:5],
            "monitor": runtime.active_monitor(),
            "message": "Assessment started.",
            "safety_validation": safety,
        },
    )


@app.get("/api/assessments/validate", response_class=HTMLResponse)
def validate_assessment(request: Request, cloud_account_id: str = "", collectors: str = ""):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    payload = runtime.pre_assessment_validation(
        cloud_account_id, [item.strip() for item in collectors.split(",") if item.strip()]
    )
    context = runtime.page_context(request, "assessments", "New Assessment", validation=payload)
    context.pop("request", None)
    return templates.TemplateResponse(request, "partials/assessment_validation.html", context)


@app.post("/api/assessments/cancel", response_class=HTMLResponse)
def cancel_assessment(request: Request):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    runtime.cancel_assessment()
    return page_action(
        request, "progress", "Assessment Progress",
        {"stages": runtime.progress(), "monitor": runtime.active_monitor()},
    )


@app.get("/history", response_class=HTMLResponse)
def history(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request, "history", "Assessment History",
        {"history": runtime.assessment_history(), "active_assessment": runtime.active_assessment()},
    )


@app.post("/api/assessments/{assessment_id}/open", response_class=HTMLResponse)
def open_assessment(request: Request, assessment_id: str):
    _, response = auth_state(request)
    if response:
        return response
    try:
        runtime.open_assessment(assessment_id)
    except KeyError as exc:
        return page_action(
            request, "history", "Assessment History",
            {
                "history": runtime.assessment_history(),
                "active_assessment": runtime.active_assessment(),
                "error": str(exc),
            },
        )
    return page_action(
        request, "history", "Assessment History",
        {"history": runtime.assessment_history(), "active_assessment": runtime.active_assessment()},
    )


@app.get("/progress", response_class=HTMLResponse)
def progress(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(
        request, "progress", "Assessment Run",
        {"stages": runtime.progress(), "monitor": runtime.active_monitor(), "logs": runtime.recent_logs()},
    )


@app.get("/register", response_class=HTMLResponse)
def register(
    request: Request,
    high_risk: bool = False,
    needs_review: bool = False,
    manual_validation: bool = False,
    crown_jewel: bool = False,
    internet_facing: bool = False,
    search: str = "",
):
    _, response = auth_state(request)
    if response:
        return response
    filters = {
        "high_risk": "1" if high_risk else "",
        "needs_review": "1" if needs_review else "",
        "manual_validation": "1" if manual_validation else "",
        "crown_jewel": "1" if crown_jewel else "",
        "internet_facing": "1" if internet_facing else "",
        "search": search,
    }
    rows = runtime.register_rows(filters)
    return page_action(
        request, "register", "Findings Register",
        {"rows": rows, "filters": filters, "validation_statuses": runtime.validation_statuses()},
    )


@app.post("/api/register/{register_id}/validate", response_class=HTMLResponse)
def validate_finding(
    request: Request,
    register_id: str,
    validation_status: Annotated[str, Form()] = "",
    analyst_notes: Annotated[str, Form()] = "",
    search: Annotated[str, Form()] = "",
):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    runtime.save_validation(register_id, validation_status, analyst_notes)
    filters = {
        "high_risk": "", "needs_review": "", "manual_validation": "",
        "crown_jewel": "", "internet_facing": "", "search": search,
    }
    rows = runtime.register_rows(filters)
    return page_action(
        request, "register", "Findings Register",
        {"rows": rows, "filters": filters, "validation_statuses": runtime.validation_statuses()},
    )


@app.get("/checklist", response_class=HTMLResponse)
def checklist(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "checklist", "Checklist Validation", {"rows": runtime.checklist_rows()})


@app.get("/threat-scenarios", response_class=HTMLResponse)
def threat_scenarios(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "threat_scenarios", "Threat Scenarios", {"rows": runtime.scenario_rows()})


@app.get("/threat-correlation", response_class=HTMLResponse)
def threat_correlation(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "threat_correlation", "Threat Correlation", {"rows": runtime.correlated_rows()})


@app.get("/attack-paths", response_class=HTMLResponse)
def attack_paths(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "attack_paths", "Attack Paths", {"graph": runtime.attack_path_graph()})


@app.get("/risk", response_class=HTMLResponse)
def risk(request: Request, sort: str = "highest_risk"):
    _, response = auth_state(request)
    if response:
        return response
    rows = runtime.risk_rows()
    if sort == "highest_impact":
        rows = sorted(rows, key=lambda item: (item.get("business_impact") or ""), reverse=True)
    elif sort == "highest_exposure":
        rows = sorted(rows, key=lambda item: item.get("exposure") == "Yes", reverse=True)
    return page_action(request, "risk", "Risk Assessment", {"rows": rows, "sort": sort})


@app.get("/recommendations", response_class=HTMLResponse)
def recommendations(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "recommendations", "Recommendations", {"rows": runtime.recommendation_rows()})


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return page_action(request, "reports", "Deliverables", {"rows": runtime.report_rows()})


@app.get("/accounts", response_class=HTMLResponse)
def accounts(request: Request, edit: str = ""):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    return page_action(
        request, "accounts", "Cloud Accounts",
        {
            "accounts": runtime.account_records(),
            "message": "",
            "editing": runtime.editable_account(edit),
            "validation_result": {},
            "access_requirements_model": runtime.access_requirements_view_model(),
        },
    )


_ACCOUNT_FORM_FIELDS = (
    "id", "name", "account_id", "alias", "auth_type", "profile", "access_key_id",
    "secret_access_key", "session_token", "role_arn", "external_id", "source_profile",
    "sso_start_url", "sso_account_id", "sso_role_name", "sso_region", "regions", "notes",
)


@app.post("/api/accounts/validate", response_class=HTMLResponse)
def validate_account_payload(
    request: Request,
    id: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
    account_id: Annotated[str, Form()] = "",
    alias: Annotated[str, Form()] = "",
    auth_type: Annotated[str, Form()] = "",
    profile: Annotated[str, Form()] = "",
    access_key_id: Annotated[str, Form()] = "",
    secret_access_key: Annotated[str, Form()] = "",
    session_token: Annotated[str, Form()] = "",
    role_arn: Annotated[str, Form()] = "",
    external_id: Annotated[str, Form()] = "",
    source_profile: Annotated[str, Form()] = "",
    sso_start_url: Annotated[str, Form()] = "",
    sso_account_id: Annotated[str, Form()] = "",
    sso_role_name: Annotated[str, Form()] = "",
    sso_region: Annotated[str, Form()] = "",
    regions: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    payload = {field: locals()[field] for field in _ACCOUNT_FORM_FIELDS}
    validation_result = {}
    message = ""
    try:
        result = runtime.validate_cloud_account_payload(payload)
        validation_result = {
            "status": result.get("status", "FAILED"),
            "validated_at": result.get("validated_at", ""),
            "error": result.get("error", ""),
            "metadata": result.get("metadata", {}) or {},
            "can_save": result.get("status") == "VALIDATED",
        }
        message = (
            "Connection validated. Review the detected metadata, then save the account."
            if validation_result["can_save"] else ""
        )
    except Exception as exc:
        validation_result = {
            "status": "FAILED", "validated_at": "", "error": str(exc), "metadata": {}, "can_save": False,
        }
    return page_action(
        request, "accounts", "Cloud Accounts",
        {
            "accounts": runtime.account_records(),
            "message": message,
            "editing": payload,
            "validation_result": validation_result,
            "access_requirements_model": runtime.access_requirements_view_model(),
        },
    )


@app.post("/api/accounts", response_class=HTMLResponse)
def save_account(
    request: Request,
    id: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
    account_id: Annotated[str, Form()] = "",
    alias: Annotated[str, Form()] = "",
    auth_type: Annotated[str, Form()] = "",
    profile: Annotated[str, Form()] = "",
    access_key_id: Annotated[str, Form()] = "",
    secret_access_key: Annotated[str, Form()] = "",
    session_token: Annotated[str, Form()] = "",
    role_arn: Annotated[str, Form()] = "",
    external_id: Annotated[str, Form()] = "",
    source_profile: Annotated[str, Form()] = "",
    sso_start_url: Annotated[str, Form()] = "",
    sso_account_id: Annotated[str, Form()] = "",
    sso_role_name: Annotated[str, Form()] = "",
    sso_region: Annotated[str, Form()] = "",
    regions: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    payload = {field: locals()[field] for field in _ACCOUNT_FORM_FIELDS}
    try:
        account = runtime.save_cloud_account(payload)
    except ValueError as exc:
        return page_action(
            request, "accounts", "Cloud Accounts",
            {
                "accounts": runtime.account_records(),
                "message": "",
                "error": str(exc),
                "editing": payload,
                "validation_result": {
                    "status": "FAILED", "validated_at": "", "error": str(exc), "metadata": {}, "can_save": False,
                },
                "access_requirements_model": runtime.access_requirements_view_model(),
            },
        )
    return page_action(
        request, "accounts", "Cloud Accounts",
        {
            "accounts": runtime.account_records(),
            "message": f'Saved account {account["name"]}.',
            "editing": {},
            "validation_result": {},
            "access_requirements_model": runtime.access_requirements_view_model(),
        },
    )


@app.post("/api/accounts/{account_id}/remove", response_class=HTMLResponse)
def remove_account(request: Request, account_id: str):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    if not runtime.account_vault.get_account(account_id):
        return page_action(
            request, "accounts", "Cloud Accounts",
            {
                "accounts": runtime.account_records(),
                "message": "",
                "error": f"Unknown account {account_id}.",
                "editing": {},
                "validation_result": {},
                "access_requirements_model": runtime.access_requirements_view_model(),
            },
        )
    runtime.delete_cloud_account(account_id)
    return page_action(
        request, "accounts", "Cloud Accounts",
        {
            "accounts": runtime.account_records(),
            "message": f"Removed account {account_id}.",
            "editing": {},
            "validation_result": {},
            "access_requirements_model": runtime.access_requirements_view_model(),
        },
    )


@app.post("/api/accounts/{account_id}/test", response_class=HTMLResponse)
def test_account(request: Request, account_id: str):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    try:
        runtime.test_cloud_account(account_id)
    except (KeyError, ValueError) as exc:
        return page_action(
            request, "accounts", "Cloud Accounts",
            {
                "accounts": runtime.account_records(),
                "message": "",
                "error": str(exc),
                "editing": {},
                "validation_result": {},
                "access_requirements_model": runtime.access_requirements_view_model(),
            },
        )
    return page_action(
        request, "accounts", "Cloud Accounts",
        {
            "accounts": runtime.account_records(),
            "message": f"Connection test completed for {account_id}.",
            "editing": {},
            "validation_result": {},
            "access_requirements_model": runtime.access_requirements_view_model(),
        },
    )


@app.get("/evidence", response_class=HTMLResponse)
def evidence(request: Request, path: str = "", search: str = "", source: str = ""):
    _, response = auth_state(request)
    if response:
        return response
    preview = (
        runtime.evidence_preview(path, search)
        if path
        else {"path": "", "content": "Select an evidence file.", "downloadable": False}
    )
    return page_action(
        request, "evidence", "Evidence Explorer",
        {
            "sources": runtime.evidence_sources(source_filter=source, search=search),
            "preview": preview,
            "search": search,
            "source": source,
            "source_options": runtime.evidence_sources_grouped(),
        },
    )


@app.get("/evidence/download")
def download_evidence(request: Request, path: str):
    _, response = auth_state(request)
    if response:
        return response
    try:
        file_path = runtime.resolve_evidence_path(path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return FileResponse(file_path)


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    return page_action(
        request, "settings", "Settings",
        {
            "config": runtime.config,
            "report_files": runtime.report_rows(),
            "state": runtime.state,
            "enabled_modules": sum(1 for value in (runtime.config.get("modules", {}) or {}).values() if value),
            "settings_payload": runtime.settings_payload(),
            "settings_model": runtime.settings_view_model(),
            "collectors": runtime.available_collectors(),
        },
    )


@app.post("/api/settings", response_class=HTMLResponse)
def save_settings(
    request: Request,
    collectors: Annotated[str, Form()] = "",
    regions: Annotated[str, Form()] = "",
    default_region: Annotated[str, Form()] = "",
    additional_regions: Annotated[str, Form()] = "",
    max_threads: Annotated[str, Form()] = "",
    retry_count: Annotated[str, Form()] = "",
    timeout: Annotated[str, Form()] = "",
    parallel_execution: Annotated[str, Form()] = "",
    log_level: Annotated[str, Form()] = "",
    output_folder: Annotated[str, Form()] = "",
    reports_directory: Annotated[str, Form()] = "",
    report_formats: Annotated[str, Form()] = "",
    threat_correlation: Annotated[str, Form()] = "",
    risk_enabled: Annotated[str, Form()] = "",
    theme: Annotated[str, Form()] = "",
):
    _, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    payload = {
        "collectors": [item.strip() for item in collectors.split(",") if item.strip()],
        "regions": regions,
        "default_region": default_region,
        "additional_regions": additional_regions,
        "max_threads": max_threads,
        "retry_count": retry_count,
        "timeout": timeout,
        "parallel_execution": parallel_execution,
        "log_level": log_level,
        "output_folder": output_folder,
        "reports_directory": reports_directory,
        "report_formats": [item.strip() for item in report_formats.split(",") if item.strip()],
        "threat_correlation": threat_correlation,
        "risk_enabled": risk_enabled,
        "theme": theme,
    }
    try:
        runtime.save_settings(payload)
    except ValueError as exc:
        return page_action(
            request, "settings", "Settings",
            {
                "config": runtime.config,
                "report_files": runtime.report_rows(),
                "state": runtime.state,
                "enabled_modules": sum(1 for value in (runtime.config.get("modules", {}) or {}).values() if value),
                "settings_payload": runtime.settings_payload(),
                "settings_model": runtime.settings_view_model(),
                "collectors": runtime.available_collectors(),
                "error": str(exc),
            },
        )
    return page_action(
        request, "settings", "Settings",
        {
            "config": runtime.config,
            "report_files": runtime.report_rows(),
            "state": runtime.state,
            "enabled_modules": sum(1 for value in (runtime.config.get("modules", {}) or {}).values() if value),
            "settings_payload": runtime.settings_payload(),
            "settings_model": runtime.settings_view_model(),
            "collectors": runtime.available_collectors(),
        },
    )


@app.get("/api/context")
def api_context(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return {
        "dashboard": runtime.dashboard(),
        "stages": [stage.__dict__ for stage in runtime.progress()],
        "register_count": len(runtime.register_entries),
        "finding_count": len(runtime.findings),
        "recommendation_count": len(runtime.recommendations),
        "accounts": runtime.account_records(),
        "history": runtime.assessment_history(),
        "monitor": runtime.active_monitor(),
    }


@app.get("/api/graph")
def api_graph(request: Request):
    _, response = auth_state(request)
    if response:
        return response
    return runtime.attack_path_graph()


@app.get("/api/node/{kind}/{identifier}", response_class=HTMLResponse)
def graph_node_detail(request: Request, kind: str, identifier: str):
    _, response = auth_state(request)
    if response:
        return response
    detail = runtime.node_detail(kind, identifier)
    return templates.TemplateResponse(request, "partials/detail_offcanvas.html", {"detail": detail})


@app.get("/api/{entity_type}/{identifier}", response_class=HTMLResponse)
def detail_panel(request: Request, entity_type: str, identifier: str):
    _, response = auth_state(request)
    if response:
        return response
    detail = runtime.detail_context(entity_type, identifier)
    return templates.TemplateResponse(request, "partials/detail_offcanvas.html", {"detail": detail})


@app.post("/api/stages/{stage_key}/retry")
def retry_stage(request: Request, stage_key: str):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    try:
        result = runtime.retry_stage(stage_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if is_htmx(request):
        return HTMLResponse(
            f'<div class="alert alert-success mb-0">Stage "{stage_key}" completed successfully.</div>'
        )
    return JSONResponse({"status": "ok", "stage": stage_key, "result": result})


@app.get("/reports/{filename}")
def view_report(request: Request, filename: str):
    _, response = auth_state(request)
    if response:
        return response
    path = runtime.base_directory / "reports" / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path)


@app.get("/diagnostics/download")
def download_diagnostics(request: Request, path: str):
    _, response = auth_state(request)
    if response:
        return response
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = (Path.cwd() / file_path).resolve()
    if not str(file_path).startswith(str(Path.cwd().resolve())):
        raise HTTPException(status_code=403, detail="Path is outside the workspace")
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Diagnostics bundle not found")
    return FileResponse(file_path)


@app.post("/api/reports/{filename}/archive", response_class=HTMLResponse)
def archive_report(request: Request, filename: str):
    _, response = auth_state(request, ROLE_ANALYST)
    if response:
        return response
    try:
        runtime.archive_report(filename)
    except (FileNotFoundError, ValueError) as exc:
        return page_action(
            request, "reports", "Deliverables", {"rows": runtime.report_rows(), "error": str(exc)}
        )
    return page_action(request, "reports", "Deliverables", {"rows": runtime.report_rows()})


@app.get("/users", response_class=HTMLResponse)
def users(request: Request):
    user, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    return page_action(
        request, "users", "User Management",
        {"users": auth_manager.list_users(), "login_history": auth_manager.login_history()},
    )


@app.post("/api/users", response_class=HTMLResponse)
def create_user(
    request: Request,
    username: Annotated[str, Form()] = "",
    display_name: Annotated[str, Form()] = "",
    role: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
):
    current, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    try:
        auth_manager.create_user(current.user_id, username, display_name, role, password)
    except (ValueError, IntegrityError) as exc:
        message = "A user with that username already exists." if isinstance(exc, IntegrityError) else str(exc)
        return page_action(
            request, "users", "User Management",
            {"users": auth_manager.list_users(), "login_history": auth_manager.login_history(), "error": message},
        )
    return users(request)


@app.post("/api/users/{user_id}/update", response_class=HTMLResponse)
def update_user(
    request: Request,
    user_id: str,
    display_name: Annotated[str, Form()] = "",
    role: Annotated[str, Form()] = "",
    account_status: Annotated[str, Form()] = "",
):
    current, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    try:
        auth_manager.update_user(
            current.user_id, int(user_id), display_name, role, account_status != "disabled"
        )
    except ValueError as exc:
        return page_action(
            request, "users", "User Management",
            {"users": auth_manager.list_users(), "login_history": auth_manager.login_history(), "error": str(exc)},
        )
    return users(request)


@app.post("/api/users/{user_id}/reset-password", response_class=HTMLResponse)
def reset_user_password(request: Request, user_id: str, new_password: Annotated[str, Form()] = ""):
    current, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    try:
        auth_manager.reset_password(current.user_id, int(user_id), new_password)
    except ValueError as exc:
        return page_action(
            request, "users", "User Management",
            {"users": auth_manager.list_users(), "login_history": auth_manager.login_history(), "error": str(exc)},
        )
    return users(request)


@app.post("/api/users/{user_id}/delete", response_class=HTMLResponse)
def delete_user(request: Request, user_id: str):
    current, response = auth_state(request, ROLE_ADMIN)
    if response:
        return response
    try:
        auth_manager.delete_user(current.user_id, int(user_id))
    except ValueError as exc:
        return page_action(
            request, "users", "User Management",
            {"users": auth_manager.list_users(), "login_history": auth_manager.login_history(), "error": str(exc)},
        )
    return users(request)


@app.get("/password", response_class=HTMLResponse)
def password_page(request: Request):
    user, response = auth_state(request)
    if response:
        return response
    return render_login(
        request, "password.html",
        {"page_title": "Change Password", "message": "", "error": "", "current_user": user},
    )


@app.post("/api/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: Annotated[str, Form()] = "",
    new_password: Annotated[str, Form()] = "",
    confirm_password: Annotated[str, Form()] = "",
):
    user, response = auth_state(request)
    if response:
        return response
    if new_password != confirm_password:
        return render_login(
            request, "password.html",
            {"page_title": "Change Password", "message": "", "error": "Passwords do not match.", "current_user": user},
        )
    try:
        auth_manager.change_password(user.user_id, current_password, new_password)
    except ValueError as exc:
        return render_login(
            request, "password.html",
            {"page_title": "Change Password", "message": "", "error": str(exc), "current_user": user},
        )
    return render_login(
        request, "password.html",
        {"page_title": "Change Password", "message": "Password updated.", "error": "", "current_user": user},
    )
