from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from workbench.auth import ROLE_READ_ONLY, SESSION_COOKIE, development_mode_enabled, has_role
from workbench.db.base import sync_engine
from workbench.singletons import auth_manager, runtime

APP_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    with sync_engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    import redis as redis_client

    redis_client.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), socket_timeout=2
    ).ping()
    if development_mode_enabled():
        auth_manager.ensure_development_user()
    print("CSAO startup: Postgres and Redis reachable, application ready.")
    yield
    sync_engine.dispose()


app = FastAPI(title="CSAO Analyst Workbench", lifespan=lifespan)

from workbench.api import router as api_router  # noqa: E402

app.include_router(api_router, prefix="/api/v1")

# The React/TypeScript SPA at /app is the only UI -- the legacy Jinja/HTMX
# templates and their routes were retired per MIGRATION_LEDGER.md §3f, once
# the user confirmed /app in a real browser.
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


@app.get("/")
def index():
    return RedirectResponse("/app")


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    from loguru import logger

    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        {"error": "Internal server error", "detail": str(exc)}, status_code=500
    )


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
    spa_ok = (SPA_DIST_DIR / "index.html").exists()
    status = "healthy" if (db_ok and redis_ok and spa_ok) else "unhealthy"
    return JSONResponse(
        {
            "status": status,
            "database": db_ok,
            "redis": redis_ok,
            "spa": spa_ok,
        }
    )


# The SPA links to these two directly via plain <a> navigation (not
# fetch/XHR), rather than going through /api/v1 -- see workbench/api/reports.py's
# comment. Since a real browser navigation can't handle a JSON 401 the way the
# SPA's fetch calls do, an auth failure here redirects to /app (which reads
# /api/v1/auth/me and routes to login/change-password) instead of raising.
def _require_download_access(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    if user is None or user.must_change_password or not has_role(user, ROLE_READ_ONLY):
        return None
    return user


@app.get("/reports/{filename}")
def view_report(request: Request, filename: str):
    if _require_download_access(request) is None:
        return RedirectResponse("/app")
    path = runtime.base_directory / "reports" / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path)


@app.get("/diagnostics/download")
def download_diagnostics(request: Request, path: str):
    if _require_download_access(request) is None:
        return RedirectResponse("/app")
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = (Path.cwd() / file_path).resolve()
    if not str(file_path).startswith(str(Path.cwd().resolve())):
        raise HTTPException(status_code=403, detail="Path is outside the workspace")
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Diagnostics bundle not found")
    return FileResponse(file_path)
