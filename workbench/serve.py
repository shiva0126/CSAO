from __future__ import annotations

import os
from pathlib import Path
import importlib
import signal
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
for site_packages in sorted((ROOT / "venv" / "lib").glob("python*/site-packages")):
    if str(site_packages) not in sys.path:
        sys.path.insert(0, str(site_packages))
        break

DEFAULT_HOST = os.environ.get("CSAO_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("CSAO_PORT", "2909"))
DEFAULT_LOG_LEVEL = os.environ.get("CSAO_LOG_LEVEL", "info")
STARTUP_TIMEOUT_SECONDS = float(os.environ.get("CSAO_STARTUP_TIMEOUT", "20"))
REQUIRED_MODULES = {
    "fastapi": "FastAPI runtime",
    "jinja2": "Jinja2 templates",
    "argon2": "argon2-cffi authentication dependency",
    "rich": "rich console/logging dependency",
    "yaml": "PyYAML configuration dependency",
}


def _probe_host(host: str) -> str:
    return "127.0.0.1" if host in {"0.0.0.0", "::"} else host


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return True
    return False


def _wait_for_endpoint(url: str, timeout_seconds: float) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response received"
    while time.monotonic() < deadline:
        try:
            with urlopen(Request(url), timeout=2) as response:
                if response.status == 200:
                    return True, "HTTP 200"
                last_error = f"HTTP {response.status}"
        except HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except URLError as exc:
            last_error = str(exc.reason)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(0.25)
    return False, last_error


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _validate_reachability(host: str, port: int, timeout_seconds: float) -> None:
    probe_host = _probe_host(host)
    health_url = f"http://{probe_host}:{port}/health"
    login_url = f"http://{probe_host}:{port}/login"

    ok, detail = _wait_for_endpoint(health_url, timeout_seconds)
    if not ok:
        raise RuntimeError(
            f"Startup validation failed: health endpoint unreachable at {health_url} ({detail})."
        )

    ok, detail = _wait_for_endpoint(login_url, timeout_seconds)
    if not ok:
        raise RuntimeError(
            f"Startup validation failed: login endpoint unreachable at {login_url} ({detail})."
        )

    print(f"CSAO network validation report:")
    print(f" - listening target: {host}:{port}")
    print(f" - probe target: {probe_host}:{port}")
    print(f" - health endpoint: PASS ({health_url})")
    print(f" - login endpoint: PASS ({login_url})")


def _validate_dependencies() -> None:
    missing = []
    for module_name, description in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            missing.append(f"{module_name} ({description}): {type(exc).__name__}: {exc}")
    if missing:
        raise RuntimeError(
            "Startup validation failed: required Python dependencies are unavailable in the launch environment.\n"
            + "\n".join(f" - {item}" for item in missing)
        )


def _validate_static_and_templates() -> None:
    static_files = [
        ROOT / "workbench" / "static" / "css" / "workbench.css",
        ROOT / "workbench" / "static" / "js" / "workbench.js",
        ROOT / "workbench" / "static" / "js" / "charts.js",
        ROOT / "workbench" / "static" / "js" / "attack-paths.js",
    ]
    templates = [
        ROOT / "workbench" / "templates" / "base.html",
        ROOT / "workbench" / "templates" / "page.html",
        ROOT / "workbench" / "templates" / "login.html",
        ROOT / "workbench" / "templates" / "partials" / "dashboard.html",
        ROOT / "workbench" / "templates" / "partials" / "runtime_status.html",
    ]
    missing = [str(path) for path in static_files + templates if not path.exists()]
    if missing:
        raise RuntimeError(
            "Startup validation failed: required UI files are missing.\n"
            + "\n".join(f" - {item}" for item in missing)
        )


def _forward_signal(process: subprocess.Popen[str], signum: int, _frame) -> None:
    if process.poll() is None:
        process.send_signal(signum)


def main() -> None:
    uvicorn_bin = ROOT / "venv" / "bin" / "uvicorn"
    if not uvicorn_bin.exists():
        raise RuntimeError(
            f"Expected uvicorn executable not found at {uvicorn_bin}. "
            "Create the virtual environment and install dependencies first."
        )

    host = DEFAULT_HOST
    port = DEFAULT_PORT
    log_level = DEFAULT_LOG_LEVEL

    if _port_in_use(host, port):
        raise RuntimeError(
            f"Startup validation failed: port {port} is already in use on {host}."
        )

    _validate_dependencies()
    _validate_static_and_templates()

    command = [
        str(uvicorn_bin),
        "workbench.app:app",
        "--host",
        host,
        "--port",
        str(port),
        "--log-level",
        log_level,
    ]
    child_env = dict(os.environ)
    child_env["CSAO_EXPECT_NETWORK"] = "1"
    process = subprocess.Popen(command, cwd=ROOT, env=child_env)

    signal.signal(signal.SIGINT, lambda signum, frame: _forward_signal(process, signum, frame))
    signal.signal(signal.SIGTERM, lambda signum, frame: _forward_signal(process, signum, frame))

    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            exit_code = process.poll()
            if exit_code is not None:
                raise RuntimeError(
                    f"Startup validation failed: server exited before becoming reachable "
                    f"(exit code {exit_code})."
                )
            try:
                _validate_reachability(host, port, 1.5)
                break
            except RuntimeError:
                time.sleep(0.25)
        else:
            raise RuntimeError(
                f"Startup validation failed: server did not become reachable within "
                f"{STARTUP_TIMEOUT_SECONDS:.0f} seconds."
            )

        raise SystemExit(process.wait())
    except BaseException:
        _terminate_process(process)
        raise


if __name__ == "__main__":
    main()
