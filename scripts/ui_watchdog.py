#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workbench.health import remediation_for_error


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def fetch_json(base_url: str, path: str) -> Dict[str, Any]:
    target = f"{base_url.rstrip('/')}{path}"
    with urlopen(target, timeout=10) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def fetch_http(base_url: str, path: str, *, headers: Dict[str, str] | None = None) -> Dict[str, Any]:
    target = f"{base_url.rstrip('/')}{path}"
    req = Request(target, headers=headers or {})
    with urlopen(req, timeout=10) as response:
        payload = response.read().decode("utf-8", errors="replace")
        return {
            "status": response.status,
            "location": response.headers.get("Location", ""),
            "sample": payload[:400],
        }


def log_entry(log_file: Path, payload: Dict[str, Any]) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")


def summarize_failures(payload: Dict[str, Any], component: str) -> List[Dict[str, Any]]:
    if component == "health":
        failures = []
        for key, value in (payload.get("checks") or {}).items():
            if value.get("ok"):
                continue
            message = value.get("error") or value.get("detail") or "Unknown failure"
            failures.append(
                {
                    "component": component,
                    "check": key,
                    "message": message,
                    "status_code": value.get("status_code", 0),
                    "remediation": remediation_for_error(message),
                }
            )
        return failures

    failures = []
    for key, value in (payload.get("results") or {}).items():
        if value.get("ok"):
            continue
        message = value.get("error") or value.get("detail") or "Unknown failure"
        failures.append(
            {
                "component": component,
                "check": key,
                "message": message,
                "status_code": value.get("status_code", 0),
                "remediation": remediation_for_error(message),
            }
        )
    return failures


def monitor(base_url: str, interval_seconds: int, log_file: Path) -> int:
    host_port = base_url.split("://", 1)[-1]
    host, _, port_text = host_port.partition(":")
    port = int(port_text or "80")
    while True:
        cycle = {"timestamp": utc_now(), "base_url": base_url, "checks": []}
        try:
            with socket.create_connection((host, port), timeout=5):
                cycle["checks"].append({"component": "port", "status": "healthy"})
        except OSError as exc:
            cycle.setdefault("failures", []).append(
                {
                    "component": "port",
                    "check": f"{host}:{port}",
                    "message": str(exc),
                    "status_code": 0,
                    "remediation": remediation_for_error(str(exc)),
                }
            )
        try:
            health = fetch_json(base_url, "/health")
            cycle["checks"].append({"component": "health", "status": health.get("status")})
            if health.get("status") != "healthy":
                cycle["failures"] = summarize_failures(health, "health")
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            cycle["failures"] = [
                {
                    "component": "health",
                    "check": "/health",
                    "message": str(exc),
                    "status_code": getattr(exc, "code", 0),
                    "remediation": remediation_for_error(str(exc)),
                }
            ]

        try:
            ui_health = fetch_json(base_url, "/health/ui")
            cycle["checks"].append({"component": "ui", "status": ui_health.get("status")})
            if ui_health.get("status") != "healthy":
                cycle.setdefault("failures", []).extend(summarize_failures(ui_health, "ui"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            cycle.setdefault("failures", []).append(
                {
                    "component": "ui",
                    "check": "/health/ui",
                    "message": str(exc),
                    "status_code": getattr(exc, "code", 0),
                    "remediation": remediation_for_error(str(exc)),
                }
            )

        http_checks = [
            ("dashboard", "/dashboard", None),
            ("runtime_status", "/runtime/status", None),
            ("auth", "/login", None),
            ("htmx", "/progress", {"hx-request": "true"}),
            ("css", "/static/css/workbench.css", None),
            ("js", "/static/js/workbench.js", None),
        ]
        for name, path, headers in http_checks:
            try:
                response = fetch_http(base_url, path, headers=headers)
                cycle["checks"].append(
                    {
                        "component": name,
                        "status": "healthy" if response["status"] in {200, 303, 307} else "unhealthy",
                        "status_code": response["status"],
                    }
                )
                if response["status"] not in {200, 303, 307}:
                    cycle.setdefault("failures", []).append(
                        {
                            "component": name,
                            "check": path,
                            "message": response["sample"],
                            "status_code": response["status"],
                            "remediation": remediation_for_error(response["sample"]),
                        }
                    )
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                cycle.setdefault("failures", []).append(
                    {
                        "component": name,
                        "check": path,
                        "message": str(exc),
                        "status_code": getattr(exc, "code", 0),
                        "remediation": remediation_for_error(str(exc)),
                    }
                )

        cycle["status"] = "healthy" if not cycle.get("failures") else "unhealthy"
        log_entry(log_file, cycle)

        if cycle["status"] != "healthy":
            print(json.dumps(cycle, indent=2))
        else:
            print(f"[{cycle['timestamp']}] UI health healthy")

        time.sleep(interval_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Continuously validate CSAO UI health.")
    parser.add_argument("--base-url", default="http://127.0.0.1:2909", help="Application base URL.")
    parser.add_argument(
        "--interval",
        type=int,
        default=45,
        help="Polling interval in seconds. Recommended range: 30-60.",
    )
    parser.add_argument(
        "--log-file",
        default="output/workbench/ui_watchdog.log",
        help="Log file path for JSONL watchdog output.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return monitor(args.base_url, args.interval, Path(args.log_file))


if __name__ == "__main__":
    raise SystemExit(main())
