from __future__ import annotations

from workbench.auth import LocalAuthManager
from workbench.runtime import WorkbenchRuntime

# Single shared instances used by both the legacy Jinja/HTMX routes
# (workbench/app.py) and the JSON API (workbench/api/*.py) -- extracted here
# so neither module has to import the other.
runtime = WorkbenchRuntime()
auth_manager = LocalAuthManager()
