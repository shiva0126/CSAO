"""Project-local Python path bootstrap.

The workspace ships with a prebuilt virtualenv whose interpreter points at the
system Python, so its bundled `site-packages` directory is not discovered
automatically. Importing this module on startup restores that path for local
commands and tests.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _add_venv_site_packages() -> None:
    root = Path(__file__).resolve().parent
    for base in (root / "venv", root.parent / "venv"):
        lib_dir = base / "lib"
        if not lib_dir.exists():
            continue
        candidates = sorted(lib_dir.glob("python*/site-packages"))
        for candidate in candidates:
            path = str(candidate)
            if path not in sys.path:
                sys.path.insert(0, path)
            return


_add_venv_site_packages()
