from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: str | Path, payload: bytes) -> None:
    target = Path(path)
    _ensure_parent(target)
    backup = target.with_suffix(target.suffix + ".bak")
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists():
            try:
                backup.write_bytes(target.read_bytes())
            except OSError:
                pass
        os.replace(temp_path, target)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


def atomic_write_text(path: str | Path, content: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, content.encode(encoding))


def atomic_write_json(path: str | Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, default=str))


def load_json_with_recovery(path: str | Path, default: Any) -> Any:
    target = Path(path)
    if not target.exists():
        return default
    try:
        with open(target, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        backup = target.with_suffix(target.suffix + ".bak")
        corrupt = target.with_suffix(target.suffix + f".corrupt-{int(time.time())}")
        try:
            os.replace(target, corrupt)
        except OSError:
            return default
        if backup.exists():
            try:
                restored = backup.read_bytes()
                atomic_write_bytes(target, restored)
                with open(target, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            except Exception:
                return default
        return default
