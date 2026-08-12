#!/usr/bin/env python3
"""One-time migration: copy users + login_audit from the legacy
output/workbench/auth.db (SQLite) into Postgres. Run once, after
`alembic upgrade head` has created the Postgres schema and before
relying on the new workbench/auth.py for logins.

Sessions are intentionally NOT migrated -- they are short-lived
(30 minute sliding expiry) and re-logging in once after cutover is
simpler and safer than porting live tokens across a storage engine
change. The old auth.db is left untouched on disk as a manual
rollback reference.
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from workbench.db.base import Base, SyncSessionLocal, sync_engine  # noqa: E402
from workbench.db.models import LoginAudit, User  # noqa: E402

SQLITE_AUTH_DB = Path("output/workbench/auth.db")


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> None:
    if not SQLITE_AUTH_DB.exists():
        print(f"No legacy auth database found at {SQLITE_AUTH_DB} -- nothing to migrate.")
        return

    Base.metadata.create_all(sync_engine, tables=[User.__table__, LoginAudit.__table__])

    conn = sqlite3.connect(SQLITE_AUTH_DB)
    conn.row_factory = sqlite3.Row

    users = conn.execute("SELECT * FROM users").fetchall()
    audit_rows = conn.execute("SELECT * FROM login_audit ORDER BY id").fetchall()
    conn.close()

    if not users:
        print("Legacy auth database has no users -- nothing to migrate.")
        return

    with SyncSessionLocal() as db:
        existing_usernames = {row[0] for row in db.query(User.username).all()}
        old_id_to_new_id: dict[int, int] = {}
        migrated = 0
        for row in users:
            if row["username"] in existing_usernames:
                print(f"Skipping '{row['username']}' -- already present in Postgres.")
                existing = db.query(User).filter_by(username=row["username"]).one()
                old_id_to_new_id[row["id"]] = existing.id
                continue
            user = User(
                username=row["username"],
                display_name=row["display_name"],
                role=row["role"],
                password_hash=row["password_hash"],
                is_active=bool(row["is_active"]),
                must_change_password=bool(row["must_change_password"]),
                failed_login_attempts=row["failed_login_attempts"] or 0,
                locked_until=_parse_ts(row["locked_until"]),
                created_at=_parse_ts(row["created_at"]) or datetime.now(UTC),
                updated_at=_parse_ts(row["updated_at"]) or datetime.now(UTC),
                last_login_at=_parse_ts(row["last_login_at"]),
            )
            db.add(user)
            db.flush()
            old_id_to_new_id[row["id"]] = user.id
            migrated += 1
            print(f"Migrated user '{row['username']}' (role={row['role']}).")

        for row in audit_rows:
            db.add(
                LoginAudit(
                    username=row["username"],
                    user_id=old_id_to_new_id.get(row["user_id"]) if row["user_id"] else None,
                    action=row["action"],
                    success=bool(row["success"]),
                    remote_addr=row["remote_addr"] or "",
                    user_agent=row["user_agent"] or "",
                    detail=row["detail"] or "",
                    created_at=_parse_ts(row["created_at"]) or datetime.now(UTC),
                )
            )
        db.commit()

    print(f"Done. Migrated {migrated} user(s) and {len(audit_rows)} audit record(s).")
    print(f"Legacy database left untouched at {SQLITE_AUTH_DB} for rollback reference.")


if __name__ == "__main__":
    main()
