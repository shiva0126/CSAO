# Release Readiness Report

Date: Monday, July 27, 2026

## Scope Completed

- Local authentication added with SQLite-backed users, Argon2id password hashing, session timeout, secure cookie handling, logout, password change, administrator password reset, and login audit history.
- Role model added:
  - `ADMINISTRATOR`
  - `ANALYST`
  - `READ_ONLY`
- Route-level permission enforcement added across the Analyst Console.
- Assessment coverage reporting added in the UI and exported reports.
- AWS pre-assessment capability validation expanded with identity, caller ARN, region, collector readiness, critical dependency, and service capability checks.
- Release hardening preserved:
  - dashboard/request-time caching
  - empty-console startup state
  - no demo assessment data retained

## Validation Status

- `pytest`: `15 passed`
- `flake8 workbench tests --jobs=1 --max-line-length=120`: passed
- Import validation: passed
- CLI smoke: passed
- Workbench startup smoke: passed

## Secure Production Notes

- Passwords are stored only as Argon2id hashes in SQLite.
- Session state is server-side in SQLite and client-side only as opaque cookie token.
- Session cookies are `HttpOnly` and `SameSite=Strict`; `Secure` is enabled for non-localhost hosts.
- Administrator bootstrap is one-time and only available before the first user exists.

## Residual Constraints

- Live AWS validation is still environment-dependent and requires real credentials/profiles.
- The local FastAPI/uvicorn compatibility layer is intentionally lightweight and not equivalent to production FastAPI middleware behavior.
