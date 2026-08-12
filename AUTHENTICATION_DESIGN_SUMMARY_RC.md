# Authentication Design Summary

Date: Monday, July 27, 2026

## Storage Model

- Persistence: SQLite database at `output/workbench/auth.db`
- Tables:
  - `users`
  - `sessions`
  - `login_audit`

## Password Security

- Algorithm: Argon2id via `argon2-cffi`
- Plaintext passwords are never persisted.
- Administrator password reset replaces the stored hash and forces password change at next login.

## Session Model

- Cookie name: `csao_session`
- Timeout: 30 minutes idle timeout
- Cookie flags:
  - `HttpOnly`
  - `SameSite=Strict`
  - `Secure` on non-localhost hosts
- Session values stored client-side are opaque random tokens only.
- Server-side session records store only token hashes.

## Bootstrap Model

- If no users exist, the application redirects to one-time administrator setup.
- After the first user is created, bootstrap is disabled.

## Role Enforcement

- `ADMINISTRATOR`
  - full console access
  - user management
  - cloud account management
  - settings changes
- `ANALYST`
  - launch assessments
  - validate findings
  - regenerate/archive reports
- `READ_ONLY`
  - view dashboards, assessments, findings, evidence, threats, and reports
  - no mutation routes

## Auditability

- Login success/failure is written to `login_audit`
- Logout, user creation, user update, deletion, password reset, and password change are also audited
