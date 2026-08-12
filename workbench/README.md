# Analyst Console Guide

This directory contains the FastAPI-based Analyst Console and operational control plane for CSAO.

## Launch

```bash
venv/bin/python -m workbench.serve
```

The console binds to `http://127.0.0.1:2909`.

## Console Areas

- `Dashboard`: operational command center with health, activity, quick actions, and assessment status
- `Login / Setup`: local authentication bootstrap and session-based access control
- `Cloud Accounts`: encrypted AWS account manager with connection testing
- `New Assessment`: step-based wizard for launching assessments without CLI commands
- `Capability Validation`: pre-assessment AWS identity, service, and collector readiness matrix
- `Access Requirements`: customer onboarding guide with dynamic least-privilege IAM permissions and read-only policy exports
- `Trust Center`: customer-facing read-only guarantee, permission transparency, API transparency, FAQ, and external tool validation
- `Coverage`: domain-level assessment coverage reporting
- `Assessment Progress`: live execution console, stage status, permanent timeline, and cancellation
- `Assessment Register`: analyst validation and note-taking
- `Evidence Explorer`: source filtering, file metadata, preview, and download
- `Threat Scenarios`, `Threat Correlation`, `Attack Paths`, `Risk`, `Recommendations`
- `Reports`: preview, download, regenerate, archive, and review version history
- `Users`: local user administration and login audit history
- `Settings`: UI-managed runtime configuration center

## Operating Model

- The console uses the existing CSAO engines exactly as the CLI does.
- The console is designed for read-only customer AWS assessment roles and least-privilege execution.
- Runtime overrides are persisted in PostgreSQL (`workbench_state` table) — not a JSON file. See `MIGRATION_LEDGER.md` for the migration history.
- Local users, sessions, and login audit history are stored in PostgreSQL (`users`, `sessions`, `login_audit` tables).
- Credentials are encrypted with a local Fernet key at `output/workbench/.secret.key`.
- Assessment snapshots are copied to `output/history/<assessment-id>/`.
- Archived reports are copied to `output/report_archive/`.
- Assessment diagnostics bundles are written to `output/diagnostics/<assessment-id>/assessment_diagnostics.zip`.

## Analyst Workflow

1. Add and validate an AWS account.
2. Review `Access Requirements` and export the least-privilege onboarding policy for the customer administrator.
3. Configure local users and roles from `Users` as needed.
4. Configure regions, collectors, reports, and logging in `Settings`.
5. Run `Capability Validation` or the validation step in `New Assessment` to confirm identity, regions, collector readiness, and service capability coverage.
6. Launch an assessment from `New Assessment`.
7. Monitor progress and logs from `Assessment Progress`.
8. Review evidence and validate findings.
9. Review threats, attack paths, risk, and recommendations.
10. Generate, preview, download, or archive reports.
11. Reopen prior assessments from history.

## Read-Only Model

- Customer AWS access is intended to stay within `List*`, `Get*`, and `Describe*` APIs wherever possible.
- Authentication may additionally use `sts:GetCallerIdentity` and `sts:AssumeRole`.
- Least-privilege policy generation, collector metadata, and capability validation are aligned to the same permission model.
- Startup safety validation refuses assessment launch if enabled collectors would violate the read-only guarantee.

## Fresh Startup

- A clean checkout starts with an empty Analyst Console state.
- Generated assessment artifacts appear under `output/` only after an assessment or smoke test is run.
