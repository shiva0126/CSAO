# Security Transparency

This document is the customer-facing security transparency summary for CSAO.

## Operating Model

- CSAO is an evidence-driven cloud security assessment platform.
- CSAO is not a cloud management platform.
- CSAO is designed to execute with customer-provided read-only AWS credentials or an approved read-only `AssumeRole` path.
- CSAO does not create, modify, update, delete, attach, detach, authorize, revoke, start, stop, or execute changes against customer AWS infrastructure.

## Read-Only Guarantee

- CSAO assessment execution is limited to `List*`, `Get*`, and `Describe*` style AWS APIs wherever possible.
- Authentication may additionally use `sts:GetCallerIdentity` and `sts:AssumeRole`.
- If an enabled collector would require write-oriented access, CSAO safety validation fails before assessment startup.

## Credential Handling

- Local Analyst Console users are stored in `output/workbench/auth.db`.
- Passwords are hashed locally with Argon2id.
- Cloud account credentials are encrypted locally with Fernet using `output/workbench/.secret.key`.
- Plaintext passwords are never stored.

## Evidence Handling

- Evidence is written only to local CSAO output artifacts.
- CSAO does not write evidence back into the customer AWS environment.
- Each assessment can produce `assessment_diagnostics.zip` containing logs, validation details, warnings, runtime metadata, and support artifacts.

## Data Flow

1. Analyst authenticates locally to the Analyst Console.
2. CSAO validates identity and capability against the customer-provided AWS role or credentials.
3. Enabled collectors retrieve read-only cloud security evidence.
4. CSAO normalizes evidence into findings, checklist coverage, threat correlation, attack paths, and reports.
5. Evidence, findings, diagnostics, and reports remain local to the CSAO deployment environment.

## Retention

- Runtime state is stored under `output/workbench/`.
- Assessment snapshots are stored under `output/history/`.
- Reports are stored under `output/reports/` and archived copies under `output/report_archive/`.
- Diagnostics bundles are stored under `output/diagnostics/`.

## Logging

- Analyst Console actions are recorded in `output/workbench/audit.log`.
- Assessment execution logs remain local to the CSAO runtime environment.
- Diagnostics bundles include local logs to simplify support and troubleshooting.
