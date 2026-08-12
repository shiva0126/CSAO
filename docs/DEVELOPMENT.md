# Development Guide

## Purpose

This repository contains the Cloud Security Assessment Orchestrator (CSAO), an evidence-driven AWS security assessment platform. Development changes should preserve the existing assessment methodology, runtime flow, and read-only execution model.

## Local Environment

1. Create a Python virtual environment.
2. Install dependencies from `requirements-dev.txt`.
3. Launch the Analyst Console with:

```bash
venv/bin/python workbench/serve.py
```

4. Run the CLI pipeline with:

```bash
venv/bin/python main.py
```

## Validation Expectations

Before opening a pull request or preparing a release candidate:

```bash
venv/bin/python -m pytest -q
venv/bin/python -m flake8 workbench tests core/reporting --jobs=1 --max-line-length=120
```

## Repository Hygiene

- Do not commit `output/`, diagnostics bundles, reports, runtime databases, or virtual environments.
- Do not commit local keys, certificates, `.env` files, or customer assessment artifacts.
- Keep generated artifacts local to the deployment or analyst workstation.

## Change Scope

- Preserve the current CSAO architecture.
- Preserve the current assessment methodology.
- Preserve the read-only AWS operating model.
- Prefer additive hardening, validation, documentation, and UX improvements over structural rewrites.

## Recommended Working Areas

- `workbench/` for UI, auth, and control-plane integration
- `core/` for engines, providers, reporting, and shared logic
- `modules/` for collector runners
- `tests/` for automated validation
- `docs/` for operator and engineering guidance

