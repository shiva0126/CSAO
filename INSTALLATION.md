# Installation Guide

## Requirements

- Python 3.12
- A writable local workspace
- Optional external tools for full evidence collection: `aws`, `prowler`, `cloudsplaining`, `steampipe`, `cartography`

## Setup

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt
```

## Launch

Workbench:

```bash
venv/bin/python -m workbench.serve
```

CLI pipeline:

```bash
venv/bin/python main.py
```

## Notes

- The project virtual environment is the supported runtime.
- The CLI can run in degraded mode when AWS credentials or optional collector binaries are not available.
- The workbench stores encrypted cloud account credentials in `output/workbench/`.
