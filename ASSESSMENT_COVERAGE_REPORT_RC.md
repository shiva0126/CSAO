# Assessment Coverage Report

Date: Monday, July 27, 2026

## Implementation

Assessment coverage is now available in:

- UI: `/coverage`
- Exported report: `output/reports/assessment_coverage.html`

## Metrics Produced

For each assessment domain the report shows:

- Assessment Domain
- Implemented Controls
- Automatically Validated
- Manual Validation Required
- Not Covered
- Coverage Percentage

## Calculation Model

- `Implemented Controls`: total checklist controls in the domain.
- `Automatically Validated`: controls with automated evidence paths whose current checklist status is `PASS` or `FAIL`.
- `Manual Validation Required`: controls flagged as manual in methodology knowledge.
- `Not Covered`: controls currently `NOT_EVALUATED`.
- `Coverage Percentage`: `(implemented_controls - not_covered) / implemented_controls`.

## Source of Truth

- Knowledge model: `checklists/checklist.yaml`
- Runtime aggregation: `workbench/runtime.py`
- Report export: `core/reporting/reporting_engine.py`
