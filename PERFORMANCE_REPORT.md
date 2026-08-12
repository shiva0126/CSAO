# Performance Report

Date: July 27, 2026

## Dashboard Optimization

Issue:

- The workbench rebuilt `AssessmentKnowledgeEngine` and reloaded base configuration on normal page refreshes.

Fixes:

- Cached base configuration in `workbench/runtime.py`
- Cached `AssessmentKnowledgeEngine` in `workbench/runtime.py`
- Preserved summary-based dashboard behavior for non-heavy views

Measured result:

- Repeated dashboard refresh path reduced from approximately `830-890 ms` to approximately `6-7 ms` in runtime measurements on July 27, 2026

## Remaining Notes

- Artifact-heavy pages still load additional data when required
- The dashboard and HTMX navigation continue to use cached metadata instead of recomputing methodology outputs
