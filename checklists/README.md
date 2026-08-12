# Assessment Checklist Format

The Checklist Validation Engine (`core/engines/checklist_engine.py`) reads a
YAML file with a top-level `checklist:` list. `config/config.yaml ->
checklist.file` currently points at `checklists/checklist.yaml` - the real
177-item checklist imported from the manager's STRIDE assessment workbooks.
`checklist.example.yaml` is a small hand-written reference used by the
offline pytest fixtures.

## The real checklist (checklists/checklist.yaml)

Generated from two workbooks (`STRIDE_CHECKLIST_Priority_Evidence_Map.xlsx`
and `STRIDE_Threat_Scenarios_Refined.xlsx`) by
`checklists/import_stride_workbooks.py`. Re-run it whenever the manager
sends an updated workbook:

```
python3 checklists/import_stride_workbooks.py \
    --checklist-workbook /path/to/STRIDE_CHECKLIST_Priority_Evidence_Map.xlsx \
    --scenarios-workbook /path/to/STRIDE_Threat_Scenarios_Refined.xlsx \
    --checklist-output checklists/checklist.yaml \
    --catalog-output data/attack_path_catalog.yaml
```

### Coverage - read this before trusting checklist status blindly

The 177 checks span 8 assessment domains; this framework only automates
AWS-cloud evidence collection, so:

- **63 items** are in the "Cloud Security (AWS & GCP)" domain.
- **17 of those 63** have a hand-reviewed automated `sources` binding to an
  existing Steampipe query / Cloudsplaining finding type / Prowler check -
  these get real PASS/FAIL/MANUAL_REVIEW status from evidence.
- **The remaining 160 items** (114 Cloud-domain items without a confident
  1:1 query match, plus all 114 items in the AD / on-prem / network /
  vulnerability-scanning / access-review / hardening domains) import with
  `sources: []` and `manual_validation_required: true`. They always report
  `NOT_EVALUATED` from this engine - they are real checklist items the
  analyst still needs to work, just not ones this codebase can validate via
  API calls today.

Known gaps worth closing if this framework's automation scope grows:
- No AWS Organizations / SCP collector exists yet (blocks all of section
  1.1 Account/Governance and 1.2 Guardrails - 14 items).
- `queries/aws/guardduty/rotation_disabled.sql` is mislabeled - it checks
  `aws_kms_key.enabled`, not `key_rotation_enabled`, so it was **not** bound
  to checklist item 1.8.4 ("KMS key rotation status") to avoid reporting a
  false PASS/FAIL. Fix the query before binding it.
- IAM Access Analyzer's "unused access" analyzer type isn't collected
  (only "external access" is) - blocks 1.6.6.
- No Macie/content-scanning, secrets-scanning, or CIS-benchmark-diffing
  integration - blocks several Storage/Secrets/Config-Hardening items even
  though they're nominally AWS-cloud domain.

## Schema

Every item from the real import carries (see
`checklists/import_stride_workbooks.py` for the exact source-column
mapping):

| Field | Source | Notes |
|---|---|---|
| `id` | Check No. (e.g. `"1.3.2"`) | |
| `domain`, `check_area`, `title` | Master STRIDE–Checklist Map | |
| `stride_category`, `linked_threat_number`, `primary_asset_at_risk` | Master map | |
| `priority_tier`, `priority_score`, `severity`, `exploitability`, `attack_phase`, `blast_radius`, `chain_potential` | Master map | |
| `evidence_type`, `evidence_format`, `pass_criteria`, `fail_indicator` | Master map | |
| `collection_method`, `output_document` | Evidence & Output Format sheet | |
| `mitre_mapping` | STRIDE Checklist Post-Val Log | `{"tactics": [...], "techniques": [...]}` - flat lists, **not** paired 1:1 (the source data doesn't pair them either) |
| `mitre_mapping_raw` | STRIDE Checklist Post-Val Log | original free-text MITRE column, kept for traceability |
| `threat_scenario` | Refined Threat Scenarios (joined by Checklist ID) | narrative populates `Finding.related_threat_scenario` |
| `related_attack_paths` | Evidence & Output Format `AP Code` + Refined Threat Scenarios `Attack Path Linked` | comma-joined AP codes, cross-referenced against `data/attack_path_catalog.yaml` in the Attack Path Summary report |
| `sources` | hand-reviewed (`AUTOMATED_SOURCES` in the import script) | `[{tool, query_ref}, ...]` - empty list if not automatable today |
| `manual_validation_required` | hand-reviewed | `true` whenever `sources` is empty, or when a source exists but is only a partial signal for what the item actually asks |

`sources` is the general form: a checklist item validated by more than one
query (e.g. both an SSH-open and an RDP-open check) lists both. A bare
`tool`/`query_ref` pair (as in `checklist.example.yaml`) is accepted as
shorthand for a single source.

## Checklist-to-Finding matching

The engine matches every normalized `Finding` against each of a checklist
item's `sources` by `tool_source` + internal check id (the same identifier
used as the MITRE mapping key - see `data/mitre_mappings.yaml`). Many
findings can satisfy/fail one checklist item across any of its sources; one
checklist item never splits across multiple ids.

## Generic importer (other workbooks)

`checklists/import_workbook.py` is a simpler single-sheet CSV/XLSX skeleton
for importing a *different* checklist workbook in the future (one row per
item, flat columns) - update its `COLUMN_MAP` to match. It is not what
produced the current `checklists/checklist.yaml`; that came from
`import_stride_workbooks.py` above, which is specific to the two STRIDE
workbook's multi-sheet structure.
