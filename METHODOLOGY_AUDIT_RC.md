# CSAO Methodology Audit

Date: July 27, 2026
Scope: Release-candidate audit of methodology representation and execution coverage. This report documents current implementation status only. It does not introduce new methodology.

## Summary

### Implemented

- Checklist Controls
  Location: `checklists/checklist.yaml`, `core/engines/assessment_knowledge_engine.py`, `core/engines/checklist_engine.py`
  Status: The platform loads checklist controls, evidence requirements, STRIDE category, severity, priority, source mappings, MITRE mapping, and downstream traceability metadata.

- MITRE Mappings
  Location: `checklists/checklist.yaml`, `data/mitre_mapping.yaml`, `core/engines/mitre_engine.py`, `core/engines/assessment_knowledge_engine.py`
  Status: Findings are mapped through predefined mappings and checklist-backed `mitre_mapping` fields. Reporting and traceability consume the mapped tactics and techniques.

- STRIDE Mappings
  Location: `checklists/checklist.yaml`, `core/engines/assessment_knowledge_engine.py`, `core/engines/traceability_engine.py`
  Status: STRIDE is represented per checklist control and carried into the relationship graph.

- Attack Pattern Templates
  Location: `data/attack_path_catalog.yaml`, `core/engines/assessment_knowledge_engine.py`, `core/engines/attack_path_engine.py`
  Status: Attack path templates are loaded as first-class methodology data and linked to scenarios, findings, and reports.

- Evidence Requirements
  Location: `checklists/checklist.yaml`, `core/engines/assessment_knowledge_engine.py`, `core/engines/traceability_engine.py`
  Status: Required evidence type/format and validating tool/query references are structured and used by checklist validation and traceability.

- Assessment Register
  Location: `core/engines/assessment_register_engine.py`
  Status: Findings are normalized into a register with checklist, MITRE, threat, attack-path, and recommendation references.

- Threat Validation and Threat Correlation
  Location: `core/engines/threat_validation_engine.py`, `core/engines/threat_correlation_engine.py`
  Status: Threat scenarios are validated from checklist outcomes and correlated with register/evidence context.

- Recommendations
  Location: `core/engines/recommendation_engine.py`
  Status: Recommendations are generated with references to register items, checklist controls, threat scenarios, attack paths, and evidence.

- Reporting
  Location: `core/reporting/reporting_engine.py`
  Status: The reporting layer consumes normalized methodology artifacts rather than raw collector output.

### Partially Implemented

- Threat Scenarios
  Location: `core/engines/assessment_knowledge_engine.py`
  Status: Threat scenarios exist and are used throughout the pipeline, but they are synthesized by grouping checklist rows with `threat_scenario` text rather than loaded from a dedicated structured scenario catalog.
  Missing placement: A separate workbook-derived threat scenario knowledge source belongs in the Knowledge Engine. The current pipeline can consume it without redesign, but the source model is not yet independently structured.

- Recommendation Templates
  Location: `core/engines/assessment_knowledge_engine.py`, `core/engines/recommendation_engine.py`
  Status: Templates are derived from checklist metadata at runtime (`output_document`, checklist title, priority, linked scenarios/paths). There is no standalone recommendation template library with explicit reusable remediation text, conditions, or analyst guidance.
  Missing placement: A dedicated recommendation template catalog belongs in the Knowledge Engine and should be referenced by the Recommendation Engine.

### Missing

- Dedicated Threat Scenario Catalog
  Current gap: No separate scenario source file with stable identifiers, structured preconditions, validation logic, and scenario-level metadata independent of checklist row aggregation.
  Belongs in: Knowledge Engine

- Dedicated Recommendation Template Catalog
  Current gap: No standalone library of remediation templates with parameterized actions, default analyst guidance, and reporting language.
  Belongs in: Knowledge Engine and Reporting Engine

## Methodology Coverage by Engine

- Assessment Register: Implemented
- Checklist Validation: Implemented
- Threat Validation: Implemented
- Threat Correlation: Implemented
- MITRE Mapping: Implemented
- Attack Path Generation: Implemented
- Recommendations: Partially Implemented
- Reporting: Implemented

## Conclusion

The RC platform implements the end-to-end methodology and executes the expected assessment flow. The main remaining methodology gaps are not pipeline gaps; they are knowledge-modeling gaps. Specifically, threat scenarios and recommendation templates are present operationally but are not yet maintained as independent structured knowledge sources.
