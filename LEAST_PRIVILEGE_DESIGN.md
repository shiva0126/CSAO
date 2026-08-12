# Least Privilege Design

CSAO generates `CSAO_Assessment_ReadOnly` from implemented collector metadata.

Design principles:

- derive actions from enabled collectors only
- keep AWS permissions read-only
- classify actions as required or optional
- exclude unused actions
- expose the same model in UI, exported policy, and validation reporting
