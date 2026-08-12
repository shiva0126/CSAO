# Configuration Guide

## Preferred Path

Runtime configuration is managed through the Analyst Console `Settings` page. Normal assessment execution should not require manual YAML edits.

## UI-Managed Areas

- AWS default and additional regions
- Output folder and reports directory
- Concurrency, timeout, retry count, and parallel execution
- Collector enablement
- Checklist path
- Threat correlation and risk scoring flags
- Logging level
- Report format flags
- Console theme

## Backing Files

- Baseline configuration: `config/config.yaml`
- Tool inventory: `config/tools.yaml`
- Workbench overrides: `output/workbench/state.json`

The UI persists overrides into the workbench state layer and merges them onto the baseline config at runtime.

## AWS Accounts

Use the `Cloud Accounts` page to manage:

- AWS Profile
- Access Keys
- Assume Role
- AWS SSO profile-based access

Credentials are masked in the UI and encrypted at rest.
