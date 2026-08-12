# Capability Validation Report

Date: Monday, July 27, 2026

## Implemented Validation Surface

The pre-assessment validation page now verifies and displays:

- STS identity availability
- AWS Account ID
- Caller ARN
- Account alias
- Configured/available regions
- Collector readiness
- Critical dependency status
- Service capability matrix

## Capability Matrix Coverage

The UI checks these service capabilities where credentials are valid:

- IAM
- EC2
- VPC
- CloudTrail
- AWS Config
- GuardDuty
- Security Hub
- Access Analyzer
- Organizations

Each service is reported as one of:

- `Available`
- `Access Denied`
- `Not Enabled`

## Assessment Behavior

- The validation surface is advisory for non-critical gaps.
- The assessment is not intended to fail for partial service coverage.
- Critical dependencies are:
  - STS identity
  - configured/available regions

## Current Environment Note

In the current validation environment, AWS profile/credential availability remains external to the application and must be provided by the operator for live cloud validation.
