# IAM Permission Matrix

Date: July 27, 2026

This matrix is derived from CSAO's implemented collector metadata and generated least-privilege policy logic.

## Required

- `sts:GetCallerIdentity`
- `sts:AssumeRole` when assume-role authentication is selected
- `ec2:DescribeInstances`
- `ec2:DescribeVpcs`
- `ec2:DescribeSecurityGroups`
- `s3:ListAllMyBuckets`
- `iam:ListUsers`
- `iam:ListRoles`
- `iam:GetAccountAuthorizationDetails`
- `lambda:ListFunctions`
- `rds:DescribeDBInstances`
- `access-analyzer:ListAnalyzers`
- `access-analyzer:ListFindings`
- `config:DescribeConfigurationAggregators`
- `config:DescribeComplianceByConfigRule`
- `config:DescribeConfigRules`
- `config:DescribeConformancePacks`
- `config:ListAggregateDiscoveredResources`

## Optional

- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `cloudtrail:GetEventSelectors`
- `config:DescribeConfigurationRecorders`
- `config:DescribeConfigurationRecorderStatus`
- `securityhub:DescribeHub`
- `securityhub:GetEnabledStandards`
- `guardduty:ListDetectors`
- `guardduty:GetDetector`
- `organizations:DescribeOrganization`
- `organizations:ListAccounts`
- `organizations:ListRoots`

## Unused

The generated CSAO least-privilege policy excludes permissions for disabled collectors and does not emit unused AWS actions.
