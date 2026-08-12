# Collector Permission Matrix

Date: July 27, 2026

## AWS Inventory

- Purpose: baseline inventory
- AWS APIs: `DescribeInstances`, `DescribeVpcs`, `DescribeSecurityGroups`, `ListBuckets`, `ListUsers`, `ListRoles`, `ListFunctions`, `DescribeDBInstances`
- Evidence: asset inventory and identity inventory

## Prowler

- Purpose: posture checks
- AWS APIs: collector-dependent read-only security/configuration APIs
- Evidence: posture findings and control evidence

## Cloudsplaining

- Purpose: IAM privilege analysis
- AWS APIs: `GetAccountAuthorizationDetails`
- Evidence: authorization details export and privilege report

## IAM Access Analyzer

- Purpose: external/public access analysis
- AWS APIs: `ListAnalyzers`, `ListFindings`
- Evidence: analyzer and finding export

## Steampipe

- Purpose: query-driven evidence collection
- AWS APIs: query-pack dependent read-only service APIs
- Evidence: JSON query output

## AWS Config Aggregator

- Purpose: compliance and config state collection
- AWS APIs: `DescribeConfigurationAggregators`, `DescribeComplianceByConfigRule`, `DescribeConfigRules`, `DescribeConformancePacks`, `ListAggregateDiscoveredResources`
- Evidence: config compliance and aggregator inventory

## Cartography

- Purpose: relationship mapping
- AWS APIs: graph-source dependent read-only APIs
- Evidence: relationship summary
- Note: writes only to analyst-owned Neo4j, not to customer AWS

## Tenable

- Purpose: optional external evidence import
- AWS APIs: none against customer AWS
- Evidence: Tenable cloud asset export
