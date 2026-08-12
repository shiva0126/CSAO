# Capability Validation Report

Date: July 27, 2026

CSAO now validates service access before assessment launch for:

- STS
- Organizations
- IAM
- EC2
- VPC
- CloudTrail
- Config
- Security Hub
- GuardDuty
- Access Analyzer
- S3
- Lambda
- EKS
- ECS
- RDS
- ELB
- CloudWatch

Statuses returned:

- Available
- Access Denied
- Service Disabled
- Unavailable

Behavior:

- Mandatory dependency failure affects readiness
- Non-mandatory capability gaps generate warnings
- Collector readiness reflects capability dependencies
- Dependent collectors are flagged as `Disabled by Capability` during pre-assessment validation
