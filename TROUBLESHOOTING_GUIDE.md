# Troubleshooting Guide

## Capability Validation Shows Access Denied

- Confirm the customer-provided read-only role includes the required collector permissions
- Re-export the latest least-privilege policy from `Access Requirements`
- Compare denied capabilities with the collector readiness table

## Collector Shows Disabled by Capability

- The collector depends on a service or permission not currently available
- Run `Capability Validation`
- Review warnings and either adjust permissions or deselect the collector

## Assessment Runs in Degraded Mode

- Check AWS authentication
- Confirm `sts:GetCallerIdentity` succeeds
- Validate configured regions

## Dashboard Feels Slow

- Confirm the service was restarted with the latest runtime caching changes
- Re-open the dashboard after login
