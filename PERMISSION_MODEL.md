# Permission Model

CSAO operates under a least-privilege, read-only assessment model.

## Allowed Permission Categories

- `List*`
- `Get*`
- `Describe*`
- `sts:GetCallerIdentity`
- `sts:AssumeRole` when the customer provides an assume-role path

## Disallowed Categories

CSAO does not intentionally require:

- `Create*`
- `Update*`
- `Put*`
- `Delete*`
- `Modify*`
- `Attach*`
- `Detach*`
- `Authorize*`
- `Revoke*`
- `Start*`
- `Stop*`
- `Run*`
- `Execute*`
- `PassRole`

## Dynamic Policy Generation

The Access Requirements page generates a least-privilege policy from the collectors currently enabled in CSAO. Disabled collectors are excluded from the policy.
