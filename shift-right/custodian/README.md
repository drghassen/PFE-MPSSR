# Cloud Custodian Runtime Remediation

Cloud Custodian is used as the runtime executor in Shift-Right.

## Contract with OPA

- OPA drift decision outputs `custodian_policy` per violation.
- `ci/scripts/shift-right/custodian-autofix.sh` runs only policies listed in `OPA_CUSTODIAN_POLICIES`.
- `OPA_CUSTODIAN_POLICIES` is populated from `effective_violations` where:
  - `requires_remediation == true`
  - `custodian_policy != null`

This enforces `CRITICAL_ONLY` auto-remediation.

## Current CRITICAL Policy Map

1. `enforce-nsg-no-open-inbound`
2. `enforce-nsg-rule-deny-all`
3. `enforce-vm-no-password-auth`
4. `enforce-sql-password-rotation`

## Operating Model

1. Detect drift/posture issue.
2. OPA decides severity/response type/risk.
3. Fan-out in parallel:
- DefectDojo finding
- Notification
- Custodian action (CRITICAL only)
4. Reconciliation ticket is created for IaC correction.
5. Team fixes Terraform and applies.

## Dry-Run

Use dry-run before live remediation:

```bash
export ARM_CLIENT_ID=...
export ARM_CLIENT_SECRET=...
export ARM_TENANT_ID=...
export ARM_SUBSCRIPTION_ID=...

custodian run --dryrun \
  --output-dir .cloudsentinel/custodian-output \
  --cache-period 0 \
  shift-right/custodian/policies/enforce-nsg-no-open-inbound.yml
```
