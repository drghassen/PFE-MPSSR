# Cloud Custodian Runtime Remediation

Cloud Custodian is used as the runtime executor in Shift-Right.

## Contract with OPA

- OPA drift decision outputs `custodian_policy` per violation.
- `ci/scripts/shift-right/custodian-autofix.sh` runs only policies listed in `OPA_CUSTODIAN_POLICIES`.
- Prowler decisions never dispatch Custodian policies (ticket/alert only).
- `OPA_CUSTODIAN_POLICIES` is populated from `effective_violations` where:
  - `remediation_level == "L3"`
  - `requires_remediation == true`
  - `custodian_policy != null`

This enforces L3-only auto-remediation from Drift Engine only.

## Current L3 Policy Map

1. `enforce-nsg-no-open-inbound`
2. `enforce-nsg-rule-deny-all`
3. `deny-public-storage`
4. `enforce-storage-tls`
5. `enforce-storage-container-private`

## Operating Model

1. Detect drift/posture issue.
2. OPA decides severity/response type/risk.
3. Fan-out in parallel:
- DefectDojo finding
- Notification
- Custodian action (L3 only)
4. Reconciliation ticket is created for IaC correction.
5. Team fixes Terraform and applies.

### Enterprise hybrid for NSG remediations

- Cloud Custodian NSG policies are `detect + tag` only (schema-safe on c7n-azure).
- Azure Policy `DeployIfNotExists` enforces baseline `DenyAllInbound`.
- This keeps runtime enforcement native/idempotent while preserving CloudSentinel traceability.

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
