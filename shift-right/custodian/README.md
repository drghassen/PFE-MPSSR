# Cloud Custodian Runtime Remediation

Cloud Custodian is used as the runtime executor in Shift-Right.

## Contract with OPA

- OPA drift decision outputs `custodian_policy` per violation.
- `ci/scripts/shift-right/custodian-autofix.sh` builds its execution plan from `.cloudsentinel/opa_drift_decision.json`.
- Only `effective_violations` with `remediation_level == "L3"`, `requires_remediation == true`, a non-empty `custodian_policy`, and a concrete Azure ARM `resource_id` are executable.
- Every Custodian run uses a generated policy scoped with a `value` filter on that exact `resource_id`; broad policy execution is refused.
- `custodian validate` runs before remediation. Validation failure aborts the whole Custodian stage before any resource is changed.
- Runtime observability is written to `.cloudsentinel/remediation_metrics.json` with `remediated`, `failed`, `ignored`, and `verified` counters.
- Prowler decisions never dispatch Custodian policies (ticket/alert only).
- `OPA_CUSTODIAN_POLICIES` remains an audit/dotenv summary, not the execution authority.

This enforces L3-only auto-remediation from Drift Engine only.

## Current L3 Policy Map

1. `enforce-nsg-no-open-inbound`
2. `enforce-nsg-rule-deny-all`
3. `deny-public-storage`
4. `enforce-storage-tls`
5. `enforce-storage-container-private`
6. `enforce-sql-no-public-network`

### SQL runtime mode (`enforce-sql-no-public-network`)

- Runtime remediation removes SQL server firewall exposure (server firewall rules = 0).
- `publicNetworkAccess` may remain `Enabled` in this mode.
- Strict private-only enforcement (`publicNetworkAccess=Disabled`) stays an external governance control.

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
