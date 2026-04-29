# Shift-Right Runtime Security

This phase monitors deployed Azure infrastructure, evaluates risk with OPA, and fans out to audit, notification, and remediation.

## Runtime Flow

1. Sensors:
- Drift Engine (Terraform state vs live cloud state)
- Prowler (runtime cloud posture checks)

2. Decision engine:
- OPA evaluates every finding and returns severity + response type + remediation requirement.

3. Fan-out (parallel):
- DefectDojo receives all findings (Info/Low/Medium/High/Critical).
- Notification pipeline raises critical alerts.
- Cloud Custodian executes only CRITICAL auto-remediation policies.

4. Durable fix:
- Teams fix Terraform source.
- `terraform apply` removes drift permanently.
- Reconciliation ticket is mandatory for CRITICAL runtime fixes.

## Severity Routing

- `CRITICAL` -> `runtime_remediation` (Custodian + alert + DefectDojo + reconciliation ticket)
- `HIGH` -> `ticket_and_notify` (no auto-fix)
- `MEDIUM` -> `ticket_and_notify` (no auto-fix)
- `LOW` -> `notify` (no auto-fix)
- `INFO` -> `none`

## Design Rules

- OPA is policy decision only.
- Custodian is execution only.
- DefectDojo is audit trail only.
- Auto-remediation scope is intentionally `CRITICAL_ONLY`.
- Correlation is end-to-end through `correlation_id`.

## Key Paths

- Drift engine: `shift-right/drift-engine/`
- Prowler runner: `shift-right/prowler/`
- OPA policies: `policies/opa/drift/`, `policies/opa/prowler/`
- Custodian policies: `shift-right/custodian/policies/`
- CI pipeline: `ci/pipelines/shift-right-drift.yml`
