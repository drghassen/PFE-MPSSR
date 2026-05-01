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
- Notification pipeline raises external alerts for L2/L3 findings.
- Cloud Custodian executes only L3 auto-remediation policies.

4. Durable fix:
- Teams fix Terraform source.
- `terraform apply` removes drift permanently.
- Reconciliation ticket is mandatory for L2/L3 runtime findings.

## Remediation Levels

- `L0` -> output-only INFO/LOW findings; audit trail only.
- `L1` -> LOW resource findings; audit WARN only.
- `L2` -> MEDIUM/HIGH or non-remediable CRITICAL; alert + ticket.
- `L3` -> CRITICAL with supported `custodian_policy`; alert + Custodian + verification + ticket.

## Design Rules

- OPA is policy decision only.
- Custodian is execution only.
- DefectDojo is audit trail only.
- Auto-remediation scope is intentionally limited to L3.
- Pipeline correlation is end-to-end through `pipeline_correlation_id`; engine `correlation_id` remains engine-scoped.

## Key Paths

- Drift engine: `shift-right/drift-engine/`
- Prowler runner: `shift-right/prowler/`
- OPA policies: `policies/opa/drift/`, `policies/opa/prowler/`
- Custodian policies: `shift-right/custodian/policies/`
- CI pipeline: `ci/pipelines/shift-right-drift.yml`
