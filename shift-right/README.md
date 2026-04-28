# Shift-Right — Runtime Compliance & Drift Detection

> **Phase 2** : Continuous monitoring and automated enforcement in production

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   LIVE INFRASTRUCTURE                      │
│                      (Azure)                               │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       ▼
              ┌──────────────────────┐
              │    DRIFT ENGINE       │
              │  Terraform vs. Cloud  │
              │  State Comparison     │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   OPA GATE (PDP)     │
              │  opa-drift-decision  │
              │  policies/opa/drift  │
              └──────────┬───────────┘
                         │
           ┌─────────────┴─────────────┐
           ▼                           ▼
  ┌────────────────┐    ┌─────────────────────┐
  │   DefectDojo   │    │   Cloud Custodian   │
  │   (Findings)   │    │   Remediation       │
  └────────────────┘    └─────────────────────┘
```

## Components

### 1. Drift Engine
- **Type**: IaC vs. live state comparison
- **Method**: `terraform plan` output parsed against cloud reality via Azure API
- **Detects**: Manual console changes, out-of-band CLI modifications, untracked config
- **Location**: `shift-right/drift-engine/`

### 2. OPA Gate (Policy Decision Point)
- **Role**: Sole policy enforcement point for Drift signals
- **Drift path**: `policies/opa/drift/` — Terraform drift violations
- **Exceptions**: Loaded from DefectDojo risk acceptances at pipeline runtime
- **Output**: `allow/deny` decision + dotenv for downstream jobs

### 3. Cloud Custodian
- **Type**: Policy engine + graduated remediation
- **Trigger**: OPA drift gate signals actionable violations
- **Actions**: Notify → Tag → Isolate → Auto-remediate
- **Policies**: `policies/custodian/azure/`

### 4. Prowler (Local Runtime Posture)
- **Type**: Cloud posture & compliance scan on deployed Azure subscription
- **Mode**: Local only (not wired into CI gate yet)
- **Auth**: Azure CLI session or Service Principal env vars
- **Entry point**: `shift-right/prowler/run-prowler-azure.sh`

## File Structure

```
shift-right/
├── drift-engine/               # Python drift detection engine (containerised)
├── prowler/                    # Local Azure posture scan wrapper
│
└── scripts/
    └── fetch_drift_exceptions.py      # Drift exception fetch from DefectDojo
```

## Local Runtime Scan (Prowler)

```bash
make prowler-azure-local
```

See: [./prowler/README.md](./prowler/README.md)

## CI Pipeline Stages

```
drift     drift-detect             — Terraform drift detection
decide    opa-drift-decision        — OPA gate for drift findings
report    upload-drift-to-defectdojo
remediate enforce-shift-right       — Triggered by OPA drift block signal
```

## Key Design Points

- **OPA is the sole policy decision point** for Drift signals —
  no compliance signal bypasses it.
- **Exceptions are dynamic**: fetched from DefectDojo risk acceptances at pipeline
  runtime, not hardcoded in YAML.
- **Severity filter is intentional**: Info and Low findings are excluded at scan
  time to keep DefectDojo signal-to-noise ratio high.

## Related Documentation

- [../policies/opa/README.md](../policies/opa/README.md) — OPA policy architecture
- [../policies/custodian/README.md](../policies/custodian/README.md) — Custodian policies
- [../ci/pipelines/shift-right-drift.yml](../ci/pipelines/shift-right-drift.yml) — Pipeline definition
