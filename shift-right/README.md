# Shift-Right — Runtime Compliance & Drift Detection

> **Phase 2** : Continuous monitoring and automated enforcement in production

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   LIVE INFRASTRUCTURE                      │
│                      (Azure)                               │
└──────────────────────┬─────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                        │
          ▼                        ▼
┌──────────────────┐    ┌──────────────────────┐
│  PROWLER SENSOR  │    │    DRIFT ENGINE       │
│  CIS Azure 2.0   │    │  Terraform vs. Cloud  │
│  Compliance Scan │    │  State Comparison     │
└────────┬─────────┘    └──────────┬───────────┘
         │                         │
         ▼                         ▼
┌──────────────────────────────────────────────┐
│              OPA GATE (PDP)                  │
│  opa-prowler-decision  |  opa-drift-decision │
│  policies/opa/prowler  |  policies/opa/drift │
└──────────┬──────────────────────┬────────────┘
           │                      │
           ▼                      ▼
  ┌────────────────┐    ┌─────────────────────┐
  │   DefectDojo   │    │   Cloud Custodian   │
  │   (Findings)   │    │   Remediation       │
  └────────────────┘    └─────────────────────┘
```

## Components

### 1. Prowler Sensor
- **Type**: CIS Azure 2.0 compliance audit
- **Auth**: Service principal (`ARM_CLIENT_ID/SECRET/TENANT_ID`)
- **Severity filter**: Medium, High, Critical only
- **Output**: OCSF JSON → converted to DefectDojo Generic Findings format
- **Exceptions**: Dynamic mutelist generated from DefectDojo risk acceptances
  via `fetch_prowler_exceptions.py`
- **Location**: `shift-right/prowler/`
- **Config**: `shift-right/prowler/config-azure.yaml`

### 2. Drift Engine
- **Type**: IaC vs. live state comparison
- **Method**: `terraform plan` output parsed against cloud reality via Azure API
- **Detects**: Manual console changes, out-of-band CLI modifications, untracked config
- **Location**: `shift-right/drift-engine/`

### 3. OPA Gate (Policy Decision Point)
- **Role**: Sole policy enforcement point for both Prowler and Drift signals
- **Prowler path**: `policies/opa/prowler/` — CIS compliance violations
- **Drift path**: `policies/opa/drift/` — Terraform drift violations
- **Exceptions**: Loaded from DefectDojo risk acceptances at pipeline runtime
- **Output**: `allow/deny` decision + dotenv for downstream jobs

### 4. Cloud Custodian
- **Type**: Policy engine + graduated remediation
- **Trigger**: OPA drift gate signals actionable violations
- **Actions**: Notify → Tag → Isolate → Auto-remediate
- **Note**: Prowler violations are currently observational (tracked in DefectDojo,
  not yet wired to Custodian). See `custodian-remediate` job comment in the pipeline.
- **Policies**: `policies/custodian/azure/`

## File Structure

```
shift-right/
├── prowler/
│   ├── config-azure.yaml       # Check-level parameter overrides
│   ├── run-prowler.sh          # Prowler v5 execution + OCSF→Generic Findings conversion
│   └── Dockerfile              # Custom image (prowler base + jq + curl)
│
├── drift-engine/               # Python drift detection engine (containerised)
│
└── scripts/
    └── fetch_drift_exceptions.py      # Drift exception fetch from DefectDojo
    └── fetch_prowler_exceptions.py    # Prowler exception fetch → mutelist + OPA JSON
```

## CI Pipeline Stages

```
sensor    prowler-audit            — Prowler CIS scan + exception fetch
drift     drift-detect             — Terraform drift detection
decide    opa-prowler-decision      — OPA gate for Prowler findings
          opa-drift-decision        — OPA gate for drift findings
report    upload-prowler-to-defectdojo
          upload-drift-to-defectdojo
remediate custodian-remediate      — Triggered by OPA drift block signal
```

## Usage

### Run Prowler Manually

```bash
# Ensure AZURE_* env vars are set (mapped from ARM_* by run-prowler.sh)
export ARM_CLIENT_ID=...
export ARM_CLIENT_SECRET=...
export ARM_TENANT_ID=...
export ARM_SUBSCRIPTION_ID=...
export PROWLER_OUTPUT_DIR=shift-right/prowler/output

bash shift-right/prowler/run-prowler.sh
```

### Generate Prowler Exceptions from DefectDojo

```bash
export DOJO_URL=https://defectdojo.example.com
export DOJO_API_KEY=<token>
export DOJO_ENGAGEMENT_ID_RIGHT=<id>

python shift-right/scripts/fetch_prowler_exceptions.py \
  --output-exceptions .cloudsentinel/prowler_exceptions.json \
  --output-mutelist   shift-right/prowler/mutelist-azure.yaml
```

### Run OPA Prowler Gate Locally

```bash
export OPA_AUTH_TOKEN=dev-token
opa run --server --addr=127.0.0.1:8383 \
  --authentication=token --authorization=basic \
  policies/opa/prowler \
  policies/opa/system/authz.rego \
  .cloudsentinel/prowler_exceptions.json \
  <(echo '{"opa_config":{"auth_token":"dev-token"}}')
```

## Key Design Points

- **OPA is the sole policy decision point** for both Prowler and Drift signals —
  no compliance signal bypasses it.
- **Exceptions are dynamic**: fetched from DefectDojo risk acceptances at pipeline
  runtime, not hardcoded in YAML.
- **DEGRADED mode is safe**: a Prowler auth failure writes an empty payload with
  `close_old_findings=false` so historical DefectDojo findings are preserved.
- **Severity filter is intentional**: Info and Low findings are excluded at scan
  time to keep DefectDojo signal-to-noise ratio high.

## Related Documentation

- [../policies/opa/README.md](../policies/opa/README.md) — OPA policy architecture
- [../policies/custodian/README.md](../policies/custodian/README.md) — Custodian policies
- [../ci/pipelines/shift-right-drift.yml](../ci/pipelines/shift-right-drift.yml) — Pipeline definition
