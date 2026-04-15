#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel CI - Shift-Right OPA Decision (PEP)
#
# Purpose:
#   Make the remediation decision from OPA policy output, not from drift engine
#   exit code alone.
#
# Inputs:
#   - shift-right/drift-engine/output/drift-report.json
#   - .cloudsentinel/drift_exceptions.json (optional, bootstrapped if absent)
#
# Outputs:
#   - .cloudsentinel/opa_drift_decision.json
#   - .cloudsentinel/opa_drift.env (dotenv for downstream jobs)
# ==============================================================================

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

REPORT_PATH="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
DECISION_FILE="${OUTPUT_DIR}/opa_drift_decision.json"
INPUT_FILE="${OUTPUT_DIR}/drift_opa_input.json"
ENV_FILE="${OUTPUT_DIR}/opa_drift.env"
OPA_LOG_FILE="${OUTPUT_DIR}/opa_drift_server.log"
EXCEPTIONS_FILE="${OUTPUT_DIR}/drift_exceptions.json"
OPA_SERVER_ADDR="${OPA_SERVER_ADDR:-127.0.0.1:8282}"
OPA_SERVER_URL="${OPA_SERVER_URL:-http://${OPA_SERVER_ADDR}}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export OPA_AUTH_TOKEN

mkdir -p "$OUTPUT_DIR"

if [[ ! -f "$REPORT_PATH" ]]; then
  echo "[opa-drift][ERROR] Drift report not found: $REPORT_PATH" >&2
  exit 2
fi

if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
  cat > "$EXCEPTIONS_FILE" <<'EOF'
{"cloudsentinel":{"drift_exceptions":{"schema_version":"1.0.0","generated_at":"2099-01-01T00:00:00Z","environment":"production","source":"ci-bootstrap","exceptions":[]}}}
EOF
fi

cat > "${OUTPUT_DIR}/opa_auth_config.json" <<EOF
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF

opa run --server --addr="${OPA_SERVER_ADDR}" \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  policies/opa/drift_decision.rego \
  policies/opa/system/authz.rego \
  "${EXCEPTIONS_FILE}" \
  "${OUTPUT_DIR}/opa_auth_config.json" \
  > "${OPA_LOG_FILE}" 2>&1 &
OPA_PID=$!

cleanup() {
  if kill -0 "$OPA_PID" >/dev/null 2>&1; then
    kill "$OPA_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for i in {1..15}; do
  if curl -sf "${OPA_SERVER_URL}/health" >/dev/null; then
    echo "[opa-drift] OPA server is UP on ${OPA_SERVER_URL}"
    break
  fi
  if [[ "$i" -eq 15 ]]; then
    echo "[opa-drift][ERROR] OPA server failed to start" >&2
    exit 2
  fi
  sleep 2
done

mode=$(jq -r '
  try .cloudsentinel.drift_exceptions.meta.mode
  catch "ENFORCING"
' "$EXCEPTIONS_FILE")

# Handle null/empty cases by defaulting to ENFORCING
if [[ -z "$mode" || "$mode" == "null" ]]; then
  mode="ENFORCING"
fi

echo "[CloudSentinel][STATE] MODE=$mode FAIL_CLOSED=${CLOUDSENTINEL_FAIL_CLOSED:-true}"

jq -c \
  --arg environment "${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repo "${CI_PROJECT_PATH:-unknown}" \
  --arg branch "${CI_COMMIT_REF_NAME:-unknown}" \
  --arg mode "$mode" \
  --argjson meta '{
    "allow_legacy_exceptions": true,
    "allow_degraded": false
  }' \
  --slurpfile exceptions "$EXCEPTIONS_FILE" \
  '{
     input: {
       source: "drift-engine",
       scan_type: "shift-right-drift",
       timestamp: $timestamp,
       environment: $environment,
       repo: $repo,
       branch: $branch,
       meta: ($meta + { mode: $mode }),
       findings: [
         (.drift.items // [])[] | {
           address: .address,
           type: .type,
           mode: (.mode // "managed"),
           name: (.name // ""),
           provider_name: (.provider_name // "unknown"),
           actions: (.actions // []),
           resource_id: .address,
           changed_paths: (.changed_paths // [])
         }
       ]
     }
   }' \
  "$REPORT_PATH" > "$INPUT_FILE"

curl -sS -f -X POST \
  "${OPA_SERVER_URL}/v1/data/cloudsentinel/shiftright/drift" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPA_AUTH_TOKEN}" \
  -d @"${INPUT_FILE}" \
  > "$DECISION_FILE"

DENY_COUNT="$(jq -r '(.result.deny // []) | length' "$DECISION_FILE")"
RAW_VIOLATIONS="$(jq -r '(.result.violations // []) | length' "$DECISION_FILE")"
EFFECTIVE_VIOLATIONS="$(jq -r '(.result.effective_violations // .result.violations // []) | length' "$DECISION_FILE")"
ACTIONABLE_EFFECTIVE_VIOLATIONS="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select(.action_required != "none" and .action_required != "monitor")] | length' "$DECISION_FILE")"
EXCEPTED_VIOLATIONS="$(jq -r '(.result.drift_exception_summary.excepted_violations // 0)' "$DECISION_FILE")"
OPA_CUSTODIAN_POLICIES="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select(.action_required != "none" and .custodian_policy != null) | .custodian_policy] | unique | join(",")' "$DECISION_FILE")"

if [[ "$DENY_COUNT" -gt 0 ]]; then
  echo "[opa-drift][ERROR] OPA explicit DENY triggered (Zero Trust / Degraded mode)." >&2
  jq -r '(.result.deny // [])[]' "$DECISION_FILE" >&2
  exit 1
fi

if [[ "$ACTIONABLE_EFFECTIVE_VIOLATIONS" -gt 0 ]]; then
  OPA_DRIFT_BLOCK=true
else
  OPA_DRIFT_BLOCK=false
fi

{
  echo "OPA_DRIFT_BLOCK=${OPA_DRIFT_BLOCK}"
  echo "OPA_RAW_VIOLATIONS=${RAW_VIOLATIONS}"
  echo "OPA_EFFECTIVE_VIOLATIONS=${EFFECTIVE_VIOLATIONS}"
  echo "OPA_ACTIONABLE_EFFECTIVE_VIOLATIONS=${ACTIONABLE_EFFECTIVE_VIOLATIONS}"
  echo "OPA_EXCEPTED_VIOLATIONS=${EXCEPTED_VIOLATIONS}"
  echo "OPA_CUSTODIAN_POLICIES=${OPA_CUSTODIAN_POLICIES}"
} > "$ENV_FILE"

echo "[opa-drift] raw=${RAW_VIOLATIONS} effective=${EFFECTIVE_VIOLATIONS} actionable=${ACTIONABLE_EFFECTIVE_VIOLATIONS} excepted=${EXCEPTED_VIOLATIONS} block=${OPA_DRIFT_BLOCK}"
