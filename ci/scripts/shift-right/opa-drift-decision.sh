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

# --- Colors & Formatting ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
log_info()   { echo -e "${BLUE}[OPA-DRIFT]${NC} ${DIM}INFO${NC}  $*"; }
log_ok()     { echo -e "${GREEN}[OPA-DRIFT]${NC} ${BOLD}OK${NC}    $*"; }
log_warn()   { echo -e "${YELLOW}[OPA-DRIFT]${NC} ${BOLD}WARN${NC}  $*" >&2; }
log_err()    { echo -e "${RED}[OPA-DRIFT]${NC} ${BOLD}ERROR${NC} $*" >&2; }

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
OPA_DRIFT_POLICY_DIR="${OPA_DRIFT_POLICY_DIR:-policies/opa/drift}"
OPA_SYSTEM_AUTHZ_FILE="${OPA_SYSTEM_AUTHZ_FILE:-policies/opa/system/authz.rego}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export OPA_AUTH_TOKEN

ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"
REPO_PATH="${CI_PROJECT_PATH:-unknown}"
BRANCH_NAME="${CI_COMMIT_REF_NAME:-unknown}"
COMMIT_SHA="$(echo "${CI_COMMIT_SHA:-unknown}" | cut -c1-8)"

mkdir -p "$OUTPUT_DIR"

if [[ ! -f "$REPORT_PATH" ]]; then
  log_err "Drift report not found: $REPORT_PATH"
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

log_header "CloudSentinel — OPA Drift Gate"
log_info "Mode        : --enforce (shift-right)"
log_info "Environment : ${ENVIRONMENT}"
log_info "Commit      : ${COMMIT_SHA} (${BRANCH_NAME})"
log_info "Repo        : ${REPO_PATH}"
log_info "Policy dir   : ${REPO_ROOT}/${OPA_DRIFT_POLICY_DIR}"
log_info "Exceptions  : ${EXCEPTIONS_FILE}"
log_info "Engine      : OPA Server ${OPA_SERVER_URL} [REST API]"
log_info "Input       : ${REPORT_PATH}"

opa run --server --addr="${OPA_SERVER_ADDR}" \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  "${OPA_DRIFT_POLICY_DIR}" \
  "${OPA_SYSTEM_AUTHZ_FILE}" \
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
    log_ok "OPA server is UP on ${OPA_SERVER_URL}"
    break
  fi
  echo "[opa-drift] Waiting for OPA... (${i}/15)"
  if [[ "$i" -eq 15 ]]; then
    log_err "OPA server failed to start. See ${OPA_LOG_FILE}"
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

log_info "State       : MODE=${mode} FAIL_CLOSED=${CLOUDSENTINEL_FAIL_CLOSED:-true}"

jq -c \
  --arg environment "${ENVIRONMENT}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repo "${REPO_PATH}" \
  --arg branch "${BRANCH_NAME}" \
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
EFFECTIVE_CRITICAL="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select((.severity // "") == "CRITICAL")] | length' "$DECISION_FILE")"
EFFECTIVE_HIGH="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select((.severity // "") == "HIGH")] | length' "$DECISION_FILE")"
EFFECTIVE_MEDIUM="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select((.severity // "") == "MEDIUM")] | length' "$DECISION_FILE")"
EFFECTIVE_LOW="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select((.severity // "") == "LOW")] | length' "$DECISION_FILE")"
TOTAL_EXCEPTIONS_LOADED="$(jq -r '(.result.drift_exception_summary.total_exceptions_loaded // 0)' "$DECISION_FILE")"
VALID_EXCEPTIONS="$(jq -r '(.result.drift_exception_summary.valid_exceptions // 0)' "$DECISION_FILE")"
OPA_CUSTODIAN_POLICIES="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select(.action_required != "none" and .custodian_policy != null) | .custodian_policy] | unique | join(",")' "$DECISION_FILE")"
FAIL_CLOSED="${CLOUDSENTINEL_FAIL_CLOSED:-true}"

log_header "Decision Report"
printf "  %-14s : %s\n" "Environment" "$ENVIRONMENT"
printf "  %-14s : %s\n" "OPA Engine" "server"
printf "  %-14s : %s\n" "Mode" "$mode"
echo ""
printf "  ${BOLD}%-26s %s${NC}\n" "Severity" "Effective (post-exception)"
printf "  ${RED}%-26s %s${NC}\n" "CRITICAL" "$EFFECTIVE_CRITICAL"
printf "  ${YELLOW}%-26s %s${NC}\n" "HIGH" "$EFFECTIVE_HIGH"
printf "  %-26s %s\n" "MEDIUM" "$EFFECTIVE_MEDIUM"
printf "  %-26s %s\n" "LOW" "$EFFECTIVE_LOW"
echo "  ──────────────────────────────"
printf "  %-26s %s\n" "Raw violations" "$RAW_VIOLATIONS"
printf "  %-26s %s\n" "Effective violations" "$EFFECTIVE_VIOLATIONS"
printf "  %-26s %s\n" "Actionable violations" "$ACTIONABLE_EFFECTIVE_VIOLATIONS"
printf "  %-26s %s\n" "Excepted violations" "$EXCEPTED_VIOLATIONS"
echo ""
printf "  ${DIM}%-26s %s${NC}\n" "Exceptions loaded" "$TOTAL_EXCEPTIONS_LOADED"
printf "  ${DIM}%-26s %s${NC}\n" "Valid exceptions" "$VALID_EXCEPTIONS"
if [[ -n "$OPA_CUSTODIAN_POLICIES" ]]; then
  printf "  ${DIM}%-26s %s${NC}\n" "Custodian policies" "$OPA_CUSTODIAN_POLICIES"
fi

if [[ "$DENY_COUNT" -gt 0 ]] || [[ "$ACTIONABLE_EFFECTIVE_VIOLATIONS" -gt 0 ]]; then
  OPA_DRIFT_BLOCK=true
else
  OPA_DRIFT_BLOCK=false
fi

if [[ "$DENY_COUNT" -gt 0 ]]; then
  OPA_DRIFT_DENY=true
else
  OPA_DRIFT_DENY=false
fi

{
  echo "OPA_DRIFT_BLOCK=${OPA_DRIFT_BLOCK}"
  echo "OPA_DRIFT_DENY=${OPA_DRIFT_DENY}"
  echo "OPA_DENY_COUNT=${DENY_COUNT}"
  echo "OPA_DECISION_MODE=${mode}"
  echo "OPA_FAIL_CLOSED=${FAIL_CLOSED}"
  echo "OPA_RAW_VIOLATIONS=${RAW_VIOLATIONS}"
  echo "OPA_EFFECTIVE_VIOLATIONS=${EFFECTIVE_VIOLATIONS}"
  echo "OPA_ACTIONABLE_EFFECTIVE_VIOLATIONS=${ACTIONABLE_EFFECTIVE_VIOLATIONS}"
  echo "OPA_EXCEPTED_VIOLATIONS=${EXCEPTED_VIOLATIONS}"
  echo "OPA_CUSTODIAN_POLICIES=${OPA_CUSTODIAN_POLICIES}"
} > "$ENV_FILE"

if [[ "$DENY_COUNT" -gt 0 ]]; then
  echo ""
  log_err "OPA explicit DENY triggered (Zero Trust / Degraded mode)."
  jq -r '
    (.result.deny // [])
    | to_entries[]
    | "  [" + ((.key + 1) | tostring) + "] "
      + (
          if (.value | type) == "object"
          then ((.value.code // "DENY") + ": " + (.value.message // ((.value | tostring))))
          else (.value | tostring)
          end
        )
  ' "$DECISION_FILE" >&2
  log_info "Artifacts   : decision=${DECISION_FILE} env=${ENV_FILE}"
  if [[ "${FAIL_CLOSED}" == "true" ]]; then
    exit 1
  fi
  log_warn "Deny detected but CLOUDSENTINEL_FAIL_CLOSED=false — continuing."
fi

if [[ "$OPA_DRIFT_BLOCK" == "true" ]]; then
  log_warn "Remediation Gate: BLOCK (actionable drift violations detected)."
else
  log_ok "Remediation Gate: ALLOW (no actionable effective drift violations)."
fi
log_info "Artifacts   : decision=${DECISION_FILE} env=${ENV_FILE}"
