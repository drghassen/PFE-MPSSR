#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel CI — Shift-Right OPA Prowler Decision (PEP)
#
# Evaluates Prowler CIS Azure 2.0 compliance findings through the OPA gate
# defined in policies/opa/prowler/. This script is the Policy Enforcement Point
# that was missing in the original architecture (Gap #1).
#
# Without this gate, Prowler findings went directly to DefectDojo with no
# policy decision point — bypassing the sole OPA authority defined by CloudSentinel.
#
# Inputs:
#   .cloudsentinel/prowler_generic_findings.json  (from prowler-audit artifact)
#   .cloudsentinel/prowler_exceptions.json        (from prowler-audit artifact)
#
# Outputs:
#   .cloudsentinel/opa_prowler_decision.json
#   .cloudsentinel/prowler_opa_input.json
#   .cloudsentinel/opa_prowler.env  (dotenv for downstream jobs)
#   .cloudsentinel/opa_prowler_server.log
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
log_info()   { echo -e "${BLUE}[OPA-PROWLER]${NC} ${DIM}INFO${NC}  $*"; }
log_ok()     { echo -e "${GREEN}[OPA-PROWLER]${NC} ${BOLD}OK${NC}    $*"; }
log_warn()   { echo -e "${YELLOW}[OPA-PROWLER]${NC} ${BOLD}WARN${NC}  $*" >&2; }
log_err()    { echo -e "${RED}[OPA-PROWLER]${NC} ${BOLD}ERROR${NC} $*" >&2; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

FINDINGS_FILE="${PROWLER_FINDINGS_PATH:-.cloudsentinel/prowler_generic_findings.json}"
OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
DECISION_FILE="${OUTPUT_DIR}/opa_prowler_decision.json"
INPUT_FILE="${OUTPUT_DIR}/prowler_opa_input.json"
ENV_FILE="${OUTPUT_DIR}/opa_prowler.env"
OPA_LOG_FILE="${OUTPUT_DIR}/opa_prowler_server.log"
EXCEPTIONS_FILE="${OUTPUT_DIR}/prowler_exceptions.json"

# Use a different port from opa-drift-decision.sh (8282) so both jobs can
# coexist in the same CI runner without port conflicts (they run separately
# but share the same host network namespace on some runner configurations).
OPA_SERVER_ADDR="${OPA_PROWLER_SERVER_ADDR:-127.0.0.1:8383}"
OPA_SERVER_URL="http://${OPA_SERVER_ADDR}"
OPA_PROWLER_POLICY_DIR="${OPA_PROWLER_POLICY_DIR:-policies/opa/prowler}"
OPA_SYSTEM_AUTHZ_FILE="${OPA_SYSTEM_AUTHZ_FILE:-policies/opa/system/authz.rego}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export OPA_AUTH_TOKEN

ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"

mkdir -p "$OUTPUT_DIR"

if [[ ! -f "$FINDINGS_FILE" ]]; then
  log_err "Findings file not found: $FINDINGS_FILE"
  log_err "Did prowler-audit artifact upload succeed?"
  exit 2
fi

# ── DEGRADED mode ──────────────────────────────────────────────────────────────
# Prowler couldn't scan (auth failure, network error). Findings are empty.
# OPA allows (no violations to evaluate) and sets DEGRADED=true in the env file
# so downstream jobs can detect this state. The upload job will use
# close_old_findings=false to preserve existing DefectDojo compliance history.
DEGRADED_MODE="$(jq -r '.meta.mode // "NORMAL"' "$FINDINGS_FILE")"
if [[ "${DEGRADED_MODE}" == "DEGRADED" ]]; then
  DEGRADED_REASON="$(jq -r '.meta.reason // "unknown"' "$FINDINGS_FILE")"
  log_warn "Prowler findings are DEGRADED (reason: ${DEGRADED_REASON})."
  log_warn "OPA gate skipped — allowing pipeline to continue; close_old_findings=false will protect DefectDojo history."
  jq -n \
    --arg reason "$DEGRADED_REASON" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      "allow": true, "deny": [],
      "violations": [], "effective_violations": [], "actionable_violations": [],
      "metrics": {"total":0,"effective":0,"actionable":0,"critical":0,"high":0,"medium":0,"low":0},
      "meta": {"mode":"DEGRADED","reason":$reason,"timestamp":$ts}
    }' > "$DECISION_FILE"
  {
    echo "OPA_PROWLER_BLOCK=false"
    echo "OPA_PROWLER_VIOLATIONS=0"
    echo "OPA_PROWLER_EFFECTIVE_VIOLATIONS=0"
    echo "OPA_PROWLER_ACTIONABLE_VIOLATIONS=0"
    echo "OPA_PROWLER_CRITICAL=0"
    echo "OPA_PROWLER_HIGH=0"
    echo "OPA_PROWLER_DEGRADED=true"
  } > "$ENV_FILE"
  exit 0
fi

# ── Bootstrap exceptions file if absent ────────────────────────────────────────
if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
  log_warn "No prowler exceptions file found — OPA will use empty exception set."
  jq -n '{"cloudsentinel":{"prowler_exceptions":{"exceptions":[]}}}' > "$EXCEPTIONS_FILE"
fi

# ── OPA auth config (shared token pattern from opa-drift-decision.sh) ──────────
cat > "${OUTPUT_DIR}/opa_prowler_auth_config.json" <<EOF
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF

log_header "CloudSentinel — OPA Prowler Gate"
log_info "Mode        : --enforce (shift-right)"
log_info "Environment : ${ENVIRONMENT}"
log_info "Policy dir  : ${REPO_ROOT}/${OPA_PROWLER_POLICY_DIR}"
log_info "Exceptions  : ${EXCEPTIONS_FILE}"
log_info "Engine      : OPA Server ${OPA_SERVER_URL} [REST API]"
log_info "Findings    : ${FINDINGS_FILE}"

opa run --server --addr="${OPA_SERVER_ADDR}" \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  "${OPA_PROWLER_POLICY_DIR}" \
  "${OPA_SYSTEM_AUTHZ_FILE}" \
  "${EXCEPTIONS_FILE}" \
  "${OUTPUT_DIR}/opa_prowler_auth_config.json" \
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
  echo "[opa-prowler] Waiting for OPA... (${i}/15)"
  if [[ "$i" -eq 15 ]]; then
    log_err "OPA server failed to start. See ${OPA_LOG_FILE}"
    exit 2
  fi
  sleep 2
done

# ── Build OPA input from Prowler Generic Findings ──────────────────────────────
jq -c \
  --arg environment "${ENVIRONMENT}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    input: {
      source:    "prowler",
      scan_type: "shift-right-prowler",
      timestamp: $timestamp,
      environment: $environment,
      findings: (.findings // [])
    }
  }' "$FINDINGS_FILE" > "$INPUT_FILE"

curl -sS -f -X POST \
  "${OPA_SERVER_URL}/v1/data/cloudsentinel/shiftright/prowler/decision" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPA_AUTH_TOKEN}" \
  -d @"${INPUT_FILE}" \
  > "$DECISION_FILE"

TOTAL="$(jq -r '(.result.metrics.total // 0)'            "$DECISION_FILE")"
EFFECTIVE="$(jq -r '(.result.metrics.effective // 0)'    "$DECISION_FILE")"
ACTIONABLE="$(jq -r '(.result.metrics.actionable // 0)'  "$DECISION_FILE")"
CRITICAL="$(jq -r '(.result.metrics.critical // 0)'      "$DECISION_FILE")"
HIGH="$(jq -r '(.result.metrics.high // 0)'              "$DECISION_FILE")"
MEDIUM="$(jq -r '(.result.metrics.medium // 0)'          "$DECISION_FILE")"
LOW="$(jq -r '(.result.metrics.low // 0)'                "$DECISION_FILE")"
DENY_COUNT="$(jq -r '(.result.deny // []) | length'      "$DECISION_FILE")"

log_header "Prowler OPA Decision"
printf "  %-26s : %s\n" "Environment" "$ENVIRONMENT"
echo ""
printf "  ${BOLD}%-26s %s${NC}\n" "Severity" "Effective (post-exception)"
printf "  ${RED}%-26s %s${NC}\n"    "CRITICAL" "$CRITICAL"
printf "  ${YELLOW}%-26s %s${NC}\n" "HIGH"     "$HIGH"
printf "  %-26s %s\n" "MEDIUM" "$MEDIUM"
printf "  %-26s %s\n" "LOW"    "$LOW"
echo "  ──────────────────────────────"
printf "  %-26s %s\n" "Total findings"       "$TOTAL"
printf "  %-26s %s\n" "Effective violations" "$EFFECTIVE"
printf "  %-26s %s\n" "Actionable violations" "$ACTIONABLE"

if [[ "$DENY_COUNT" -gt 0 ]]; then
  echo ""
  log_err "OPA explicit DENY:"
  jq -r '
    (.result.deny // [])
    | to_entries[]
    | "  [" + ((.key + 1) | tostring) + "] "
      + (if (.value | type) == "object"
         then ((.value.code // "DENY") + ": " + (.value.message // (.value | tostring)))
         else (.value | tostring)
         end)
  ' "$DECISION_FILE" >&2
fi

if [[ "$ACTIONABLE" -gt 0 ]]; then
  OPA_PROWLER_BLOCK=true
  log_warn "Prowler Gate: BLOCK — actionable compliance violations detected."
  log_warn "Findings are uploaded to DefectDojo for tracking."
  log_warn "Remediation is observational in this release (see Gap #5 — custodian not wired to Prowler)."
else
  OPA_PROWLER_BLOCK=false
  log_ok "Prowler Gate: ALLOW — no actionable effective violations."
fi

{
  echo "OPA_PROWLER_BLOCK=${OPA_PROWLER_BLOCK}"
  echo "OPA_PROWLER_VIOLATIONS=${TOTAL}"
  echo "OPA_PROWLER_EFFECTIVE_VIOLATIONS=${EFFECTIVE}"
  echo "OPA_PROWLER_ACTIONABLE_VIOLATIONS=${ACTIONABLE}"
  echo "OPA_PROWLER_CRITICAL=${CRITICAL}"
  echo "OPA_PROWLER_HIGH=${HIGH}"
  echo "OPA_PROWLER_DEGRADED=false"
} > "$ENV_FILE"

log_info "Artifacts: decision=${DECISION_FILE} env=${ENV_FILE}"
