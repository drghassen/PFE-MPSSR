#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel - OPA Quality Gate (Policy Enforcement Point)
#
# Architecture Role:
#   This script is the PEP (Policy Enforcement Point).
#   OPA is the PDP (Policy Decision Point).
#
#   PEP  →  golden_report.json  →  PDP (OPA)  →  decision (allow/deny)
#   (here)                         (opa server or opa eval CLI)
#
# Invocation Modes:
#   --advisory  : Evaluate and display. Always exits 0. Use locally / pre-commit.
#   --enforce   : Evaluate and block.   Exits 1 on deny.   Use in CI/CD pipelines.
#
# OPA Engine Selection (automatic fallback):
#   1. OPA Server REST API  : POST ${OPA_SERVER_URL}/v1/data/cloudsentinel/gate/decision
#   2. OPA CLI fallback     : opa eval --input --data ...
#   Use OPA_PREFER_CLI=true to force CLI mode.
#
# Environment Variables:
#   OPA_SERVER_URL      : OPA server URL (default: http://localhost:8181)
#   OPA_EXCEPTIONS_FILE : Override path to exceptions.json (for testing)
#   OPA_DECISION_FILE   : Override path for saved decision output
#   OPA_PREFER_CLI      : Force CLI evaluation even if server is reachable
#
# Usage:
#   bash shift-left/opa/run-opa.sh --advisory   # local, always passes
#   bash shift-left/opa/run-opa.sh --enforce    # CI mode, blocks on deny
#   OPA_SERVER_URL=http://opa:8181 bash shift-left/opa/run-opa.sh --enforce
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

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# --- Paths (all overridable via env) ---
GOLDEN_REPORT="${REPO_ROOT}/.cloudsentinel/golden_report.json"
POLICY_FILE="${REPO_ROOT}/policies/opa/pipeline_decision.rego"
EXCEPTIONS_FILE="${OPA_EXCEPTIONS_FILE:-${REPO_ROOT}/policies/opa/exceptions.json}"
OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
DECISION_FILE="${OPA_DECISION_FILE:-${OUTPUT_DIR}/opa_decision.json}"

OPA_SERVER_URL="${OPA_SERVER_URL:-http://localhost:8181}"
OPA_API_PATH="/v1/data/cloudsentinel/gate/decision"
OPA_QUERY="data.cloudsentinel.gate.decision"
OPA_PREFER_CLI="${OPA_PREFER_CLI:-false}"

# --- Mode ---
MODE="${1:---enforce}"
if [[ "$MODE" != "--advisory" && "$MODE" != "--enforce" ]]; then
  echo -e "${RED}Usage:${NC} $0 [--advisory|--enforce]" >&2
  echo -e "  ${DIM}--advisory : evaluate, warn only, always exit 0${NC}" >&2
  echo -e "  ${DIM}--enforce  : evaluate, block on deny, exit 1${NC}" >&2
  exit 1
fi

# --- Logging ---
log_header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
log_info()   { echo -e "${BLUE}[OPA]${NC} ${DIM}INFO${NC}  $*"; }
log_ok()     { echo -e "${GREEN}[OPA]${NC} ${BOLD}ALLOW${NC} $*"; }
log_warn()   { echo -e "${YELLOW}[OPA]${NC} ${BOLD}WARN${NC}  $*" >&2; }
log_deny()   { echo -e "${RED}[OPA]${NC} ${BOLD}DENY${NC}  $*"; }
log_err()    { echo -e "${RED}[OPA]${NC} ${BOLD}ERROR${NC} $*" >&2; }

# --- Prerequisites ---
command -v jq >/dev/null 2>&1 || { log_err "jq is required. Install with: apt-get install jq"; exit 2; }

[[ -f "$GOLDEN_REPORT" ]] || {
  log_err "Golden report not found: ${GOLDEN_REPORT}"
  log_err "Run first: bash shift-left/normalizer/normalize.sh"
  exit 2
}

[[ -f "$POLICY_FILE" ]] || { log_err "Policy not found: ${POLICY_FILE}"; exit 2; }
[[ -f "$EXCEPTIONS_FILE" ]] || { log_err "Exceptions not found: ${EXCEPTIONS_FILE}"; exit 2; }

mkdir -p "$OUTPUT_DIR"

# ==============================================================================
# OPA Invocation — Server (preferred) → CLI (fallback)
# ==============================================================================

# Strategy 1: OPA Server (REST API)
# Production pattern: OPA runs as a persistent daemon, policies hot-reloaded.
# Decouples the CI pipeline from policy evaluation logic.
invoke_opa_server() {
  local input_json
  # Inline the golden_report as the OPA input document
  input_json="$(jq -c '.' "$GOLDEN_REPORT")"

  # OPA v1 REST API:
  #   POST /v1/data/<package>/<rule>
  #   Body: { "input": <input_document> }
  #   Response: { "result": <rule_value> }
  curl -sf \
    --max-time 5 \
    --connect-timeout 2 \
    -X POST "${OPA_SERVER_URL}${OPA_API_PATH}" \
    -H "Content-Type: application/json" \
    -d "{\"input\": ${input_json}}" \
    -o "$DECISION_FILE" \
    2>/dev/null
}

# Strategy 2: OPA CLI (opa eval)
# Development / air-gapped fallback. No server needed.
# Normalizes CLI output format to match OPA REST API response shape.
invoke_opa_cli() {
  command -v opa >/dev/null 2>&1 || {
    log_err "Neither OPA Server (${OPA_SERVER_URL}) nor OPA CLI ('opa') is available."
    log_err "Start OPA: docker compose up -d opa-server"
    log_err "Or install CLI: https://www.openpolicyagent.org/docs/latest/#running-opa"
    exit 2
  }

  local tmp_raw
  local tmp_err
  tmp_raw="$(mktemp -t opa_raw.XXXXXX.json)"
  tmp_err="$(mktemp -t opa_err.XXXXXX.log)"
  trap 'rm -f "$tmp_raw" "$tmp_err"' RETURN

  if ! opa eval \
    --format json \
    --input "$GOLDEN_REPORT" \
    --data "$POLICY_FILE" \
    --data "$EXCEPTIONS_FILE" \
    "$OPA_QUERY" \
    > "$tmp_raw" 2> "$tmp_err"; then
    log_err "OPA CLI eval failed. Check policy compatibility and OPA version."
    if [[ -s "$tmp_err" ]]; then
      log_err "OPA error output:"
      sed 's/^/[opa-cli] /' "$tmp_err" >&2
    fi
    exit 2
  fi

  # OPA CLI output: {"result": [{"expressions": [{"value": {...}}]}]}
  # Normalize to match REST API shape: {"result": {...}}
  jq '{result: .result[0].expressions[0].value}' "$tmp_raw" > "$DECISION_FILE"
}

# ==============================================================================
# Execute OPA
# ==============================================================================

log_header "CloudSentinel — OPA Quality Gate"

ENVIRONMENT="$(jq -r '.metadata.environment // "unknown"' "$GOLDEN_REPORT")"
GIT_COMMIT="$(jq -r '.metadata.git.commit // "unknown"' "$GOLDEN_REPORT" | cut -c1-8)"
GIT_BRANCH="$(jq -r '.metadata.git.branch // "unknown"' "$GOLDEN_REPORT")"

log_info "Mode        : ${BOLD}${MODE}${NC}"
log_info "Environment : ${BOLD}${ENVIRONMENT}${NC}"
log_info "Commit      : ${GIT_COMMIT} (${GIT_BRANCH})"
log_info "Policy      : ${POLICY_FILE}"
log_info "Exceptions  : ${EXCEPTIONS_FILE}"
echo ""

INVOCATION_MODE=""
if [[ "${OPA_PREFER_CLI}" == "true" ]]; then
  invoke_opa_cli
  INVOCATION_MODE="cli"
  log_info "Engine      : OPA CLI ${YELLOW}[forced]${NC}"
else
  if invoke_opa_server 2>/dev/null; then
    INVOCATION_MODE="server"
    log_info "Engine      : OPA Server ${BOLD}${OPA_SERVER_URL}${NC} ${GREEN}[REST API]${NC}"
  else
    log_warn "OPA Server not reachable (${OPA_SERVER_URL}). Falling back to OPA CLI."
    invoke_opa_cli
    INVOCATION_MODE="cli"
    log_info "Engine      : OPA CLI ${YELLOW}[fallback]${NC}"
  fi
fi

if [[ ! -s "$DECISION_FILE" ]]; then
  log_err "OPA decision file not generated: ${DECISION_FILE}"
  log_err "Check OPA CLI version and policy compatibility."
  exit 2
fi

if ! jq -e '.result' "$DECISION_FILE" >/dev/null 2>&1; then
  log_err "OPA decision file is invalid or missing '.result': ${DECISION_FILE}"
  exit 2
fi

# ==============================================================================
# Parse & Display Decision
# ==============================================================================

ALLOW="$(jq -r   '.result.allow          // false'   "$DECISION_FILE")"
CRITICAL="$(jq -r '.result.metrics.critical // 0'    "$DECISION_FILE")"
HIGH="$(jq -r     '.result.metrics.high     // 0'    "$DECISION_FILE")"
MEDIUM="$(jq -r   '.result.metrics.medium   // 0'    "$DECISION_FILE")"
LOW="$(jq -r      '.result.metrics.low      // 0'    "$DECISION_FILE")"
EFFECTIVE="$(jq -r '.result.metrics.failed_effective // 0' "$DECISION_FILE")"
EXCEPTED="$(jq -r  '.result.metrics.excepted     // 0'    "$DECISION_FILE")"
APPLIED_IDS="$(jq -r '.result.exceptions.applied_ids // [] | join(", ")' "$DECISION_FILE")"
INVALID_IDS="$(jq -r '.result.exceptions.invalid_enabled_ids // [] | join(", ")' "$DECISION_FILE")"
DENY_COUNT="$(jq -r  '.result.deny // [] | length'           "$DECISION_FILE")"

log_header "Decision Report"

printf "  %-14s : %s\n" "Environment"  "${ENVIRONMENT}"
printf "  %-14s : %s\n" "OPA Engine"   "${INVOCATION_MODE}"
echo ""

# Severity table
printf "  ${BOLD}%-22s  %s${NC}\n" "Severity" "Effective (post-exception)"
printf "  ${RED}%-22s  %s${NC}\n"    "CRITICAL"             "${CRITICAL}"
printf "  ${YELLOW}%-22s  %s${NC}\n" "HIGH"                 "${HIGH}"
printf "  %-22s  %s\n"               "MEDIUM"               "${MEDIUM}"
printf "  %-22s  %s\n"               "LOW"                  "${LOW}"
echo   "  ──────────────────────────────"
printf "  %-22s  %s\n"               "Total failed"         "${EFFECTIVE}"
printf "  ${DIM}%-22s  %s${NC}\n"    "Excepted (suppressed)"  "${EXCEPTED}"

if [[ -n "$APPLIED_IDS" ]]; then
  echo ""
  printf "  ${DIM}%-22s  %s${NC}\n" "Applied exceptions" "${APPLIED_IDS}"
fi

if [[ -n "$INVALID_IDS" ]]; then
  echo ""
  printf "  ${RED}%-22s  %s${NC}\n" "INVALID exceptions" "${INVALID_IDS}"
fi

echo ""
echo "  ──────────────────────────────"

if [[ "$ALLOW" == "true" ]]; then
  log_ok "DECISION → ${BOLD}${GREEN}ALLOW ✓${NC}"
else
  log_deny "DECISION → ${BOLD}${RED}DENY ✗${NC}  (${DENY_COUNT} reason(s))"
  echo ""
  jq -r '.result.deny // [] | to_entries[] | "  [" + (.key + 1 | tostring) + "] " + .value' "$DECISION_FILE"
fi

echo ""

# ==============================================================================
# Enrich & Save Decision Artifact
# ==============================================================================

tmp_decision="$(mktemp -t opa_decision_enriched.XXXXXX.json)"
jq \
  --arg mode        "$MODE" \
  --arg engine      "$INVOCATION_MODE" \
  --arg policy_file "$POLICY_FILE" \
  --arg exc_file    "$EXCEPTIONS_FILE" \
  --arg timestamp   "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  '.result += {
    _gate: {
      mode:         $mode,
      engine:       $engine,
      policy_file:  $policy_file,
      exceptions_file: $exc_file,
      evaluated_at: $timestamp
    }
  }' \
  "$DECISION_FILE" > "$tmp_decision" \
  && mv "$tmp_decision" "$DECISION_FILE"

log_info "Decision saved : ${DECISION_FILE}"

# ==============================================================================
# Enforcement
# ==============================================================================

if [[ "$ALLOW" == "true" ]]; then
  exit 0
fi

if [[ "$MODE" == "--enforce" ]]; then
  echo ""
  log_deny "${BOLD}Pipeline BLOCKED by OPA Quality Gate.${NC}"
  log_deny "Fix violations or submit an exception request (see policies/opa/exceptions.json)."
  exit 1
else
  log_warn "Advisory mode: deny detected but pipeline continues."
  log_warn "Resolve all violations before this reaches --enforce (CI/CD)."
  exit 0
fi
