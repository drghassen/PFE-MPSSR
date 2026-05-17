#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel Pre-Commit (Advisory)
# - Runs Gitleaks on staged files
# - Builds a golden report (fast, no extra scanners executed)
# - Runs OPA in advisory mode by default (server preferred, CLI fallback)
# - Can run OPA in local enforcement mode with CLOUDSENTINEL_PRECOMMIT_MODE=enforce
# ==============================================================================

log()  { echo "[CloudSentinel][pre-commit] $*"; }
warn() { echo "[CloudSentinel][pre-commit][WARN] $*" >&2; }
json_get_or() {
  local file=$1
  local filter=$2
  local fallback=$3
  jq -r "$filter" "$file" 2>/dev/null || echo "$fallback"
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

GITLEAKS_RUNNER="${REPO_ROOT}/shift-left/gitleaks/run-gitleaks.sh"
GITLEAKS_REPORT="${REPO_ROOT}/.cloudsentinel/gitleaks_raw.json"
GOLDEN_REPORT="${REPO_ROOT}/.cloudsentinel/golden_report.json"
NORMALIZER_SH="${REPO_ROOT}/shift-left/normalizer/normalize.sh"
NORMALIZER_PY="${REPO_ROOT}/shift-left/normalizer/normalize.py"
OPA_RUNNER="${REPO_ROOT}/shift-left/opa/run-opa.sh"
OPA_DECISION_FILE="${REPO_ROOT}/.cloudsentinel/opa_decision_precommit.json"

PRECOMMIT_MODE="${CLOUDSENTINEL_PRECOMMIT_MODE:-advisory}"
PRECOMMIT_SCAN_SCOPE="${CLOUDSENTINEL_PRECOMMIT_SCAN_SCOPE:-staged}"
if [[ "${PRECOMMIT_ENFORCE:-false}" == "true" ]]; then
  PRECOMMIT_MODE="enforce"
fi

case "$PRECOMMIT_MODE" in
  advisory) OPA_ARG="--advisory" ;;
  enforce)  OPA_ARG="--enforce" ;;
  *)
    warn "Unknown CLOUDSENTINEL_PRECOMMIT_MODE=${PRECOMMIT_MODE}. Falling back to advisory."
    PRECOMMIT_MODE="advisory"
    OPA_ARG="--advisory"
    ;;
esac

case "$PRECOMMIT_SCAN_SCOPE" in
  staged) ;;
  staged_history|staged+history|all) PRECOMMIT_SCAN_SCOPE="staged_history" ;;
  *)
    warn "Unknown CLOUDSENTINEL_PRECOMMIT_SCAN_SCOPE=${PRECOMMIT_SCAN_SCOPE}. Falling back to staged."
    PRECOMMIT_SCAN_SCOPE="staged"
    ;;
esac

log "Running checks (mode=${PRECOMMIT_MODE}, scan_scope=${PRECOMMIT_SCAN_SCOPE})..."

STAGED_FILES="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "$STAGED_FILES" ]]; then
  log "No staged files detected. Skipping advisory scanners."
  exit 0
fi
STAGED_COUNT="$(printf '%s\n' "$STAGED_FILES" | sed '/^$/d' | wc -l | tr -d ' ')"
log "Staged files detected: ${STAGED_COUNT}"

# 1) Gitleaks (staged files)
if [[ -f "$GITLEAKS_RUNNER" ]]; then
  set +e
  (
    unset CI
    USE_BASELINE="true" \
      SCAN_TARGET="$PRECOMMIT_SCAN_SCOPE" \
      SCAN_MODE="local" \
      bash "$GITLEAKS_RUNNER"
  )
  GITLEAKS_RC=$?
  set -e

  if [[ "$GITLEAKS_RC" -ne 0 ]]; then
    warn "Gitleaks runner returned rc=${GITLEAKS_RC}."
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit "$GITLEAKS_RC"
    fi
  fi

  if [[ -f "$GITLEAKS_REPORT" ]]; then
    GITLEAKS_TOTAL="$(json_get_or "$GITLEAKS_REPORT" 'length' 0)"
    log "Gitleaks raw findings: ${GITLEAKS_TOTAL}"
    if [[ "$GITLEAKS_TOTAL" -gt 0 ]]; then
      warn "Gitleaks detected $GITLEAKS_TOTAL finding(s) locally."
    fi
  else
    warn "Gitleaks report missing: ${GITLEAKS_REPORT}"
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit 2
    fi
  fi
else
  warn "Gitleaks runner not found: ${GITLEAKS_RUNNER}"
  if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
    exit 2
  fi
fi

# 2) Build golden report (fast, uses existing scanner outputs if any)
if [[ -f "$NORMALIZER_SH" ]]; then
  if ! CLOUDSENTINEL_EXECUTION_MODE="advisory" CLOUDSENTINEL_LOCAL_FAST="true" bash "$NORMALIZER_SH"; then
    warn "Normalizer failed. Skipping OPA advisory."
    log "Pre-commit completed."
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit 2
    fi
    exit 0
  fi
elif [[ -f "$NORMALIZER_PY" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    warn "Normalizer python entrypoint found but python3 is missing: ${NORMALIZER_PY}"
    log "Pre-commit completed."
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit 2
    fi
    exit 0
  fi

  if ! CLOUDSENTINEL_EXECUTION_MODE="advisory" CLOUDSENTINEL_LOCAL_FAST="true" python3 "$NORMALIZER_PY"; then
    warn "Normalizer failed. Skipping OPA advisory."
    log "Pre-commit completed."
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit 2
    fi
    exit 0
  fi
else
  warn "Normalizer not found: ${NORMALIZER_SH} or ${NORMALIZER_PY}"
  log "Pre-commit completed."
  if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
    exit 2
  fi
  exit 0
fi

if [[ -f "$GOLDEN_REPORT" ]]; then
  NORM_TOTAL="$(json_get_or "$GOLDEN_REPORT" '.summary.by_tool.gitleaks.TOTAL // 0' 0)"
  NORM_FAILED="$(json_get_or "$GOLDEN_REPORT" '.summary.by_tool.gitleaks.FAILED // 0' 0)"
  NORM_CRITICAL="$(json_get_or "$GOLDEN_REPORT" '.summary.by_tool.gitleaks.CRITICAL // 0' 0)"
  NORM_HIGH="$(json_get_or "$GOLDEN_REPORT" '.summary.by_tool.gitleaks.HIGH // 0' 0)"
  log "Gitleaks normalized summary: total=${NORM_TOTAL}, failed=${NORM_FAILED}, critical=${NORM_CRITICAL}, high=${NORM_HIGH}"
fi

# 3) OPA advisory (server preferred, CLI fallback)
if [[ "${OPA_LOCAL_ADVISORY:-true}" != "true" ]]; then
  log "OPA local advisory disabled (OPA_LOCAL_ADVISORY=${OPA_LOCAL_ADVISORY:-true})."
elif [[ -f "$OPA_RUNNER" ]]; then
  OPA_LOCAL_MODE="${OPA_LOCAL_MODE:-auto}"  # auto | cli
  case "$OPA_LOCAL_MODE" in
    auto) OPA_LOCAL_PREFER_CLI="false" ;;
    cli)  OPA_LOCAL_PREFER_CLI="true" ;;
    *)
      warn "Unknown OPA_LOCAL_MODE=${OPA_LOCAL_MODE}. Falling back to auto."
      OPA_LOCAL_PREFER_CLI="false"
      ;;
  esac

  set +e
  CLOUDSENTINEL_EXECUTION_MODE="advisory" \
    OPA_PREFER_CLI="$OPA_LOCAL_PREFER_CLI" \
    OPA_DECISION_FILE="$OPA_DECISION_FILE" \
    bash "$OPA_RUNNER" "$OPA_ARG"
  RC=$?
  set -e

  if [[ "$RC" -ne 0 ]]; then
    warn "OPA ${PRECOMMIT_MODE} failed or denied the commit (rc=${RC})."
    if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
      exit "$RC"
    fi
  elif [[ -f "$OPA_DECISION_FILE" ]]; then
    OPA_ALLOW="$(json_get_or "$OPA_DECISION_FILE" '.result.allow // false' false)"
    if [[ "$OPA_ALLOW" != "true" ]]; then
      if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
        warn "OPA decision is DENY."
        exit 1
      else
        warn "OPA advisory decision is DENY (commit still allowed locally)."
      fi
    fi
  fi
else
  warn "OPA runner not found: ${OPA_RUNNER}"
  if [[ "$PRECOMMIT_MODE" == "enforce" ]]; then
    exit 2
  fi
fi

log "Pre-commit completed (mode=${PRECOMMIT_MODE})."
exit 0
