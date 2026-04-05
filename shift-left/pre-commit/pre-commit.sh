#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel Pre-Commit (Advisory)
# - Runs Gitleaks on staged files
# - Builds a golden report (fast, no extra scanners executed)
# - Runs OPA in advisory mode (server preferred, CLI fallback)
# - Never blocks the commit
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
NORMALIZER_SH="${REPO_ROOT}/shift-left/normalizer/normalize.sh"
NORMALIZER_PY="${REPO_ROOT}/shift-left/normalizer/normalize.py"
OPA_RUNNER="${REPO_ROOT}/shift-left/opa/run-opa.sh"
OPA_DECISION_FILE="${REPO_ROOT}/.cloudsentinel/opa_decision_precommit.json"

log "Running advisory checks..."

if ! git diff --cached --name-only --diff-filter=ACMR | grep -q .; then
  log "No staged files detected. Skipping advisory scanners."
  exit 0
fi

# 1) Gitleaks (staged files, advisory only)
if [[ -f "$GITLEAKS_RUNNER" ]]; then
  set +e
  (
    unset CI
    USE_BASELINE="true" \
      SCAN_TARGET="staged" \
      SCAN_MODE="local" \
      bash "$GITLEAKS_RUNNER"
  )
  GITLEAKS_RC=$?
  set -e

  if [[ "$GITLEAKS_RC" -ne 0 ]]; then
    warn "Gitleaks runner returned rc=${GITLEAKS_RC}. Continuing in advisory mode."
  fi

  if [[ -f "$GITLEAKS_REPORT" ]]; then
    GITLEAKS_TOTAL="$(json_get_or "$GITLEAKS_REPORT" 'length' 0)"
    if [[ "$GITLEAKS_TOTAL" -gt 0 ]]; then
      warn "Gitleaks detected $GITLEAKS_TOTAL finding(s) locally (advisory)."
    fi
  else
    warn "Gitleaks report missing: ${GITLEAKS_REPORT}"
  fi
else
  warn "Gitleaks runner not found: ${GITLEAKS_RUNNER}"
fi

# 2) Build golden report (fast, uses existing scanner outputs if any)
if [[ -f "$NORMALIZER_SH" ]]; then
  if ! CLOUDSENTINEL_EXECUTION_MODE="advisory" CLOUDSENTINEL_LOCAL_FAST="true" bash "$NORMALIZER_SH"; then
    warn "Normalizer failed. Skipping OPA advisory."
    log "Pre-commit completed (advisory only)."
    exit 0
  fi
elif [[ -f "$NORMALIZER_PY" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    warn "Normalizer python entrypoint found but python3 is missing: ${NORMALIZER_PY}"
    log "Pre-commit completed (advisory only)."
    exit 0
  fi

  if ! CLOUDSENTINEL_EXECUTION_MODE="advisory" CLOUDSENTINEL_LOCAL_FAST="true" python3 "$NORMALIZER_PY"; then
    warn "Normalizer failed. Skipping OPA advisory."
    log "Pre-commit completed (advisory only)."
    exit 0
  fi
else
  warn "Normalizer not found: ${NORMALIZER_SH} or ${NORMALIZER_PY}"
  log "Pre-commit completed (advisory only)."
  exit 0
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
    bash "$OPA_RUNNER" --advisory
  RC=$?
  set -e

  if [[ "$RC" -ne 0 ]]; then
    warn "OPA advisory skipped or failed (rc=${RC}). Install OPA or run the OPA server for local checks."
  elif [[ -f "$OPA_DECISION_FILE" ]]; then
    OPA_ALLOW="$(json_get_or "$OPA_DECISION_FILE" '.result.allow // false' false)"
    if [[ "$OPA_ALLOW" != "true" ]]; then
      warn "OPA advisory decision is DENY (commit still allowed locally)."
    fi
  fi
else
  warn "OPA runner not found: ${OPA_RUNNER}"
fi

log "Pre-commit completed (advisory only)."
exit 0
