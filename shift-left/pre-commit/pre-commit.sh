#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel Pre-Commit (Advisory)
# - Runs Gitleaks on staged files
# - Builds a golden report (fast, no extra scanners executed)
# - Runs OPA in advisory mode (CLI or server)
# - Never blocks the commit
# ==============================================================================

log()  { echo "[CloudSentinel][pre-commit] $*"; }
warn() { echo "[CloudSentinel][pre-commit][WARN] $*" >&2; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

GITLEAKS_HOOK="${REPO_ROOT}/shift-left/gitleaks/pre-commit-hook.sh"
NORMALIZER="${REPO_ROOT}/shift-left/normalizer/normalize.sh"
OPA_RUNNER="${REPO_ROOT}/shift-left/opa/run-opa.sh"

log "Running advisory checks..."

# 1) Gitleaks (staged files)
if [[ -x "$GITLEAKS_HOOK" ]]; then
  bash "$GITLEAKS_HOOK" || true
else
  warn "Gitleaks hook not found or not executable: ${GITLEAKS_HOOK}"
fi

# 2) Build golden report (fast, uses existing scanner outputs if any)
if [[ -x "$NORMALIZER" ]]; then
  if ! CLOUDSENTINEL_EXECUTION_MODE="local" CLOUDSENTINEL_LOCAL_FAST="true" bash "$NORMALIZER"; then
    warn "Normalizer failed. Skipping OPA advisory."
    log "Pre-commit completed (advisory only)."
    exit 0
  fi
else
  warn "Normalizer not found: ${NORMALIZER}"
  log "Pre-commit completed (advisory only)."
  exit 0
fi

# 3) OPA advisory (server preferred, CLI fallback)
if [[ -x "$OPA_RUNNER" ]]; then
  set +e
  CLOUDSENTINEL_EXECUTION_MODE="local" \
    OPA_PREFER_CLI="true" \
    OPA_DECISION_FILE="${REPO_ROOT}/.cloudsentinel/opa_decision_precommit.json" \
    bash "$OPA_RUNNER" --advisory
  RC=$?
  set -e

  if [[ "$RC" -ne 0 ]]; then
    warn "OPA advisory skipped or failed (rc=${RC}). Install OPA or run the OPA server for local checks."
  fi
else
  warn "OPA runner not found: ${OPA_RUNNER}"
fi

log "Pre-commit completed (advisory only)."
exit 0
