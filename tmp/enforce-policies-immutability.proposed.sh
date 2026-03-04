#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# CloudSentinel OPA Policies Immutability Guard
# - Restricts OPA policy/security-contract edits to AppSec identities
# - Protects Rego decision logic and exception schema from unauthorized modifications
# ------------------------------------------------------------------------------

log() { echo "[CloudSentinel][policies-immutability] $*"; }
err() { echo "[CloudSentinel][policies-immutability][ERROR] $*" >&2; }

TARGET_PATH="policies/opa/"
SCHEMA_FILE="shift-left/opa/schema/exceptions_v2.schema.json"
APPSEC_ALLOWED_USERS="${APPSEC_ALLOWED_USERS:-appsec-bot,appsec-admin}"

BASE_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"
HEAD_SHA="${CI_COMMIT_SHA:-HEAD}"
ZERO_SHA="0000000000000000000000000000000000000000"

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  log "No valid base SHA found; skipping policies immutability check."
  exit 0
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  log "Base SHA not available in clone; skipping policies immutability check."
  exit 0
fi

if ! git cat-file -e "${HEAD_SHA}^{commit}" 2>/dev/null; then
  err "Head SHA not available in clone: ${HEAD_SHA}"
  exit 2
fi

CHANGED_PROTECTED_FILES="$(
  git diff --name-only "$BASE_SHA" "$HEAD_SHA" -- "$TARGET_PATH" "$SCHEMA_FILE" \
    | grep -E '(^policies/opa/.*\.rego$|^shift-left/opa/schema/exceptions_v2\.schema\.json$)' \
    || true
)"

if [[ -z "$CHANGED_PROTECTED_FILES" ]]; then
  log "No protected policy/schema changes detected."
  exit 0
fi

ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"

if echo ",${APPSEC_ALLOWED_USERS}," | grep -qi ",${ACTOR_LOGIN},"; then
  log "Authorized AppSec security change by ${ACTOR_LOGIN}."
  log "Changed protected files:"
  echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /'
  exit 0
fi

err "Unauthorized modification of OPA policies/schema by ${ACTOR_LOGIN} (${ACTOR_EMAIL})."
err "Changed protected files:"
echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /' >&2
exit 1
