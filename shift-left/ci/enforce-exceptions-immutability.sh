#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# CloudSentinel Exceptions Immutability Guard
# - Prevents direct developer modifications to governance exception registry
# - Only AppSec identities can change policies/opa/exceptions.json
# ------------------------------------------------------------------------------

log()  { echo "[CloudSentinel][exceptions-immutability] $*"; }
err()  { echo "[CloudSentinel][exceptions-immutability][ERROR] $*" >&2; }

TARGET_FILE="policies/opa/exceptions.json"
APPSEC_ALLOWED_USERS="${APPSEC_ALLOWED_USERS:-appsec-bot,appsec-admin,security-admin}"
OUTPUT_DIR="${CI_PROJECT_DIR:-$(pwd)}/.cloudsentinel"
AUDIT_LOG_FILE="${CLOUDSENTINEL_AUDIT_LOG:-$OUTPUT_DIR/audit_events.jsonl}"
mkdir -p "$OUTPUT_DIR"

emit_audit_event() {
  local event_type=$1
  local payload=$2
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg event_type "$event_type" \
    --argjson payload "$payload" \
    '{timestamp:$ts,component:"exceptions-immutability",event_type:$event_type} + $payload' \
    >> "$AUDIT_LOG_FILE" || true
}

BASE_SHA="${CI_COMMIT_BEFORE_SHA:-}"
if [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}" ]]; then
  BASE_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}"
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "0000000000000000000000000000000000000000" ]]; then
  log "No valid base SHA found; skipping immutability check for initial/edge pipeline."
  emit_audit_event "immutability_skipped" "{\"reason\":\"missing_base_sha\",\"target_file\":\"$TARGET_FILE\"}"
  exit 0
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  log "Base SHA not available in clone; skipping immutability check."
  emit_audit_event "immutability_skipped" "{\"reason\":\"base_sha_missing_in_clone\",\"target_file\":\"$TARGET_FILE\",\"base_sha\":\"$BASE_SHA\"}"
  exit 0
fi

CHANGED="$(git diff --name-only "$BASE_SHA" "${CI_COMMIT_SHA:-HEAD}" -- "$TARGET_FILE" | wc -l | tr -d ' ')"
if [[ "$CHANGED" -eq 0 ]]; then
  log "No direct change to $TARGET_FILE detected."
  emit_audit_event "immutability_passed" "{\"target_file\":\"$TARGET_FILE\",\"changed\":false}"
  exit 0
fi

ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"

if echo ",${APPSEC_ALLOWED_USERS}," | grep -qi ",${ACTOR_LOGIN},"; then
  log "Change authorized for AppSec user: ${ACTOR_LOGIN}"
  emit_audit_event "immutability_passed" "{\"target_file\":\"$TARGET_FILE\",\"changed\":true,\"actor_login\":\"$ACTOR_LOGIN\",\"authorized\":true}"
  exit 0
fi

err "Unauthorized modification detected in ${TARGET_FILE} by ${ACTOR_LOGIN} (${ACTOR_EMAIL})."
emit_audit_event "immutability_blocked" "{\"target_file\":\"$TARGET_FILE\",\"changed\":true,\"actor_login\":\"$ACTOR_LOGIN\",\"actor_email\":\"$ACTOR_EMAIL\",\"authorized\":false}"
exit 1

