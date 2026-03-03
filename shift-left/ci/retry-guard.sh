#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# CloudSentinel Retry Guard
# - Protects CI from retry abuse on same commit SHA
# - Enforces max retries and minimum delay between retries
# - Stateless OPA stays focused on policy decision only
# ------------------------------------------------------------------------------

log()  { echo "[CloudSentinel][retry-guard] $*"; }
warn() { echo "[CloudSentinel][retry-guard][WARN] $*" >&2; }
err()  { echo "[CloudSentinel][retry-guard][ERROR] $*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || { err "$1 not installed"; exit 2; }; }
need curl
need jq
need date

: "${CI_API_V4_URL:?CI_API_V4_URL is required}"
: "${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
: "${CI_PIPELINE_ID:?CI_PIPELINE_ID is required}"
: "${CI_COMMIT_SHA:?CI_COMMIT_SHA is required}"

OUTPUT_DIR="${CI_PROJECT_DIR:-$(pwd)}/.cloudsentinel"
AUDIT_LOG_FILE="${CLOUDSENTINEL_AUDIT_LOG:-$OUTPUT_DIR/audit_events.jsonl}"
mkdir -p "$OUTPUT_DIR"

MAX_RETRIES="${RETRY_GUARD_MAX_RETRIES:-3}"
MIN_INTERVAL_SEC="${RETRY_GUARD_MIN_INTERVAL_SEC:-120}"
LOOKBACK_LIMIT="${RETRY_GUARD_LOOKBACK_LIMIT:-50}"

API_URL="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines?sha=${CI_COMMIT_SHA}&per_page=${LOOKBACK_LIMIT}"

auth_header_name="JOB-TOKEN"
auth_header_value="${CI_JOB_TOKEN:-}"
if [[ -n "${GITLAB_RETRY_GUARD_TOKEN:-}" ]]; then
  auth_header_name="PRIVATE-TOKEN"
  auth_header_value="${GITLAB_RETRY_GUARD_TOKEN}"
fi

if [[ -z "$auth_header_value" ]]; then
  err "No token available (CI_JOB_TOKEN or GITLAB_RETRY_GUARD_TOKEN)"
  exit 2
fi

emit_audit_event() {
  local event_type=$1
  local payload=$2
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg event_type "$event_type" \
    --argjson payload "$payload" \
    '{timestamp:$ts,component:"retry-guard",event_type:$event_type} + $payload' \
    >> "$AUDIT_LOG_FILE" || true
}

log "Checking retry policy for commit ${CI_COMMIT_SHA:0:12}..."

RESP_FILE="$(mktemp -t retry-guard.XXXXXX.json)"
trap 'rm -f "$RESP_FILE"' EXIT

HTTP_CODE="$(curl -sS -w "%{http_code}" \
  -H "${auth_header_name}: ${auth_header_value}" \
  "$API_URL" -o "$RESP_FILE")"

if [[ "$HTTP_CODE" != "200" ]]; then
  err "GitLab API error HTTP=${HTTP_CODE}"
  emit_audit_event "retry_guard_error" "{\"http_code\":\"$HTTP_CODE\",\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
  exit 2
fi

if ! jq -e 'type=="array"' "$RESP_FILE" >/dev/null 2>&1; then
  err "Unexpected GitLab API payload format"
  emit_audit_event "retry_guard_error" "{\"reason\":\"invalid_payload\",\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
  exit 2
fi

PREVIOUS_COUNT="$(jq -r --arg cur "$CI_PIPELINE_ID" '[ .[] | select((.id|tostring) != $cur) ] | length' "$RESP_FILE")"
LAST_PREVIOUS_TS="$(jq -r --arg cur "$CI_PIPELINE_ID" '[ .[] | select((.id|tostring) != $cur) ][0].updated_at // ""' "$RESP_FILE")"

if [[ "$PREVIOUS_COUNT" -gt "$MAX_RETRIES" ]]; then
  err "Retry limit exceeded: previous_runs=${PREVIOUS_COUNT}, max_retries=${MAX_RETRIES}"
  emit_audit_event "retry_guard_blocked" "{\"reason\":\"max_retries_exceeded\",\"previous_runs\":$PREVIOUS_COUNT,\"max_retries\":$MAX_RETRIES,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
  exit 1
fi

if [[ -n "$LAST_PREVIOUS_TS" ]]; then
  NOW_EPOCH="$(date -u +%s)"
  LAST_EPOCH="$(date -u -d "$LAST_PREVIOUS_TS" +%s 2>/dev/null || echo 0)"
  if [[ "$LAST_EPOCH" -gt 0 ]]; then
    DELTA_SEC="$((NOW_EPOCH - LAST_EPOCH))"
    if [[ "$DELTA_SEC" -lt "$MIN_INTERVAL_SEC" ]]; then
      err "Retry interval too short: ${DELTA_SEC}s < ${MIN_INTERVAL_SEC}s"
      emit_audit_event "retry_guard_blocked" "{\"reason\":\"min_interval_not_respected\",\"delta_sec\":$DELTA_SEC,\"min_interval_sec\":$MIN_INTERVAL_SEC,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
      exit 1
    fi
  else
    warn "Could not parse previous pipeline timestamp: $LAST_PREVIOUS_TS"
  fi
fi

emit_audit_event "retry_guard_passed" "{\"previous_runs\":$PREVIOUS_COUNT,\"max_retries\":$MAX_RETRIES,\"min_interval_sec\":$MIN_INTERVAL_SEC,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
log "Retry guard passed (previous_runs=${PREVIOUS_COUNT}, max_retries=${MAX_RETRIES})."
exit 0

