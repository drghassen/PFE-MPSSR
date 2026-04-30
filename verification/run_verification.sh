#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-.cloudsentinel}"
STATE_DIR="${OUTPUT_DIR}/runtime-state"
STATE_FILE="${RUNTIME_STATE_FILE:-${STATE_DIR}/runtime-state.jsonl}"

mkdir -p "$STATE_DIR"

SCRIPT_NAME=""
RESOURCE_ID=""
FINDING_ID=""
POLICY=""
SEVERITY="LOW"
CORRELATION_ID="unknown"
MAX_RETRIES="${VERIFICATION_MAX_RETRIES:-3}"
TIMEOUT_SECONDS="${VERIFICATION_TIMEOUT_SECONDS:-30}"
ATTEMPTED="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --script)
      SCRIPT_NAME="${2:-}"; shift 2 ;;
    --resource-id)
      RESOURCE_ID="${2:-}"; shift 2 ;;
    --finding-id)
      FINDING_ID="${2:-}"; shift 2 ;;
    --policy)
      POLICY="${2:-}"; shift 2 ;;
    --severity)
      SEVERITY="${2:-LOW}"; shift 2 ;;
    --correlation-id)
      CORRELATION_ID="${2:-unknown}"; shift 2 ;;
    --max-retries)
      MAX_RETRIES="${2:-3}"; shift 2 ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="${2:-30}"; shift 2 ;;
    *)
      echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$SCRIPT_NAME" || -z "$RESOURCE_ID" || -z "$FINDING_ID" || -z "$POLICY" ]]; then
  echo "required args: --script --resource-id --finding-id --policy" >&2
  exit 2
fi

SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"
if [[ ! -x "$SCRIPT_PATH" ]]; then
  echo "verification script not executable: $SCRIPT_PATH" >&2
  exit 2
fi

_emit_state() {
  local status="$1"
  local passed="$2"
  local attempt="$3"
  local reason="${4:-}"

  jq -cn \
    --arg finding_id "$FINDING_ID" \
    --arg policy "$POLICY" \
    --arg severity "$SEVERITY" \
    --arg status "$status" \
    --argjson remediation_attempted "$ATTEMPTED" \
    --argjson verification_passed "$passed" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg resource_id "$RESOURCE_ID" \
    --arg correlation_id "$CORRELATION_ID" \
    --argjson attempt "$attempt" \
    --arg reason "$reason" \
    '{
      finding_id: $finding_id,
      policy: $policy,
      severity: $severity,
      status: $status,
      remediation_attempted: $remediation_attempted,
      verification_passed: $verification_passed,
      timestamp: $timestamp,
      resource_id: $resource_id,
      correlation_id: $correlation_id,
      attempt: $attempt,
      reason: $reason
    }' >> "$STATE_FILE"
}

_emit_state "REMEDIATION_ATTEMPTED" false 0 "verification_started"

attempt=1
while [[ "$attempt" -le "$MAX_RETRIES" ]]; do
  if timeout "$TIMEOUT_SECONDS" "$SCRIPT_PATH" "$RESOURCE_ID"; then
    _emit_state "REMEDIATION_VERIFIED" true "$attempt" "verification_passed"
    exit 0
  fi

  if [[ "$attempt" -lt "$MAX_RETRIES" ]]; then
    sleep 2
  fi

  attempt=$((attempt + 1))
done

_emit_state "FAILED" false "$MAX_RETRIES" "verification_failed_after_retries"
exit 1
