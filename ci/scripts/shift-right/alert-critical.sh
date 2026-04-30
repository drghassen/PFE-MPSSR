#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/alert_critical_audit.jsonl"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/alert-critical" "$AUDIT_FILE"
sr_require_command jq curl timeout

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-}"
CI_PROJECT_URL="${CI_PROJECT_URL:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"
ALERT_CHANNEL="${ALERT_CHANNEL:-auto}"
ALERT_MAX_RETRIES="${ALERT_MAX_RETRIES:-3}"
ALERT_TIMEOUT_SECONDS="${ALERT_TIMEOUT_SECONDS:-15}"

TOTAL_CRITICAL=$((OPA_DRIFT_CRITICAL_COUNT + OPA_PROWLER_CRITICAL_COUNT))
CORRELATION_ID="${OPA_CORRELATION_ID:-$OPA_PROWLER_CORRELATION_ID}"
if [[ -z "$CORRELATION_ID" ]]; then
  CORRELATION_ID="unknown"
fi

if [[ "$TOTAL_CRITICAL" -eq 0 ]]; then
  sr_audit "INFO" "skip" "no critical findings" "$(sr_build_details \
    --argjson drift_critical "$OPA_DRIFT_CRITICAL_COUNT" \
    --argjson prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
    --argjson total_critical "$TOTAL_CRITICAL" \
    '{drift_critical:$drift_critical, prowler_critical:$prowler_critical, total_critical:$total_critical}')"
  exit 0
fi

resolve_channel() {
  local channel="$1"
  case "$channel" in
    teams|gitlab)
      printf '%s' "$channel"
      return 0
      ;;
    auto)
      if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
        printf 'teams'
        return 0
      fi
      if [[ -n "${CI_API_V4_URL:-}" && -n "${CI_PROJECT_ID:-}" && -n "${GITLAB_API_TOKEN:-}" ]]; then
        printf 'gitlab'
        return 0
      fi
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

retry_request() {
  local cmd="$1"
  local attempt=1
  local rc=1

  while [[ "$attempt" -le "$ALERT_MAX_RETRIES" ]]; do
    if eval "$cmd"; then
      return 0
    fi
    rc=$?
    sr_audit "WARN" "alert_retry" "alert delivery attempt failed" "$(sr_build_details \
      --argjson attempt "$attempt" \
      --argjson max_retries "$ALERT_MAX_RETRIES" \
      --argjson rc "$rc" \
      '{attempt:$attempt, max_retries:$max_retries, rc:$rc}')"
    attempt=$((attempt + 1))
    sleep 2
  done

  return "$rc"
}

CHANNEL="$(resolve_channel "$ALERT_CHANNEL" || true)"
if [[ -z "$CHANNEL" ]]; then
  sr_fail "unable to resolve alert channel (set ALERT_CHANNEL=teams|gitlab or required env vars)" 1 \
    "$(sr_build_details --arg alert_channel "$ALERT_CHANNEL" '{alert_channel:$alert_channel}')"
fi

sr_audit "WARN" "alert_triggered" "critical findings detected; sending alert" "$(sr_build_details \
  --arg channel "$CHANNEL" \
  --arg correlation_id "$CORRELATION_ID" \
  --arg ci_project_url "$CI_PROJECT_URL" \
  --arg ci_pipeline_id "$CI_PIPELINE_ID" \
  --arg ci_commit_ref_name "$CI_COMMIT_REF_NAME" \
  --argjson drift_critical "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  '{channel:$channel, correlation_id:$correlation_id, drift_critical:$drift_critical, prowler_critical:$prowler_critical, total_critical:$total_critical, pipeline:{project_url:$ci_project_url, pipeline_id:$ci_pipeline_id, branch:$ci_commit_ref_name}}')"

if [[ "$CHANNEL" == "teams" ]]; then
  sr_require_env TEAMS_WEBHOOK_URL

  PAYLOAD="$(jq -cn \
    --arg text "CloudSentinel CRITICAL findings detected (corr=${CORRELATION_ID}) - ${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID} [drift=${OPA_DRIFT_CRITICAL_COUNT}, prowler=${OPA_PROWLER_CRITICAL_COUNT}]" \
    '{text:$text}')"

  CMD="timeout ${ALERT_TIMEOUT_SECONDS} curl -sS -f -X POST '${TEAMS_WEBHOOK_URL}' -H 'Content-Type: application/json' -d '${PAYLOAD}' >/dev/null"
  if ! retry_request "$CMD"; then
    sr_fail "failed to deliver Teams alert" 1 "$(sr_build_details --arg channel "$CHANNEL" '{channel:$channel}')"
  fi
else
  sr_require_env CI_API_V4_URL CI_PROJECT_ID GITLAB_API_TOKEN

  TITLE="CloudSentinel CRITICAL alert (${CORRELATION_ID})"
  BODY="## CloudSentinel Runtime Alert

- Correlation ID: ${CORRELATION_ID}
- Pipeline: ${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}
- Branch: ${CI_COMMIT_REF_NAME}
- CRITICAL findings: drift=${OPA_DRIFT_CRITICAL_COUNT}, prowler=${OPA_PROWLER_CRITICAL_COUNT}
"

  PAYLOAD="$(jq -cn \
    --arg title "$TITLE" \
    --arg description "$BODY" \
    --arg labels "security,critical,runtime-alert" \
    '{title:$title, description:$description, labels:$labels}')"

  CMD="timeout ${ALERT_TIMEOUT_SECONDS} curl -sS -f -X POST '${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/issues' -H 'PRIVATE-TOKEN: ${GITLAB_API_TOKEN}' -H 'Content-Type: application/json' -d '${PAYLOAD}' >/dev/null"
  if ! retry_request "$CMD"; then
    sr_fail "failed to create GitLab alert issue" 1 "$(sr_build_details --arg channel "$CHANNEL" '{channel:$channel}')"
  fi
fi

sr_audit "INFO" "alert_sent" "critical alert delivered" "$(sr_build_details \
  --arg channel "$CHANNEL" \
  --arg correlation_id "$CORRELATION_ID" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  '{channel:$channel, correlation_id:$correlation_id, total_critical:$total_critical}')"

exit 0
