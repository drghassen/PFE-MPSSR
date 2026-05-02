#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/alert_critical_audit.jsonl"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/alert-critical" "$AUDIT_FILE"
sr_require_command jq curl timeout

OPA_DRIFT_L0_COUNT="${OPA_DRIFT_L0_COUNT:-0}"
OPA_DRIFT_L1_COUNT="${OPA_DRIFT_L1_COUNT:-0}"
OPA_DRIFT_L2_COUNT="${OPA_DRIFT_L2_COUNT:-0}"
OPA_DRIFT_L3_COUNT="${OPA_DRIFT_L3_COUNT:-0}"
OPA_PROWLER_L0_COUNT="${OPA_PROWLER_L0_COUNT:-0}"
OPA_PROWLER_L1_COUNT="${OPA_PROWLER_L1_COUNT:-0}"
OPA_PROWLER_L2_COUNT="${OPA_PROWLER_L2_COUNT:-0}"
OPA_PROWLER_L3_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
OPA_DRIFT_BLOCK_REASON="${OPA_DRIFT_BLOCK_REASON:-none}"
OPA_PROWLER_BLOCK_REASON="${OPA_PROWLER_BLOCK_REASON:-none}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-}"
CI_PROJECT_URL="${CI_PROJECT_URL:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"
ALERT_CHANNEL="${ALERT_CHANNEL:-auto}"
ALERT_MAX_RETRIES="${ALERT_MAX_RETRIES:-3}"
ALERT_TIMEOUT_SECONDS="${ALERT_TIMEOUT_SECONDS:-15}"

TOTAL_L3=$((OPA_DRIFT_L3_COUNT + OPA_PROWLER_L3_COUNT))
TOTAL_L2=$((OPA_DRIFT_L2_COUNT + OPA_PROWLER_L2_COUNT))
TOTAL_L1=$((OPA_DRIFT_L1_COUNT + OPA_PROWLER_L1_COUNT))
TOTAL_L0=$((OPA_DRIFT_L0_COUNT + OPA_PROWLER_L0_COUNT))
TOTAL_ACTIONABLE=$((TOTAL_L3 + TOTAL_L2))

CORRELATION_ID="${OPA_PIPELINE_CORRELATION_ID:-}"
if [[ -z "$CORRELATION_ID" || "$CORRELATION_ID" == "unknown" ]]; then
  CORRELATION_ID="$(sr_pipeline_correlation_id)"
fi
if [[ -z "$CORRELATION_ID" || "$CORRELATION_ID" == "unknown" ]]; then
  CORRELATION_ID="${OPA_CORRELATION_ID:-$OPA_PROWLER_CORRELATION_ID}"
fi
if [[ -z "$CORRELATION_ID" ]]; then
  CORRELATION_ID="unknown"
fi

if [[ "$TOTAL_L3" -gt 0 ]]; then
  ALERT_PRIORITY="CRITICAL"
  ALERT_SUBJECT="CloudSentinel AUTO-REMEDIATION triggered"
elif [[ "$TOTAL_L2" -gt 0 ]]; then
  ALERT_PRIORITY="HIGH"
  ALERT_SUBJECT="CloudSentinel TICKET required - actionable violations"
else
  if [[ "$TOTAL_L1" -gt 0 ]]; then
    AUDIT_LEVEL="WARN"
    AUDIT_EVENT="l1_notify"
    AUDIT_MESSAGE="L1 findings logged to audit trail only"
  else
    AUDIT_LEVEL="INFO"
    AUDIT_EVENT="skip"
    AUDIT_MESSAGE="no actionable findings (L2/L3)"
  fi
  sr_audit "$AUDIT_LEVEL" "$AUDIT_EVENT" "$AUDIT_MESSAGE" \
    "$(sr_build_details \
      --argjson drift_l0 "$OPA_DRIFT_L0_COUNT" \
      --argjson drift_l1 "$OPA_DRIFT_L1_COUNT" \
      --argjson prowler_l0 "$OPA_PROWLER_L0_COUNT" \
      --argjson prowler_l1 "$OPA_PROWLER_L1_COUNT" \
      '{drift_l0:$drift_l0, drift_l1:$drift_l1, prowler_l0:$prowler_l0, prowler_l1:$prowler_l1, action:"audit_only"}')"
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
      # CI_JOB_TOKEN is always injected by GitLab CI — use it as a fallback
      if [[ -n "${CI_API_V4_URL:-}" && -n "${CI_PROJECT_ID:-}" && -n "${CI_JOB_TOKEN:-}" ]]; then
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
  local attempt=1
  local rc=1
  while [[ "$attempt" -le "$ALERT_MAX_RETRIES" ]]; do
    if "$@"; then
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

PIPELINE_URL="${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}"
BLOCK_REASON="drift=${OPA_DRIFT_BLOCK_REASON};prowler=${OPA_PROWLER_BLOCK_REASON}"

sr_audit "WARN" "alert_triggered" "L2/L3 findings detected; sending alert" "$(sr_build_details \
  --arg channel "$CHANNEL" \
  --arg priority "$ALERT_PRIORITY" \
  --arg subject "$ALERT_SUBJECT" \
  --arg correlation_id "$CORRELATION_ID" \
  --arg pipeline_url "$PIPELINE_URL" \
  --arg block_reason "$BLOCK_REASON" \
  --argjson total_l0 "$TOTAL_L0" \
  --argjson total_l1 "$TOTAL_L1" \
  --argjson total_l2 "$TOTAL_L2" \
  --argjson total_l3 "$TOTAL_L3" \
  '{channel:$channel, priority:$priority, subject:$subject, pipeline_correlation_id:$correlation_id, pipeline_url:$pipeline_url, block_reason:$block_reason, l0_count:$total_l0, l1_count:$total_l1, l2_count:$total_l2, l3_count:$total_l3}')"

if [[ "$CHANNEL" == "teams" ]]; then
  sr_require_env TEAMS_WEBHOOK_URL
  PAYLOAD="$(jq -cn \
    --arg text "${ALERT_SUBJECT} [priority=${ALERT_PRIORITY}, l3=${TOTAL_L3}, l2=${TOTAL_L2}, corr=${CORRELATION_ID}] ${PIPELINE_URL}" \
    --arg priority "$ALERT_PRIORITY" \
    --argjson l3_count "$TOTAL_L3" \
    --argjson l2_count "$TOTAL_L2" \
    --arg pipeline_correlation_id "$CORRELATION_ID" \
    --arg pipeline_url "$PIPELINE_URL" \
    --arg block_reason "$BLOCK_REASON" \
    '{text:$text, priority:$priority, l3_count:$l3_count, l2_count:$l2_count, pipeline_correlation_id:$pipeline_correlation_id, pipeline_url:$pipeline_url, block_reason:$block_reason}')"

  if ! retry_request timeout "$ALERT_TIMEOUT_SECONDS" curl -sS -f -X POST "$TEAMS_WEBHOOK_URL" \
      -H "Content-Type: application/json" --data-binary "$PAYLOAD" -o /dev/null; then
    sr_fail "failed to deliver Teams alert" 1 "$(sr_build_details --arg channel "$CHANNEL" '{channel:$channel}')"
  fi
else
  sr_require_env CI_API_V4_URL CI_PROJECT_ID
  GITLAB_AUTH_TOKEN="${GITLAB_API_TOKEN:-${CI_JOB_TOKEN:-}}"
  if [[ -z "$GITLAB_AUTH_TOKEN" ]]; then
    sr_fail "no GitLab auth token available (set GITLAB_API_TOKEN or ensure CI_JOB_TOKEN is present)" 1 \
      "$(sr_build_details --arg channel "$CHANNEL" '{channel:$channel}')"
  fi
  BODY="## ${ALERT_SUBJECT}

- Priority: ${ALERT_PRIORITY}
- Pipeline Correlation ID: \`${CORRELATION_ID}\`
- Pipeline: ${PIPELINE_URL}
- Branch: \`${CI_COMMIT_REF_NAME}\`
- L3 findings (auto-remediation): ${TOTAL_L3}
- L2 findings (ticket+notify): ${TOTAL_L2}
- L1 findings (audit warn): ${TOTAL_L1}
- L0 findings (audit only): ${TOTAL_L0}
- Block reason: ${BLOCK_REASON}
"
  PAYLOAD="$(jq -cn \
    --arg title "$ALERT_SUBJECT (${CORRELATION_ID})" \
    --arg description "$BODY" \
    --arg labels "security,runtime-alert,${ALERT_PRIORITY}" \
    --arg priority "$ALERT_PRIORITY" \
    --argjson l3_count "$TOTAL_L3" \
    --argjson l2_count "$TOTAL_L2" \
    --arg pipeline_correlation_id "$CORRELATION_ID" \
    --arg pipeline_url "$PIPELINE_URL" \
    --arg block_reason "$BLOCK_REASON" \
    '{title:$title, description:$description, labels:$labels, priority:$priority, l3_count:$l3_count, l2_count:$l2_count, pipeline_correlation_id:$pipeline_correlation_id, pipeline_url:$pipeline_url, block_reason:$block_reason}')"

  if [[ -n "${GITLAB_API_TOKEN:-}" ]]; then
    GITLAB_AUTH_HEADER="PRIVATE-TOKEN: ${GITLAB_API_TOKEN}"
  else
    GITLAB_AUTH_HEADER="JOB-TOKEN: ${CI_JOB_TOKEN}"
  fi
  if ! retry_request timeout "$ALERT_TIMEOUT_SECONDS" curl -sS -f -X POST "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/issues" \
      -H "$GITLAB_AUTH_HEADER" \
      -H "Content-Type: application/json" \
      --data-binary "$PAYLOAD" \
      -o /dev/null; then
    sr_fail "failed to create GitLab alert issue" 1 "$(sr_build_details --arg channel "$CHANNEL" '{channel:$channel}')"
  fi
fi

sr_audit "INFO" "alert_sent" "runtime alert delivered" "$(sr_build_details \
  --arg channel "$CHANNEL" \
  --arg priority "$ALERT_PRIORITY" \
  --arg correlation_id "$CORRELATION_ID" \
  --argjson l3_count "$TOTAL_L3" \
  --argjson l2_count "$TOTAL_L2" \
  '{channel:$channel, priority:$priority, pipeline_correlation_id:$correlation_id, l3_count:$l3_count, l2_count:$l2_count}')"

exit 0
