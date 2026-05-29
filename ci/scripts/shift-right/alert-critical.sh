#!/usr/bin/env bash
# jq filters below use $vars supplied by jq --arg/--argjson.
# shellcheck disable=SC2016
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
CI_PROJECT_PATH="${CI_PROJECT_PATH:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_PIPELINE_SOURCE="${CI_PIPELINE_SOURCE:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"
CI_COMMIT_SHA="${CI_COMMIT_SHA:-unknown}"
ALERT_CHANNEL="${ALERT_CHANNEL:-auto}"
ALERT_MAX_RETRIES="${ALERT_MAX_RETRIES:-3}"
ALERT_TIMEOUT_SECONDS="${ALERT_TIMEOUT_SECONDS:-15}"
ALERT_RUNBOOK_URL="${ALERT_RUNBOOK_URL:-}"

TOTAL_L3=$((OPA_DRIFT_L3_COUNT + OPA_PROWLER_L3_COUNT))
TOTAL_L2=$((OPA_DRIFT_L2_COUNT + OPA_PROWLER_L2_COUNT))
TOTAL_L1=$((OPA_DRIFT_L1_COUNT + OPA_PROWLER_L1_COUNT))
TOTAL_L0=$((OPA_DRIFT_L0_COUNT + OPA_PROWLER_L0_COUNT))
TOTAL_ACTIONABLE=$((TOTAL_L3 + TOTAL_L2))
DRIFT_ACTIONABLE=$((OPA_DRIFT_L3_COUNT + OPA_DRIFT_L2_COUNT))
PROWLER_ACTIONABLE=$((OPA_PROWLER_L3_COUNT + OPA_PROWLER_L2_COUNT))

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

GENERATED_AT_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
if [[ "$CI_COMMIT_SHA" == "unknown" || ${#CI_COMMIT_SHA} -lt 8 ]]; then
  COMMIT_SHORT_SHA="$CI_COMMIT_SHA"
else
  COMMIT_SHORT_SHA="${CI_COMMIT_SHA:0:8}"
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

if [[ "$TOTAL_L3" -gt 0 ]]; then
  DECISION_SUMMARY="L3 findings detected: auto-remediation + reconciliation ticket required."
  ACTION_REQUIRED="1) Validate Custodian execution in job custodian-autofix.\n2) Confirm reconciliation ticket ownership and ETA.\n3) Run post-remediation verification and commit IaC fix."
  PRIORITY_COLOR="Attention"
elif [[ "$TOTAL_L2" -gt 0 ]]; then
  DECISION_SUMMARY="L2 actionable findings detected: reconciliation ticket and incident notification required."
  ACTION_REQUIRED="1) Create/assign reconciliation ticket.\n2) Prioritize IaC fix based on impacted controls.\n3) Verify closure on next scheduled runtime scan."
  PRIORITY_COLOR="Warning"
else
  DECISION_SUMMARY="No actionable findings."
  ACTION_REQUIRED="No immediate action."
  PRIORITY_COLOR="Good"
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

normalize_channel() {
  local raw="${1:-auto}"
  # Trim leading/trailing spaces then lowercase for deterministic matching.
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  raw="${raw,,}"

  case "$raw" in
    ""|auto|default)
      printf 'auto'
      return 0
      ;;
    teams|msteams|ms-teams)
      printf 'teams'
      return 0
      ;;
    gitlab|issue|issues)
      printf 'gitlab'
      return 0
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
    else
      rc=$?
    fi
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

RAW_ALERT_CHANNEL="$ALERT_CHANNEL"
if ! ALERT_CHANNEL="$(normalize_channel "$ALERT_CHANNEL")"; then
  sr_audit "WARN" "alert_channel_invalid" "invalid ALERT_CHANNEL value; falling back to auto" "$(sr_build_details \
    --arg alert_channel_raw "$RAW_ALERT_CHANNEL" \
    '{alert_channel_raw:$alert_channel_raw, fallback:"auto"}')"
  ALERT_CHANNEL="auto"
fi

CHANNEL="$(resolve_channel "$ALERT_CHANNEL" || true)"
if [[ -z "$CHANNEL" ]]; then
  sr_fail "unable to resolve alert channel (set ALERT_CHANNEL=teams|gitlab or required env vars)" 1 \
    "$(sr_build_details \
      --arg alert_channel "$ALERT_CHANNEL" \
      --arg alert_channel_raw "$RAW_ALERT_CHANNEL" \
      '{alert_channel:$alert_channel, alert_channel_raw:$alert_channel_raw}')"
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
  --argjson total_actionable "$TOTAL_ACTIONABLE" \
  '{channel:$channel, priority:$priority, subject:$subject, pipeline_correlation_id:$correlation_id, pipeline_url:$pipeline_url, block_reason:$block_reason, l0_count:$total_l0, l1_count:$total_l1, l2_count:$total_l2, l3_count:$total_l3, actionable_count:$total_actionable}')"

if [[ "$CHANNEL" == "teams" ]]; then
  sr_require_env TEAMS_WEBHOOK_URL
  PAYLOAD="$(jq -cn \
    --arg subject "$ALERT_SUBJECT" \
    --arg priority "$ALERT_PRIORITY" \
    --arg priority_color "$PRIORITY_COLOR" \
    --arg decision_summary "$DECISION_SUMMARY" \
    --arg action_required "$ACTION_REQUIRED" \
    --argjson l3_count "$TOTAL_L3" \
    --argjson l2_count "$TOTAL_L2" \
    --argjson l1_count "$TOTAL_L1" \
    --argjson l0_count "$TOTAL_L0" \
    --argjson drift_l3_count "$OPA_DRIFT_L3_COUNT" \
    --argjson drift_l2_count "$OPA_DRIFT_L2_COUNT" \
    --argjson drift_l1_count "$OPA_DRIFT_L1_COUNT" \
    --argjson drift_l0_count "$OPA_DRIFT_L0_COUNT" \
    --argjson drift_actionable "$DRIFT_ACTIONABLE" \
    --argjson prowler_l3_count "$OPA_PROWLER_L3_COUNT" \
    --argjson prowler_l2_count "$OPA_PROWLER_L2_COUNT" \
    --argjson prowler_l1_count "$OPA_PROWLER_L1_COUNT" \
    --argjson prowler_l0_count "$OPA_PROWLER_L0_COUNT" \
    --argjson prowler_actionable "$PROWLER_ACTIONABLE" \
    --arg pipeline_correlation_id "$CORRELATION_ID" \
    --arg pipeline_url "$PIPELINE_URL" \
    --arg project_path "$CI_PROJECT_PATH" \
    --arg pipeline_id "$CI_PIPELINE_ID" \
    --arg pipeline_source "$CI_PIPELINE_SOURCE" \
    --arg branch "$CI_COMMIT_REF_NAME" \
    --arg commit_short_sha "$COMMIT_SHORT_SHA" \
    --arg generated_at_utc "$GENERATED_AT_UTC" \
    --arg drift_block_reason "$OPA_DRIFT_BLOCK_REASON" \
    --arg prowler_block_reason "$OPA_PROWLER_BLOCK_REASON" \
    --arg block_reason "$BLOCK_REASON" \
    --arg runbook_url "$ALERT_RUNBOOK_URL" \
    '{
      type:"message",
      summary:$subject,
      attachments:[
        {
          contentType:"application/vnd.microsoft.card.adaptive",
          contentUrl:null,
          content:{
            "$schema":"http://adaptivecards.io/schemas/adaptive-card.json",
            type:"AdaptiveCard",
            version:"1.4",
            msteams:{width:"Full"},
            body:[
              {
                type:"TextBlock",
                size:"Large",
                weight:"Bolder",
                text:$subject,
                wrap:true
              },
              {
                type:"TextBlock",
                text:("Priority: " + $priority),
                color: $priority_color,
                weight:"Bolder",
                wrap:true
              },
              {
                type:"TextBlock",
                text:("Generated (UTC): " + $generated_at_utc),
                isSubtle:true,
                spacing:"None",
                wrap:true
              },
              {
                type:"TextBlock",
                text:$decision_summary,
                wrap:true
              },
              {
                type:"TextBlock",
                text:"Pipeline Context",
                weight:"Bolder",
                spacing:"Medium",
                wrap:true
              },
              {
                type:"FactSet",
                facts:[
                  {title:"Project", value:$project_path},
                  {title:"Pipeline ID", value:$pipeline_id},
                  {title:"Pipeline source", value:$pipeline_source},
                  {title:"Pipeline Correlation ID", value:$pipeline_correlation_id},
                  {title:"Branch", value:$branch},
                  {title:"Commit", value:$commit_short_sha},
                  {title:"Actionable total (L2+L3)", value:(($l2_count + $l3_count)|tostring)}
                ]
              },
              {
                type:"TextBlock",
                text:"Severity Totals",
                weight:"Bolder",
                spacing:"Medium",
                wrap:true
              },
              {
                type:"FactSet",
                facts:[
                  {title:"L3 (auto-remediation)", value:($l3_count|tostring)},
                  {title:"L2 (ticket+notify)", value:($l2_count|tostring)},
                  {title:"L1 (audit warn)", value:($l1_count|tostring)},
                  {title:"L0 (audit only)", value:($l0_count|tostring)}
                ]
              },
              {
                type:"TextBlock",
                text:"Breakdown by Sensor",
                weight:"Bolder",
                spacing:"Medium",
                wrap:true
              },
              {
                type:"FactSet",
                facts:[
                  {title:"Drift L3/L2/L1/L0", value:(($drift_l3_count|tostring) + "/" + ($drift_l2_count|tostring) + "/" + ($drift_l1_count|tostring) + "/" + ($drift_l0_count|tostring))},
                  {title:"Prowler L3/L2/L1/L0", value:(($prowler_l3_count|tostring) + "/" + ($prowler_l2_count|tostring) + "/" + ($prowler_l1_count|tostring) + "/" + ($prowler_l0_count|tostring))},
                  {title:"Drift actionable", value:($drift_actionable|tostring)},
                  {title:"Prowler actionable", value:($prowler_actionable|tostring)}
                ]
              },
              {
                type:"TextBlock",
                text:"OPA Decision Reasons",
                weight:"Bolder",
                spacing:"Medium",
                wrap:true
              },
              {
                type:"FactSet",
                facts:[
                  {title:"Drift reason", value:$drift_block_reason},
                  {title:"Prowler reason", value:$prowler_block_reason},
                  {title:"Combined reason", value:$block_reason}
                ]
              },
              {
                type:"TextBlock",
                text:"Required Actions",
                weight:"Bolder",
                spacing:"Medium",
                wrap:true
              },
              {
                type:"TextBlock",
                text:$action_required,
                wrap:true
              },
              {
                type:"TextBlock",
                text:"Traceability: Use pipeline_correlation_id across Drift, OPA, Custodian and DefectDojo artifacts.",
                isSubtle:true,
                wrap:true
              }
            ],
            actions: (
              [
                {type:"Action.OpenUrl", title:"Open Pipeline", url:$pipeline_url}
              ]
              + (if $runbook_url != "" then
                  [{type:"Action.OpenUrl", title:"Open Runbook", url:$runbook_url}]
                 else
                  []
                 end)
            )
          }
        }
      ],
      priority:$priority,
      l3_count:$l3_count,
      l2_count:$l2_count,
      pipeline_correlation_id:$pipeline_correlation_id,
      pipeline_url:$pipeline_url,
      drift_block_reason:$drift_block_reason,
      prowler_block_reason:$prowler_block_reason,
      block_reason:$block_reason,
      generated_at_utc:$generated_at_utc
    }')"

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
- Decision summary: ${DECISION_SUMMARY}
- Pipeline Correlation ID: \`${CORRELATION_ID}\`
- Project: \`${CI_PROJECT_PATH}\`
- Pipeline: ${PIPELINE_URL}
- Pipeline source: \`${CI_PIPELINE_SOURCE}\`
- Branch: \`${CI_COMMIT_REF_NAME}\`
- Commit: \`${COMMIT_SHORT_SHA}\`
- L3 findings (auto-remediation): ${TOTAL_L3}
- L2 findings (ticket+notify): ${TOTAL_L2}
- L1 findings (audit warn): ${TOTAL_L1}
- L0 findings (audit only): ${TOTAL_L0}
- Drift L3/L2/L1/L0: ${OPA_DRIFT_L3_COUNT}/${OPA_DRIFT_L2_COUNT}/${OPA_DRIFT_L1_COUNT}/${OPA_DRIFT_L0_COUNT}
- Prowler L3/L2/L1/L0: ${OPA_PROWLER_L3_COUNT}/${OPA_PROWLER_L2_COUNT}/${OPA_PROWLER_L1_COUNT}/${OPA_PROWLER_L0_COUNT}
- Drift reason: ${OPA_DRIFT_BLOCK_REASON}
- Prowler reason: ${OPA_PROWLER_BLOCK_REASON}
- Combined block reason: ${BLOCK_REASON}
- Generated (UTC): ${GENERATED_AT_UTC}
"
  PAYLOAD="$(jq -cn \
    --arg title "$ALERT_SUBJECT (${CORRELATION_ID})" \
    --arg description "$BODY" \
    --arg labels "security,runtime-alert,${ALERT_PRIORITY}" \
    --arg priority "$ALERT_PRIORITY" \
    --argjson l3_count "$TOTAL_L3" \
    --argjson l2_count "$TOTAL_L2" \
    --argjson actionable_count "$TOTAL_ACTIONABLE" \
    --arg pipeline_correlation_id "$CORRELATION_ID" \
    --arg pipeline_url "$PIPELINE_URL" \
    --arg block_reason "$BLOCK_REASON" \
    '{title:$title, description:$description, labels:$labels, priority:$priority, l3_count:$l3_count, l2_count:$l2_count, actionable_count:$actionable_count, pipeline_correlation_id:$pipeline_correlation_id, pipeline_url:$pipeline_url, block_reason:$block_reason}')"

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
  --arg generated_at_utc "$GENERATED_AT_UTC" \
  --argjson l3_count "$TOTAL_L3" \
  --argjson l2_count "$TOTAL_L2" \
  --argjson actionable_count "$TOTAL_ACTIONABLE" \
  '{channel:$channel, priority:$priority, pipeline_correlation_id:$correlation_id, generated_at_utc:$generated_at_utc, l3_count:$l3_count, l2_count:$l2_count, actionable_count:$actionable_count}')"

exit 0
