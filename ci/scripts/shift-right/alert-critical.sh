#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/alert_critical_audit.jsonl"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/alert-critical" "$AUDIT_FILE"

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-}"
CI_PROJECT_URL="${CI_PROJECT_URL:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"

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
    '{
      drift_critical: $drift_critical,
      prowler_critical: $prowler_critical,
      total_critical: $total_critical
    }')"
  exit 0
fi

sr_audit "WARN" "alert_triggered" "critical findings detected; alert routing required" "$(sr_build_details \
  --argjson drift_critical "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  --arg correlation_id "$CORRELATION_ID" \
  --arg ci_project_url "$CI_PROJECT_URL" \
  --arg ci_pipeline_id "$CI_PIPELINE_ID" \
  --arg ci_commit_ref_name "$CI_COMMIT_REF_NAME" \
  '{
    drift_critical: $drift_critical,
    prowler_critical: $prowler_critical,
    total_critical: $total_critical,
    correlation_id: $correlation_id,
    pipeline: {
      project_url: $ci_project_url,
      pipeline_id: $ci_pipeline_id,
      branch: $ci_commit_ref_name
    }
  }')"

# ── TODO Phase 2 — Alert Integration ─────────────────────────────────────
# Implement ONE of the following alert channels:
#
# Option A — Microsoft Teams webhook:
#   curl -H "Content-Type: application/json" \
#        -d "{\"text\": \"CRITICAL drift in ${CI_PROJECT_URL}/pipelines/${CI_PIPELINE_ID}\"}" \
#        "${TEAMS_WEBHOOK_URL}"
#   Required CI variable: TEAMS_WEBHOOK_URL (masked)
#
# Option B — PagerDuty Events API v2:
#   curl -X POST https://events.pagerduty.com/v2/enqueue \
#        -H "Content-Type: application/json" \
#        -d "{\"routing_key\": \"${PAGERDUTY_ROUTING_KEY}\", \"event_action\": \"trigger\", ...}"
#   Required CI variable: PAGERDUTY_ROUTING_KEY (masked)
#
# Option C — GitLab Issue (no external dependency):
#   curl --request POST "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/issues" \
#        --header "PRIVATE-TOKEN: ${GITLAB_API_TOKEN}" \
#        --form "title=CRITICAL drift detected — pipeline ${CI_PIPELINE_ID}" \
#        --form "labels=security,critical,drift"
#   Required CI variable: GITLAB_API_TOKEN (masked)
# ─────────────────────────────────────────────────────────────────────────

exit 0
