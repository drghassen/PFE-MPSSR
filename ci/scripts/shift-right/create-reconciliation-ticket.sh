#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/reconciliation_ticket_audit.jsonl"
ENV_FILE="${OUTPUT_DIR}/reconciliation_ticket.env"
RESPONSE_FILE="${OUTPUT_DIR}/reconciliation_ticket_response.json"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/reconciliation-ticket" "$AUDIT_FILE"
sr_require_command jq curl

OPA_DRIFT_L2_COUNT="${OPA_DRIFT_L2_COUNT:-0}"
OPA_DRIFT_L3_COUNT="${OPA_DRIFT_L3_COUNT:-0}"
OPA_PROWLER_L2_COUNT="${OPA_PROWLER_L2_COUNT:-0}"
OPA_PROWLER_L3_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
OPA_DRIFT_BLOCK_REASON="${OPA_DRIFT_BLOCK_REASON:-none}"
OPA_PROWLER_BLOCK_REASON="${OPA_PROWLER_BLOCK_REASON:-none}"
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_PROWLER_CUSTODIAN_POLICIES="${OPA_PROWLER_CUSTODIAN_POLICIES:-}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-unknown}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-unknown}"
CI_PROJECT_URL="${CI_PROJECT_URL:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"
CI_COMMIT_SHA="${CI_COMMIT_SHA:-unknown}"

TOTAL_L3=$((OPA_DRIFT_L3_COUNT + OPA_PROWLER_L3_COUNT))
TOTAL_L2=$((OPA_DRIFT_L2_COUNT + OPA_PROWLER_L2_COUNT))
TOTAL_ACTIONABLE=$((TOTAL_L3 + TOTAL_L2))

ALL_RUNTIME_POLICIES="$(jq -nr \
  --arg drift "$OPA_CUSTODIAN_POLICIES" \
  --arg prowler "$OPA_PROWLER_CUSTODIAN_POLICIES" \
  '[($drift|split(",")[]?), ($prowler|split(",")[]?)]
   | map(gsub("^\\s+|\\s+$";""))
   | map(select(length > 0))
   | unique
   | join(",")')"
if [[ -z "$ALL_RUNTIME_POLICIES" ]]; then
  ALL_RUNTIME_POLICIES="none"
fi

PIPELINE_CORRELATION_ID="$(sr_pipeline_correlation_id)"
CORRELATION_ID="${OPA_PIPELINE_CORRELATION_ID:-}"
if [[ -z "$CORRELATION_ID" || "$CORRELATION_ID" == "unknown" ]]; then
  CORRELATION_ID="$PIPELINE_CORRELATION_ID"
fi
if [[ -z "$CORRELATION_ID" ]]; then
  CORRELATION_ID="unknown"
fi

if [[ "$TOTAL_ACTIONABLE" -eq 0 ]]; then
  {
    echo "RECONCILIATION_TICKET_REQUIRED=false"
    echo "RECONCILIATION_TICKET_CREATED=false"
    echo "RECONCILIATION_TICKET_URL="
    echo "RECONCILIATION_CORRELATION_ID=${CORRELATION_ID}"
    echo "RECONCILIATION_DRIFT_CORRELATION_ID=${OPA_CORRELATION_ID}"
    echo "RECONCILIATION_PROWLER_CORRELATION_ID=${OPA_PROWLER_CORRELATION_ID}"
    echo "RECONCILIATION_TICKET_SKIP_REASON=no_actionable_findings"
  } > "$ENV_FILE"

  sr_audit "INFO" "skip" "no actionable findings - reconciliation ticket not required" \
    "$(sr_build_details \
      --argjson total_l3 "$TOTAL_L3" \
      --argjson total_l2 "$TOTAL_L2" \
      --arg correlation_id "$CORRELATION_ID" \
      '{total_l3:$total_l3, total_l2:$total_l2, correlation_id:$correlation_id, skip_reason:"no_actionable_findings"}')"
  exit 0
fi

if [[ "$TOTAL_L3" -gt 0 ]]; then
  TICKET_LABELS="security,drift,reconciliation,critical,auto-remediation"
  TICKET_PRIORITY="Critical"
else
  TICKET_LABELS="security,drift,reconciliation,high,ticket-and-notify"
  TICKET_PRIORITY="High"
fi

sr_require_env CI_API_V4_URL CI_PROJECT_ID GITLAB_API_TOKEN

L3_SECTION=""
if [[ "$TOTAL_L3" -gt 0 ]]; then
  L3_SECTION="
### L3 Required Actions
1. Verify Custodian auto-remediation result in verify-remediation artifacts.
2. Update Terraform source - runtime fix will be overwritten on next apply.
3. Open MR with IaC fix referencing this ticket.
"
fi

L2_SECTION=""
if [[ "$TOTAL_L2" -gt 0 ]]; then
  L2_SECTION="
### L2 Required Actions
1. Review ticket_and_notify violations in DefectDojo engagement shift-right.
2. Assess each finding: accept risk in DefectDojo or fix in IaC.
3. Findings with risk acceptance will be excepted in next OPA evaluation.
"
fi

TITLE="CloudSentinel IaC Reconciliation Required (${CORRELATION_ID})"
DESCRIPTION="## CloudSentinel Drift Reconciliation

- Pipeline Correlation ID: \`${CORRELATION_ID}\`
- Drift Engine Correlation ID: \`${OPA_CORRELATION_ID}\`
- Prowler Correlation ID: \`${OPA_PROWLER_CORRELATION_ID}\`
- Pipeline: ${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}
- Branch: \`${CI_COMMIT_REF_NAME}\`
- Commit: \`${CI_COMMIT_SHA}\`
- Priority: ${TICKET_PRIORITY}
- L3 findings (auto-remediation): ${TOTAL_L3}
- L2 findings (ticket+notify): ${TOTAL_L2}
- Custodian policies triggered: ${ALL_RUNTIME_POLICIES}
- Block reason (drift): ${OPA_DRIFT_BLOCK_REASON}
- Block reason (prowler): ${OPA_PROWLER_BLOCK_REASON}

### Required Actions${L3_SECTION}${L2_SECTION}"

PAYLOAD="$(jq -cn \
  --arg title "$TITLE" \
  --arg description "$DESCRIPTION" \
  --arg labels "$TICKET_LABELS" \
  '{title: $title, description: $description, labels: $labels}')"

sr_audit "WARN" "ticket_create_start" "creating reconciliation issue" \
  "$(sr_build_details \
    --arg correlation_id "$CORRELATION_ID" \
    --arg title "$TITLE" \
    --arg project_id "$CI_PROJECT_ID" \
    --arg pipeline_id "$CI_PIPELINE_ID" \
    --arg policies "$ALL_RUNTIME_POLICIES" \
    --arg priority "$TICKET_PRIORITY" \
    --arg drift_correlation_id "$OPA_CORRELATION_ID" \
    --arg prowler_correlation_id "$OPA_PROWLER_CORRELATION_ID" \
    --argjson total_l3 "$TOTAL_L3" \
    --argjson total_l2 "$TOTAL_L2" \
    '{correlation_id:$correlation_id, drift_correlation_id:$drift_correlation_id, prowler_correlation_id:$prowler_correlation_id, title:$title, project_id:$project_id, pipeline_id:$pipeline_id, policies:$policies, priority:$priority, total_l3:$total_l3, total_l2:$total_l2}')"

HTTP_CODE="$(curl -sS \
  -o "$RESPONSE_FILE" \
  -w "%{http_code}" \
  -X POST "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/issues" \
  -H "PRIVATE-TOKEN: ${GITLAB_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")"

if [[ "$HTTP_CODE" != "201" ]]; then
  sr_fail "failed to create reconciliation ticket" 1 \
    "$(jq -cn --arg http_code "$HTTP_CODE" --arg response_file "$RESPONSE_FILE" '{http_code:$http_code,response_file:$response_file}')"
fi

TICKET_URL="$(jq -r '.web_url // ""' "$RESPONSE_FILE")"
if [[ -z "$TICKET_URL" ]]; then
  sr_fail "reconciliation ticket created but web_url missing in response" 1 \
    "$(jq -cn --arg response_file "$RESPONSE_FILE" '{response_file:$response_file}')"
fi

{
  echo "RECONCILIATION_TICKET_REQUIRED=true"
  echo "RECONCILIATION_TICKET_CREATED=true"
  echo "RECONCILIATION_TICKET_URL=${TICKET_URL}"
  echo "RECONCILIATION_CORRELATION_ID=${CORRELATION_ID}"
  echo "RECONCILIATION_DRIFT_CORRELATION_ID=${OPA_CORRELATION_ID}"
  echo "RECONCILIATION_PROWLER_CORRELATION_ID=${OPA_PROWLER_CORRELATION_ID}"
  echo "RECONCILIATION_TICKET_SKIP_REASON="
  echo "RECONCILIATION_TICKET_PRIORITY=${TICKET_PRIORITY}"
} > "$ENV_FILE"

sr_audit "INFO" "ticket_create_complete" "reconciliation issue created" \
  "$(sr_build_details \
    --arg correlation_id "$CORRELATION_ID" \
    --arg ticket_url "$TICKET_URL" \
    --arg http_code "$HTTP_CODE" \
    --arg priority "$TICKET_PRIORITY" \
    '{correlation_id:$correlation_id,ticket_url:$ticket_url,http_code:$http_code,priority:$priority}')"

exit 0
