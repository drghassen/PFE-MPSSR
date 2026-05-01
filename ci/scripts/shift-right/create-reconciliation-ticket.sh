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

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_PROWLER_CUSTODIAN_POLICIES="${OPA_PROWLER_CUSTODIAN_POLICIES:-}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-}"
CI_PROJECT_URL="${CI_PROJECT_URL:-unknown}"
CI_PIPELINE_ID="${CI_PIPELINE_ID:-unknown}"
CI_COMMIT_REF_NAME="${CI_COMMIT_REF_NAME:-unknown}"
CI_COMMIT_SHA="${CI_COMMIT_SHA:-unknown}"

TOTAL_CRITICAL=$((OPA_DRIFT_CRITICAL_COUNT + OPA_PROWLER_CRITICAL_COUNT))
ALL_RUNTIME_POLICIES="$(jq -nr \
  --arg drift "$OPA_CUSTODIAN_POLICIES" \
  --arg prowler "$OPA_PROWLER_CUSTODIAN_POLICIES" \
  '[($drift|split(",")[]?), ($prowler|split(",")[]?)]
   | map(gsub("^\\s+|\\s+$";""))
   | map(select(length > 0))
   | unique
   | join(",")')"
CORRELATION_ID="${OPA_CORRELATION_ID:-$OPA_PROWLER_CORRELATION_ID}"
if [[ -z "$CORRELATION_ID" ]]; then
  CORRELATION_ID="unknown"
fi

if [[ "$TOTAL_CRITICAL" -eq 0 ]]; then
  {
    echo "RECONCILIATION_TICKET_REQUIRED=false"
    echo "RECONCILIATION_TICKET_CREATED=false"
    echo "RECONCILIATION_TICKET_URL="
    echo "RECONCILIATION_CORRELATION_ID=${CORRELATION_ID}"
    echo "RECONCILIATION_TICKET_SKIP_REASON=no_critical_findings"
  } > "$ENV_FILE"

  sr_audit "INFO" "skip" "no critical findings - reconciliation ticket not required" \
    "$(sr_build_details \
      --argjson total_critical "$TOTAL_CRITICAL" \
      --arg correlation_id "$CORRELATION_ID" \
      '{total_critical:$total_critical, correlation_id:$correlation_id}')"
  exit 0
fi

sr_require_env CI_API_V4_URL CI_PROJECT_ID GITLAB_API_TOKEN

TITLE="CloudSentinel IaC Reconciliation Required (${CORRELATION_ID})"
DESCRIPTION="$(cat <<EOF
## CloudSentinel Drift Reconciliation

- Correlation ID: \`${CORRELATION_ID}\`
- Pipeline: ${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}
- Branch: \`${CI_COMMIT_REF_NAME}\`
- Commit: \`${CI_COMMIT_SHA}\`
- Critical findings: drift=${OPA_DRIFT_CRITICAL_COUNT}, prowler=${OPA_PROWLER_CRITICAL_COUNT}
- Runtime policies executed/planned: \`${ALL_RUNTIME_POLICIES}\`

### Required actions
1. Update Terraform source of truth for remediated resources.
2. Open merge request with IaC fix.
3. Run terraform plan/apply in the target environment.
4. Confirm next shift-right scan no longer reports this drift.

This ticket is mandatory to prevent drift recurrence after runtime hotfixes.
EOF
)"

PAYLOAD="$(jq -cn \
  --arg title "$TITLE" \
  --arg description "$DESCRIPTION" \
  --arg labels "security,drift,reconciliation,critical" \
  '{
    title: $title,
    description: $description,
    labels: $labels
  }')"

sr_audit "WARN" "ticket_create_start" "creating reconciliation issue" \
  "$(sr_build_details \
    --arg correlation_id "$CORRELATION_ID" \
    --arg title "$TITLE" \
    --arg project_id "$CI_PROJECT_ID" \
    --arg pipeline_id "$CI_PIPELINE_ID" \
    --arg policies "$ALL_RUNTIME_POLICIES" \
    '{
      correlation_id: $correlation_id,
      title: $title,
      project_id: $project_id,
      pipeline_id: $pipeline_id,
      policies: $policies
    }')"

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
  echo "RECONCILIATION_TICKET_SKIP_REASON="
} > "$ENV_FILE"

sr_audit "INFO" "ticket_create_complete" "reconciliation issue created" \
  "$(sr_build_details \
    --arg correlation_id "$CORRELATION_ID" \
    --arg ticket_url "$TICKET_URL" \
    --arg http_code "$HTTP_CODE" \
    '{correlation_id:$correlation_id,ticket_url:$ticket_url,http_code:$http_code}')"

exit 0
