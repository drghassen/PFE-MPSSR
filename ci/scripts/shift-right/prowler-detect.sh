#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh
source ci/scripts/shift-right/lib/azure-auth-context.sh
source ci/scripts/setup-custom-ca.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR=".cloudsentinel"
PROWLER_OUTPUT_DIR="${PROWLER_OUTPUT_DIR:-${REPO_ROOT}/.cloudsentinel/prowler/output}"
PROWLER_REPORT_PATH="${PROWLER_REPORT_PATH:-${REPO_ROOT}/shift-right/prowler/output/prowler-report.json}"
PROWLER_ENGINE_ENV_FILE="${OUTPUT_DIR}/prowler_engine.env"
PROWLER_EXCEPTIONS_FILE="${PROWLER_EXCEPTIONS_PATH:-${OUTPUT_DIR}/prowler_exceptions.json}"
EXCEPTIONS_FETCH_MODE="${EXCEPTIONS_FETCH_MODE:-strict}"
PROWLER_EXCEPTIONS_SNAPSHOT_PATH="${PROWLER_EXCEPTIONS_SNAPSHOT_PATH:-${OUTPUT_DIR}/last-known-good/prowler_exceptions.json}"
PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH="${PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH:-${PROWLER_EXCEPTIONS_SNAPSHOT_PATH}.sha256}"
PROWLER_DEGRADED_ARTIFACT="${PROWLER_DEGRADED_ARTIFACT:-${OUTPUT_DIR}/prowler_degraded_mode.json}"
AUDIT_FILE="${OUTPUT_DIR}/prowler_detect_audit.jsonl"
ENVIRONMENT="${PROWLER_ENVIRONMENT:-${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}}"
SUBSCRIPTION_IDS="${PROWLER_AZURE_SUBSCRIPTION_IDS:-${ARM_SUBSCRIPTION_ID:-}}"
AUTH_MODE="${PROWLER_AZURE_AUTH_MODE:-sp-env}"
IGNORE_EXIT_CODE_3="${PROWLER_IGNORE_EXIT_CODE_3:-true}"
OUTPUT_FORMATS="${PROWLER_OUTPUT_FORMATS:-csv json-ocsf html}"
PROWLER_DETECT_SKIP_SCAN="${PROWLER_DETECT_SKIP_SCAN:-false}"
PROWLER_OCSF_INPUT_PATH="${PROWLER_OCSF_INPUT_PATH:-}"
PROWLER_FETCH_EXCEPTIONS="${PROWLER_FETCH_EXCEPTIONS:-true}"

mkdir -p "$OUTPUT_DIR" "$PROWLER_OUTPUT_DIR" "$(dirname "$PROWLER_REPORT_PATH")"

# Fail-safe: guarantee both artifact files exist on any exit path so GitLab
# artifact upload never errors with "no matching files". The exit code of the
# job is preserved; only the file presence is guaranteed.
_ensure_artifacts_on_exit() {
  local _rc=$?
  trap - EXIT
  set +e  # cleanup must not abort on error; original exit code is restored below
  [[ -f "$PROWLER_ENGINE_ENV_FILE" ]] || touch "$PROWLER_ENGINE_ENV_FILE" 2>/dev/null
  [[ -f "$PROWLER_EXCEPTIONS_FILE" ]] || touch "$PROWLER_EXCEPTIONS_FILE" 2>/dev/null
  exit "$_rc"
}
trap _ensure_artifacts_on_exit EXIT

sr_init_guard "shift-right/prowler-detection" "$AUDIT_FILE"
sr_require_command jq python sha256sum

if [[ "$PROWLER_DETECT_SKIP_SCAN" != "true" ]]; then
  sr_require_command prowler
fi

if [[ -z "$SUBSCRIPTION_IDS" ]]; then
  sr_fail "Prowler subscription scope is missing" 1 '{}'
fi

azure_auth_init "$AUTH_MODE" "$SUBSCRIPTION_IDS"

sr_audit "INFO" "stage_start" "starting prowler detection" "$(sr_build_details \
  --arg environment "$ENVIRONMENT" \
  --arg subscriptions "$SUBSCRIPTION_IDS" \
  --arg auth_mode "$AUTH_MODE" \
  --arg output_dir "$PROWLER_OUTPUT_DIR" \
  --arg report_path "$PROWLER_REPORT_PATH" \
  --arg fetch_exceptions "$PROWLER_FETCH_EXCEPTIONS" \
  '{
    scan_target: {
      environment: $environment,
      subscriptions: $subscriptions,
      auth_mode: $auth_mode
    },
    output: {
      prowler_output_dir: $output_dir,
      normalized_report: $report_path
    },
    governance: {
      fetch_exceptions: ($fetch_exceptions == "true")
    }
  }')"

PROWLER_CMD_EXIT_CODE=0
OCSF_PATH=""

if [[ "$PROWLER_DETECT_SKIP_SCAN" == "true" ]]; then
  sr_require_nonempty_file "$PROWLER_OCSF_INPUT_PATH" "prowler ocsf input"
  OCSF_PATH="$PROWLER_OCSF_INPUT_PATH"
else
  marker_file="$(mktemp)"
  touch "$marker_file"

  read -r -a output_formats_argv <<< "$OUTPUT_FORMATS"
  prowler_cmd=(
    prowler azure
    --subscription-ids "$SUBSCRIPTION_IDS"
    --output-formats "${output_formats_argv[@]}"
    --output-directory "$PROWLER_OUTPUT_DIR"
  )

  if [[ "$IGNORE_EXIT_CODE_3" == "true" ]]; then
    prowler_cmd+=(--ignore-exit-code-3)
  fi

  # ── Prowler exclusions (structurally impossible checks) ──────────────────
  PROWLER_EXCLUDED_CHECKS_FILE="${PROWLER_EXCLUDED_CHECKS_FILE:-config/prowler/exclusions-azure-student.txt}"
  if [[ -f "$PROWLER_EXCLUDED_CHECKS_FILE" ]]; then
    while IFS= read -r _check_id || [[ -n "$_check_id" ]]; do
      [[ -z "$_check_id" || "$_check_id" == \#* ]] && continue
      prowler_cmd+=(--excluded-check "$_check_id")
    done < "$PROWLER_EXCLUDED_CHECKS_FILE"
    sr_audit "INFO" "exclusions_loaded" "prowler check exclusions applied" \
      "$(sr_build_details --arg file "$PROWLER_EXCLUDED_CHECKS_FILE" '{file:$file}')"
  fi

  # ── Prowler mutelist (design-accepted / licensing constraints) ───────────
  PROWLER_MUTELIST_FILE="${PROWLER_MUTELIST_FILE:-config/prowler/mutelist-azure-student.yaml}"
  if [[ -f "$PROWLER_MUTELIST_FILE" ]]; then
    prowler_cmd+=(--mutelist-file "$PROWLER_MUTELIST_FILE")
    sr_audit "INFO" "mutelist_loaded" "prowler mutelist applied" \
      "$(sr_build_details --arg file "$PROWLER_MUTELIST_FILE" '{file:$file}')"
  fi

  case "$AUTH_MODE" in
    sp-env)
      prowler_cmd+=(--sp-env-auth)
      ;;
    az-cli)
      prowler_cmd+=(--az-cli-auth)
      ;;
    managed-identity)
      prowler_cmd+=(--managed-identity-auth)
      ;;
    browser)
      prowler_cmd+=(--browser-auth)
      ;;
    *)
      sr_fail "invalid PROWLER_AZURE_AUTH_MODE" 1 "$(jq -cn --arg auth_mode "$AUTH_MODE" '{auth_mode:$auth_mode,allowed:["sp-env","az-cli","managed-identity","browser"]}')"
      ;;
  esac

  if "${prowler_cmd[@]}"; then
    PROWLER_CMD_EXIT_CODE=0
  else
    PROWLER_CMD_EXIT_CODE=$?
  fi

  # Prowler may return code 3 when FAIL findings exist.
  if [[ "$PROWLER_CMD_EXIT_CODE" -ne 0 && "$PROWLER_CMD_EXIT_CODE" -ne 3 ]]; then
    sr_fail "prowler execution failed" 1 "$(jq -cn --argjson exit_code "$PROWLER_CMD_EXIT_CODE" '{exit_code:$exit_code}')"
  fi

  OCSF_PATH="$(find "$PROWLER_OUTPUT_DIR" -maxdepth 1 -type f -name 'prowler-output-*.ocsf.json' -newer "$marker_file" -print | sort | tail -n1)"
  if [[ -z "$OCSF_PATH" ]]; then
    OCSF_PATH="$(ls -1t "$PROWLER_OUTPUT_DIR"/prowler-output-*.ocsf.json 2>/dev/null | head -n1 || true)"
  fi

  rm -f "$marker_file"
  sr_require_nonempty_file "$OCSF_PATH" "prowler ocsf report"
fi

sr_require_json "$OCSF_PATH" '
  type == "array"
  and all(.[]; type == "object")
' "prowler ocsf report"

TOTAL_FINDINGS="$(sr_json_number "$OCSF_PATH" 'length' 'prowler ocsf report')"
FAIL_COUNT="$(sr_json_number "$OCSF_PATH" '[.[] | select((.status_code // "" | ascii_upcase) == "FAIL")] | length' 'prowler ocsf report')"
PASS_COUNT="$(sr_json_number "$OCSF_PATH" '[.[] | select((.status_code // "" | ascii_upcase) == "PASS")] | length' 'prowler ocsf report')"
MUTED_COUNT="$(sr_json_number "$OCSF_PATH" '[.[] | select((.status_code // "" | ascii_upcase) == "MUTED")] | length' 'prowler ocsf report')"

RUN_ID="$(python - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -c \
  --arg run_id "$RUN_ID" \
  --arg environment "$ENVIRONMENT" \
  --arg finished_at "$FINISHED_AT" \
  --argjson total_findings "$TOTAL_FINDINGS" \
  --argjson fail_count "$FAIL_COUNT" \
  --argjson pass_count "$PASS_COUNT" \
  --argjson muted_count "$MUTED_COUNT" \
  '
  def parse_check_id:
    (.finding_info.uid // "") as $uid
    | if $uid == "" then "unknown"
      else (try ($uid
        | capture("^prowler-azure-(?<check>.+)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}-.+$").check) catch $uid)
      end;

  def norm_severity:
    (.severity // "LOW" | ascii_upcase) as $s
    | if ($s == "CRITICAL" or $s == "HIGH" or $s == "MEDIUM" or $s == "LOW" or $s == "INFO")
      then $s
      else "LOW"
      end;

  {
    cloudsentinel: {
      run_id: $run_id,
      correlation_id: $run_id,
      engine: "cloudsentinel-prowler-engine",
      version: "0.1.0",
      source: "prowler",
      finished_at: $finished_at,
      environment: $environment
    },
    prowler: {
      detected: ($fail_count > 0),
      summary: {
        total_findings: $total_findings,
        fail_count: $fail_count,
        pass_count: $pass_count,
        muted_count: $muted_count
      },
      items: [
        .[]
        | select((.status_code // "" | ascii_upcase) == "FAIL")
        | {
            check_id: parse_check_id,
            check_uid: (.finding_info.uid // ""),
            title: (.finding_info.title // "Prowler finding"),
            resource_id: (.resources[0].uid // .cloud.account.uid // "unknown"),
            resource_type: (.resources[0].type // "unknown"),
            region: (.resources[0].region // "global"),
            severity: norm_severity,
            status_code: ((.status_code // "FAIL") | ascii_upcase),
            status_detail: (.status_detail // ""),
            provider: "azure"
          }
      ]
    },
    errors: []
  }
' "$OCSF_PATH" > "$PROWLER_REPORT_PATH"

sr_require_json "$PROWLER_REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and ((.cloudsentinel.correlation_id // "") | type == "string" and length > 0)
  and (.prowler | type == "object")
  and (.prowler.summary | type == "object")
  and (.prowler.items | type == "array")
  and (.errors | type == "array")
  and (.prowler.detected | type == "boolean")
' "prowler normalized report"

REPORT_ERROR_COUNT="$(sr_json_number "$PROWLER_REPORT_PATH" '.errors | length' 'prowler normalized report')"
REPORT_ITEM_COUNT="$(sr_json_number "$PROWLER_REPORT_PATH" '.prowler.items | length' 'prowler normalized report')"
REPORT_DETECTED="$(jq -r '.prowler.detected' "$PROWLER_REPORT_PATH")"
PROWLER_CORRELATION_ID="$(jq -r '.cloudsentinel.correlation_id // .cloudsentinel.run_id // "unknown"' "$PROWLER_REPORT_PATH")"

sr_assert_eq "$REPORT_ITEM_COUNT" "$FAIL_COUNT" "prowler normalized report item count mismatch"
if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "prowler normalized report contains embedded errors" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
if [[ "$REPORT_DETECTED" == "true" && "$REPORT_ITEM_COUNT" -eq 0 ]]; then
  sr_fail "prowler report indicates findings but contains zero items" 1 "$(jq -cn --argjson report_item_count "$REPORT_ITEM_COUNT" '{report_item_count:$report_item_count}')"
fi
if [[ "$REPORT_DETECTED" == "false" && "$REPORT_ITEM_COUNT" -gt 0 ]]; then
  sr_fail "prowler report contains items while detected=false" 1 "$(jq -cn --argjson report_item_count "$REPORT_ITEM_COUNT" '{report_item_count:$report_item_count}')"
fi

if [[ "$PROWLER_FETCH_EXCEPTIONS" == "true" ]]; then
  FETCH_ERROR=""
  if ! python shift-right/scripts/fetch_prowler_exceptions.py \
    --output "$PROWLER_EXCEPTIONS_FILE" \
    --environment "$ENVIRONMENT"; then
    FETCH_ERROR="fetch_failed"
  fi

  if [[ -z "$FETCH_ERROR" ]]; then
    mkdir -p "$(dirname "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH")"
    cp "$PROWLER_EXCEPTIONS_FILE" "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH"
    (cd "$(dirname "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH")" && sha256sum "$(basename "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH")" > "$(basename "$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH")")
  else
    if [[ "$EXCEPTIONS_FETCH_MODE" != "degraded" ]]; then
      sr_fail "failed to fetch prowler exceptions from DefectDojo in strict mode" 1 \
        "$(jq -cn --arg mode "$EXCEPTIONS_FETCH_MODE" '{mode:$mode}')"
    fi

    sr_require_nonempty_file "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH" "prowler exceptions snapshot"
    sr_require_nonempty_file "$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH" "prowler exceptions snapshot signature"
    if ! (cd "$(dirname "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH")" && sha256sum -c "$(basename "$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH")" >/dev/null 2>&1); then
      sr_fail "degraded mode enabled but prowler snapshot signature verification failed" 1 \
        "$(jq -cn --arg snapshot \"$PROWLER_EXCEPTIONS_SNAPSHOT_PATH\" --arg sig \"$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH\" '{snapshot:$snapshot,signature:$sig}')"
    fi

    cp "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH" "$PROWLER_EXCEPTIONS_FILE"
    jq -cn \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg mode "$EXCEPTIONS_FETCH_MODE" \
      --arg snapshot "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH" \
      --arg signature "$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH" \
      --arg reason "defectdojo_fetch_failed_snapshot_used" \
      '{timestamp:$timestamp, mode:$mode, snapshot:$snapshot, signature:$signature, reason:$reason}' > "$PROWLER_DEGRADED_ARTIFACT"

    sr_audit "WARN" "exceptions_degraded_mode" "DefectDojo unavailable, using signed prowler snapshot" \
      "$(sr_build_details --arg snapshot "$PROWLER_EXCEPTIONS_SNAPSHOT_PATH" --arg signature "$PROWLER_EXCEPTIONS_SNAPSHOT_SIG_PATH" '{snapshot:$snapshot, signature:$signature}')"
  fi
else
  jq -cn \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg environment "$ENVIRONMENT" \
    '{
      cloudsentinel: {
        prowler_exceptions: {
          schema_version: "1.0.0",
          generated_at: $generated_at,
          environment: $environment,
          source: "disabled",
          meta: {
            engagement_scope: "shift-right",
            raw_risk_acceptances: 0,
            valid_exceptions: 0,
            skipped_findings: 0,
            disabled: true
          },
          exceptions: []
        }
      }
    }' > "$PROWLER_EXCEPTIONS_FILE"
fi

sr_require_nonempty_file "$PROWLER_EXCEPTIONS_FILE" "prowler exceptions"
sr_require_json "$PROWLER_EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.prowler_exceptions | type == "object")
  and (.cloudsentinel.prowler_exceptions.exceptions | type == "array")
' "prowler exceptions"

PROWLER_EXCEPTION_COUNT="$(sr_json_number "$PROWLER_EXCEPTIONS_FILE" '.cloudsentinel.prowler_exceptions.exceptions | length' 'prowler exceptions')"

{
  echo "PROWLER_DETECT_EXIT_CODE=${PROWLER_CMD_EXIT_CODE}"
  if [[ "$REPORT_DETECTED" == "true" ]]; then
    echo "PROWLER_DETECTED=true"
  else
    echo "PROWLER_DETECTED=false"
  fi
  echo "PROWLER_TOTAL_FINDINGS=${TOTAL_FINDINGS}"
  echo "PROWLER_FAIL_COUNT=${FAIL_COUNT}"
  echo "PROWLER_PASS_COUNT=${PASS_COUNT}"
  echo "PROWLER_MUTED_COUNT=${MUTED_COUNT}"
  echo "PROWLER_EXCEPTION_COUNT=${PROWLER_EXCEPTION_COUNT}"
  echo "PROWLER_CORRELATION_ID=${PROWLER_CORRELATION_ID}"
} > "$PROWLER_ENGINE_ENV_FILE"

# ── Prowler Detection Summary Table ──────────────────────────────────────────
_status="$([ "$REPORT_DETECTED" == "true" ] && echo "FAILED_CHECKS" || echo "CLEAN")"
{
  printf '┌────────────────────────────────────────────────────────────────────────────────┐\n'
  printf '│ %-78s │\n' "CloudSentinel Prowler — Azure Runtime Posture"
  printf '│ %-78s │\n' "Env: ${ENVIRONMENT}  |  Status: ${_status}  |  Total: ${TOTAL_FINDINGS}"
  printf '├──────────────────────────────────────────┬──────────────┬──────────────────────┤\n'
  printf '│ %-40s │ %-12s │ %-20s │\n' "Metric" "Value" "Notes"
  printf '├──────────────────────────────────────────┼──────────────┼──────────────────────┤\n'
  printf '│ %-40s │ %-12s │ %-20s │\n' "Findings FAIL" "${FAIL_COUNT}" "input to OPA"
  printf '│ %-40s │ %-12s │ %-20s │\n' "Findings PASS" "${PASS_COUNT}" "non-blocking"
  printf '│ %-40s │ %-12s │ %-20s │\n' "Findings MUTED" "${MUTED_COUNT}" "mutelist applied"
  printf '│ %-40s │ %-12s │ %-20s │\n' "Exceptions available" "${PROWLER_EXCEPTION_COUNT}" "DefectDojo RA"
  printf '└──────────────────────────────────────────┴──────────────┴──────────────────────┘\n'
} >&2

sr_audit "INFO" "stage_complete" "prowler detection completed" "$(sr_build_details \
  --arg  environment "$ENVIRONMENT" \
  --argjson total_findings "$TOTAL_FINDINGS" \
  --argjson fail_count "$FAIL_COUNT" \
  --argjson pass_count "$PASS_COUNT" \
  --argjson muted_count "$MUTED_COUNT" \
  --argjson exception_count "$PROWLER_EXCEPTION_COUNT" \
  --arg  report_path "$PROWLER_REPORT_PATH" \
  --arg  ocsf_path "$OCSF_PATH" \
  --arg  env_file "$PROWLER_ENGINE_ENV_FILE" \
  '{
    result: {
      environment: $environment,
      total_findings: $total_findings,
      fail_count: $fail_count,
      pass_count: $pass_count,
      muted_count: $muted_count,
      exception_count: $exception_count
    },
    artifacts: {
      normalized_report: $report_path,
      ocsf_report: $ocsf_path,
      env_file: $env_file
    }
  }')"
