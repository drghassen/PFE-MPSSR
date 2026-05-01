#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel

CI_PIPELINE_ID=12345 bash -c '
  source ci/scripts/shift-right/lib/pipeline-guard.sh
  sr_init_guard "test" ".cloudsentinel/test-audit.jsonl"
  test "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" = "cspipe-12345"
  jq -cn --arg cid "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" "{cloudsentinel:{pipeline_correlation_id:\$cid}}" > .cloudsentinel/drift-report.json
  jq -cn --arg cid "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" "{cloudsentinel:{pipeline_correlation_id:\$cid}}" > .cloudsentinel/prowler-report.json
  printf "PIPELINE_CORRELATION_ID=%s\n" "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" > .cloudsentinel/drift_engine.env
  printf "PIPELINE_CORRELATION_ID=%s\n" "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" > .cloudsentinel/prowler_engine.env
'

jq -e '.cloudsentinel.pipeline_correlation_id == "cspipe-12345"' .cloudsentinel/drift-report.json >/dev/null
jq -e '.cloudsentinel.pipeline_correlation_id == "cspipe-12345"' .cloudsentinel/prowler-report.json >/dev/null
grep -q '^PIPELINE_CORRELATION_ID=cspipe-12345$' .cloudsentinel/drift_engine.env
grep -q '^PIPELINE_CORRELATION_ID=cspipe-12345$' .cloudsentinel/prowler_engine.env

unset CLOUDSENTINEL_PIPELINE_CORRELATION_ID CI_PIPELINE_ID
fallback_drift="$(
  CI_PROJECT_ID=123 CI_PIPELINE_IID=77 CI_RUNNER_ID=5 CI_COMMIT_SHA=abcdef CI_PROJECT_PATH=group/project bash -c '
    source ci/scripts/shift-right/lib/pipeline-guard.sh
    sr_init_guard "test-drift" ".cloudsentinel/fallback-drift-audit.jsonl"
    printf "%s" "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID"
  '
)"
fallback_prowler="$(
  CI_PROJECT_ID=123 CI_PIPELINE_IID=77 CI_RUNNER_ID=5 CI_COMMIT_SHA=abcdef CI_PROJECT_PATH=group/project bash -c '
    source ci/scripts/shift-right/lib/pipeline-guard.sh
    sr_init_guard "test-prowler" ".cloudsentinel/fallback-prowler-audit.jsonl"
    printf "%s" "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID"
  '
)"
test "$fallback_drift" = "$fallback_prowler"
grep -Eq '^cspipe-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' <<< "$fallback_drift"

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT
cat > "$TMPBIN/curl" <<'MOCKCURL'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
payload=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out_file="${2:-}"; shift 2 ;;
    -d|--data|--data-binary) payload="${2:-}"; shift 2 ;;
    -w) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s' "$payload" > .cloudsentinel/last-ticket-payload.json
if [[ -n "$out_file" ]]; then
  printf '%s\n' '{"web_url":"https://gitlab.example/group/project/-/issues/321"}' > "$out_file"
fi
printf '201'
MOCKCURL
chmod +x "$TMPBIN/curl"
export PATH="$TMPBIN:$PATH"

CI_PIPELINE_ID=12345 \
CI_API_V4_URL=https://gitlab.example/api/v4 \
CI_PROJECT_ID=123 \
GITLAB_API_TOKEN=token \
CI_PROJECT_URL=https://gitlab.example/group/project \
CI_COMMIT_REF_NAME=main \
CI_COMMIT_SHA=abcdef \
OPA_DRIFT_L2_COUNT=1 \
OPA_PIPELINE_CORRELATION_ID=cspipe-12345 \
OPA_CORRELATION_ID=drift-engine-1 \
OPA_PROWLER_CORRELATION_ID=prowler-engine-1 \
bash ci/scripts/shift-right/create-reconciliation-ticket.sh

jq -r '.description' .cloudsentinel/last-ticket-payload.json | grep -q 'Pipeline Correlation ID: `cspipe-12345`'
jq -r '.description' .cloudsentinel/last-ticket-payload.json | grep -q 'Drift Engine Correlation ID: `drift-engine-1`'
jq -r '.description' .cloudsentinel/last-ticket-payload.json | grep -q 'Prowler Correlation ID: `prowler-engine-1`'

echo "test_correlation_id: OK"
