#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT

cat > "$TMPBIN/curl" <<'MOCKCURL'
#!/usr/bin/env bash
set -euo pipefail
exit 0
MOCKCURL
chmod +x "$TMPBIN/curl"

export PATH="$TMPBIN:$PATH"

ALERT_CHANNEL=gitlab \
CI_API_V4_URL=https://gitlab.example/api/v4 \
CI_PROJECT_ID=123 \
GITLAB_API_TOKEN=token \
OPA_DRIFT_CRITICAL_COUNT=1 \
OPA_PROWLER_CRITICAL_COUNT=0 \
CI_PROJECT_URL=https://gitlab.example/group/project \
CI_PIPELINE_ID=99 \
CI_COMMIT_REF_NAME=main \
bash ci/scripts/shift-right/alert-critical.sh

jq -e 'select(.event=="alert_sent")' .cloudsentinel/alert_critical_audit.jsonl >/dev/null

echo "test_alert_critical: OK"
