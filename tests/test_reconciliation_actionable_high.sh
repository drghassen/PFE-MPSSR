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

out_file=""
write_fmt=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out_file="${2:-}"
      shift 2
      ;;
    -w)
      write_fmt="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$out_file" ]]; then
  printf '%s\n' '{"web_url":"https://gitlab.example/group/project/-/issues/321"}' > "$out_file"
fi

if [[ -n "$write_fmt" ]]; then
  printf '201'
fi
MOCKCURL
chmod +x "$TMPBIN/curl"
export PATH="$TMPBIN:$PATH"

CI_API_V4_URL=https://gitlab.example/api/v4 \
CI_PROJECT_ID=123 \
GITLAB_API_TOKEN=token \
CI_PROJECT_URL=https://gitlab.example/group/project \
CI_PIPELINE_ID=100 \
CI_COMMIT_REF_NAME=main \
CI_COMMIT_SHA=abcdefabcdefabcdefabcdefabcdefabcdefabcd \
OPA_DRIFT_L2_COUNT=0 \
OPA_PROWLER_L2_COUNT=4 \
OPA_DRIFT_BLOCK=false \
OPA_PROWLER_BLOCK=true \
OPA_CORRELATION_ID=drift-corr-1 \
OPA_PROWLER_CORRELATION_ID=prowler-corr-1 \
bash ci/scripts/shift-right/create-reconciliation-ticket.sh

grep -q '^RECONCILIATION_TICKET_REQUIRED=true$' .cloudsentinel/reconciliation_ticket.env
grep -q '^RECONCILIATION_TICKET_CREATED=true$' .cloudsentinel/reconciliation_ticket.env
grep -q '^RECONCILIATION_DRIFT_CORRELATION_ID=drift-corr-1$' .cloudsentinel/reconciliation_ticket.env
grep -q '^RECONCILIATION_PROWLER_CORRELATION_ID=prowler-corr-1$' .cloudsentinel/reconciliation_ticket.env

echo "test_reconciliation_actionable_high: OK"
