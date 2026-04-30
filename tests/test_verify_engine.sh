#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel/runtime-state

cat > /tmp/verify-pass.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
exit 0
SCRIPT
chmod +x /tmp/verify-pass.sh
cp /tmp/verify-pass.sh verification/verify-pass.sh

verification/run_verification.sh \
  --script verify-pass.sh \
  --resource-id /subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa \
  --finding-id drift:test \
  --policy deny-public-storage \
  --severity CRITICAL \
  --correlation-id corr-1 \
  --max-retries 2 \
  --timeout-seconds 2

jq -e 'select(.status=="REMEDIATION_VERIFIED")' .cloudsentinel/runtime-state/runtime-state.jsonl >/dev/null
rm -f verification/verify-pass.sh

echo "test_verify_engine: OK"
