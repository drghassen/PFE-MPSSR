#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel

cat > .cloudsentinel/opa_drift_decision.json <<'JSON'
{
  "result": {
    "violations": [
      {
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        "severity": "CRITICAL",
        "requires_remediation": true,
        "custodian_policy": "enforce-nsg-no-open-inbound",
        "verification_script": "verify_nsg_no_open_inbound.sh",
        "correlation_id": "corr-e2e"
      }
    ],
    "effective_violations": [
      {
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        "severity": "CRITICAL",
        "requires_remediation": true,
        "custodian_policy": "enforce-nsg-no-open-inbound",
        "verification_script": "verify_nsg_no_open_inbound.sh",
        "correlation_id": "corr-e2e"
      }
    ]
  }
}
JSON

cat > .cloudsentinel/opa_prowler_decision.json <<'JSON'
{"result":{"violations":[],"effective_violations":[]}}
JSON

cat > .cloudsentinel/custodian.env <<'ENV'
CUSTODIAN_EXECUTED=true
CUSTODIAN_DRY_RUN=false
ENV

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT
cat > "$TMPBIN/az" <<'MOCKAZ'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"network nsg show"* ]]; then
  echo 0
  exit 0
fi
exit 1
MOCKAZ
chmod +x "$TMPBIN/az"
export PATH="$TMPBIN:$PATH"

OPA_REQUIRES_AUTO_REMEDIATION=true \
OPA_PROWLER_REQUIRES_AUTO_REMEDIATION=false \
OPA_DRIFT_CRITICAL_COUNT=1 \
OPA_PROWLER_CRITICAL_COUNT=0 \
bash ci/scripts/shift-right/verify-remediation.sh

grep -q '^REMEDIATION_FAILED=false$' .cloudsentinel/remediation_verify.env
jq -e 'select(.status=="REMEDIATION_VERIFIED")' .cloudsentinel/runtime-state/runtime-state.jsonl >/dev/null

echo "test_verify_remediation_e2e: OK"
