#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel

cat > .cloudsentinel/remediation_verify.env <<'EOF_ENV'
REMEDIATION_FAILED=false
EOF_ENV

cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=false
RECONCILIATION_TICKET_CREATED=false
EOF_ENV

OPA_DRIFT_L1_COUNT=4 \
OPA_PROWLER_L1_COUNT=0 \
bash ci/scripts/shift-right/enforce-gates.sh

grep -q '^GATE_STATUS=PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=no_actionable_findings$' .cloudsentinel/gate.env

echo "test_enforce_manual_only: OK"
