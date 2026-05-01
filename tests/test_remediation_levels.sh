#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT

cat > "$TMPBIN/curl" <<'MOCKCURL'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
write_fmt=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out_file="${2:-}"; shift 2 ;;
    -w) write_fmt="${2:-}"; shift 2 ;;
    *) shift ;;
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

reset_artifacts() {
  rm -rf .cloudsentinel
  mkdir -p .cloudsentinel
  cat > .cloudsentinel/remediation_verify.env <<'EOF_ENV'
REMEDIATION_FAILED=false
EOF_ENV
  cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=false
RECONCILIATION_TICKET_CREATED=false
EOF_ENV
}

run_gate() {
  bash ci/scripts/shift-right/enforce-gates.sh >/tmp/cloudsentinel-gate.out 2>/tmp/cloudsentinel-gate.err
}

base_ci_env() {
  export ALERT_CHANNEL=gitlab
  export CI_API_V4_URL=https://gitlab.example/api/v4
  export CI_PROJECT_ID=123
  export GITLAB_API_TOKEN=token
  export CI_PROJECT_URL=https://gitlab.example/group/project
  export CI_PIPELINE_ID=99
  export CI_COMMIT_REF_NAME=main
  export CI_COMMIT_SHA=abcdefabcdefabcdefabcdefabcdefabcdefabcd
}

# T1: L0 only -> gate pass, no alert, no ticket.
reset_artifacts
base_ci_env
OPA_DRIFT_L0_COUNT=4 bash ci/scripts/shift-right/alert-critical.sh
OPA_DRIFT_L0_COUNT=4 bash ci/scripts/shift-right/create-reconciliation-ticket.sh
grep -q '^RECONCILIATION_TICKET_CREATED=false$' .cloudsentinel/reconciliation_ticket.env
OPA_DRIFT_L0_COUNT=4 run_gate
grep -q '^GATE_STATUS=PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=no_actionable_findings$' .cloudsentinel/gate.env

# T2: L1 only -> gate pass, no external alert, no ticket, WARN audit.
reset_artifacts
base_ci_env
OPA_DRIFT_L1_COUNT=2 bash ci/scripts/shift-right/alert-critical.sh
jq -e 'select(.event=="l1_notify" and .level=="WARN")' .cloudsentinel/alert_critical_audit.jsonl >/dev/null
OPA_DRIFT_L1_COUNT=2 bash ci/scripts/shift-right/create-reconciliation-ticket.sh
grep -q '^RECONCILIATION_TICKET_CREATED=false$' .cloudsentinel/reconciliation_ticket.env
OPA_DRIFT_L1_COUNT=2 run_gate
grep -q '^GATE_STATUS=PASS$' .cloudsentinel/gate.env

# T3: L2 only -> alert sent, ticket created, gate pass.
reset_artifacts
base_ci_env
OPA_PROWLER_L2_COUNT=8 OPA_PROWLER_BLOCK_REASON=ticket_and_notify_required bash ci/scripts/shift-right/alert-critical.sh
jq -e 'select(.event=="alert_sent")' .cloudsentinel/alert_critical_audit.jsonl >/dev/null
OPA_PROWLER_L2_COUNT=8 OPA_PROWLER_BLOCK_REASON=ticket_and_notify_required bash ci/scripts/shift-right/create-reconciliation-ticket.sh
grep -q '^RECONCILIATION_TICKET_CREATED=true$' .cloudsentinel/reconciliation_ticket.env
OPA_PROWLER_L2_COUNT=8 run_gate
grep -q '^GATE_STATUS=PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=l2_workflow_complete$' .cloudsentinel/gate.env

# T4: L2 only, no ticket -> soft pass.
reset_artifacts
OPA_PROWLER_L2_COUNT=8 SOFT_PASS_EXIT_CODE=0 run_gate
grep -q '^GATE_STATUS=SOFT_PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=l2_ticket_not_created$' .cloudsentinel/gate.env

# T5: L3 with custodian dry-run -> soft pass.
reset_artifacts
cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=true
RECONCILIATION_TICKET_CREATED=true
EOF_ENV
cat > .cloudsentinel/custodian.env <<'EOF_ENV'
CUSTODIAN_EXECUTED=true
CUSTODIAN_DRY_RUN=true
EOF_ENV
OPA_DRIFT_L3_COUNT=1 SOFT_PASS_EXIT_CODE=0 run_gate
grep -q '^GATE_STATUS=SOFT_PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=l3_custodian_dry_run$' .cloudsentinel/gate.env

# T6: L3 live verified -> pass with ticket.
reset_artifacts
cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=true
RECONCILIATION_TICKET_CREATED=true
EOF_ENV
cat > .cloudsentinel/custodian.env <<'EOF_ENV'
CUSTODIAN_EXECUTED=true
CUSTODIAN_DRY_RUN=false
EOF_ENV
OPA_DRIFT_L3_COUNT=1 run_gate
grep -q '^GATE_STATUS=PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=l3_verified_workflow_complete$' .cloudsentinel/gate.env

# T7: L3 live failed verification -> hard fail exit 1.
reset_artifacts
cat > .cloudsentinel/remediation_verify.env <<'EOF_ENV'
REMEDIATION_FAILED=true
EOF_ENV
cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=true
RECONCILIATION_TICKET_CREATED=true
EOF_ENV
cat > .cloudsentinel/custodian.env <<'EOF_ENV'
CUSTODIAN_EXECUTED=true
CUSTODIAN_DRY_RUN=false
EOF_ENV
if OPA_DRIFT_L3_COUNT=1 bash ci/scripts/shift-right/enforce-gates.sh >/tmp/cloudsentinel-gate.out 2>/tmp/cloudsentinel-gate.err; then
  echo "expected hard fail" >&2
  exit 1
fi
grep -q '^GATE_STATUS=HARD_FAIL$' .cloudsentinel/gate.env

# T8: L2+L3 mixed -> L3 path takes precedence.
reset_artifacts
cat > .cloudsentinel/reconciliation_ticket.env <<'EOF_ENV'
RECONCILIATION_TICKET_REQUIRED=true
RECONCILIATION_TICKET_CREATED=true
EOF_ENV
cat > .cloudsentinel/custodian.env <<'EOF_ENV'
CUSTODIAN_EXECUTED=true
CUSTODIAN_DRY_RUN=true
EOF_ENV
OPA_DRIFT_L2_COUNT=2 OPA_DRIFT_L3_COUNT=1 SOFT_PASS_EXIT_CODE=0 run_gate
grep -q '^GATE_STATUS=SOFT_PASS$' .cloudsentinel/gate.env
grep -q '^GATE_REASON=l3_custodian_dry_run$' .cloudsentinel/gate.env

echo "test_remediation_levels: OK"
