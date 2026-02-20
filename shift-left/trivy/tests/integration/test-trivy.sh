#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Integration Tests v3.0
#
# Tests:
#   1. FS scan   → SCA on vulnerable-package.json fixture
#   2. Config scan → Dockerfile misconfig on Dockerfile.critical fixture
#   3. Schema validation → OPA JSON output structure
#
# NOT tested here (requires network / separate CI job):
#   - Image scan against a real registry image (tested in CI pipeline)
#
# Responsibility:
#   IaC  → Checkov tests  | Secrets (source) → Gitleaks tests
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIVY_RUNNER="$SCRIPT_DIR/../../scripts/run-trivy.sh"
FIXTURES_DIR="$SCRIPT_DIR/../fixtures"
OPA_REPORT="$SCRIPT_DIR/../../reports/opa/trivy_opa.json"

PASS=0
FAIL=0

log()   { echo -e "\033[1;32m[TEST]\033[0m $*"; }
fail()  { echo -e "\033[1;31m[FAIL]\033[0m $*"; FAIL=$((FAIL+1)); }
pass()  { echo -e "\033[1;32m[PASS]\033[0m $*"; PASS=$((PASS+1)); }
assert_gt() {
  local label="$1" actual="$2" min="$3"
  if [[ "$actual" -gt "$min" ]]; then
    pass "$label: $actual findings (expected > $min)"
  else
    fail "$label: $actual findings (expected > $min)"
  fi
}
assert_keys() {
  local label="$1" file="$2"
  local required_keys=("tool" "timestamp" "scan_type" "stats" "findings")
  for key in "${required_keys[@]}"; do
    if jq -e ".$key" "$file" >/dev/null 2>&1; then
      pass "$label — key '$key' present"
    else
      fail "$label — key '$key' MISSING in OPA report"
    fi
  done
}

# ════════════════════════════════════════════════════════════════════════════
log "Test 1: FS Scan — SCA on vulnerable-package.json"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/fs" fs
assert_gt "FS Scan TOTAL findings" \
  "$(jq '.stats.TOTAL' "$OPA_REPORT")" 0

# ════════════════════════════════════════════════════════════════════════════
log "Test 2: Config Scan — Dockerfile.critical misconfigurations"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/images/Dockerfile.critical" config
assert_gt "Config Scan TOTAL findings" \
  "$(jq '.stats.TOTAL' "$OPA_REPORT")" 0

# ════════════════════════════════════════════════════════════════════════════
log "Test 3: OPA JSON schema validation"
assert_keys "OPA Schema" "$OPA_REPORT"

# ════════════════════════════════════════════════════════════════════════════
log "Test 4: scan_type field integrity"
SCAN_TYPE_VALUE=$(jq -r '.scan_type' "$OPA_REPORT")
if [[ "$SCAN_TYPE_VALUE" == "config" ]]; then
  pass "scan_type field = 'config' ✓"
else
  fail "scan_type field = '$SCAN_TYPE_VALUE' (expected 'config')"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: PASS=$PASS | FAIL=$FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[[ "$FAIL" -eq 0 ]] && { log "SUCCESS: All Trivy integration tests passed."; exit 0; }
echo -e "\033[1;31m[CloudSentinel] FAILURE: $FAIL test(s) failed\033[0m"
exit 1
