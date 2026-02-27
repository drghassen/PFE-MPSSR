#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# CloudSentinel - Trivy Integration Tests v4.0
# - Positive FS + config tests
# - Negative config test (clean Dockerfile)
# - OPA report contract checks
# - Optional image test (network-dependent)
###############################################################################

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TRIVY_RUNNER="$REPO_ROOT/shift-left/trivy/scripts/run-trivy.sh"
FIXTURES_DIR="$REPO_ROOT/shift-left/trivy/tests/fixtures"
OPA_REPORT="$REPO_ROOT/.cloudsentinel/trivy_opa.json"
IMAGE_TEST_ENABLED="${TRIVY_ENABLE_IMAGE_TEST:-false}"

PASS=0
FAIL=0

log()  { echo -e "\033[1;32m[TEST]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; FAIL=$((FAIL+1)); }
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; PASS=$((PASS+1)); }

assert_gt() {
  local label="$1" actual="$2" min="$3"
  if [[ "$actual" -gt "$min" ]]; then
    pass "$label: $actual (expected > $min)"
  else
    fail "$label: $actual (expected > $min)"
  fi
}

assert_eq() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    pass "$label: $actual"
  else
    fail "$label: $actual (expected $expected)"
  fi
}

assert_keys() {
  local label="$1" file="$2"
  local required_keys=("tool" "timestamp" "scan_type" "has_findings" "stats" "findings")
  for key in "${required_keys[@]}"; do
    if jq -e --arg key "$key" 'has($key)' "$file" >/dev/null 2>&1; then
      pass "$label - key '$key' present"
    else
      fail "$label - key '$key' missing"
    fi
  done
}

assert_not_not_run() {
  local label="$1" file="$2"
  if jq -e '.status == "NOT_RUN"' "$file" >/dev/null 2>&1; then
    fail "$label: report is NOT_RUN"
  else
    pass "$label: report executed"
  fi
}

log "Test 1: FS scan on vulnerable fixture"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/fs" fs
assert_not_not_run "FS scan" "$OPA_REPORT"
assert_eq "FS scan_type" "$(jq -r '.scan_type' "$OPA_REPORT")" "fs"
assert_keys "FS report contract" "$OPA_REPORT"

log "Test 2: Config scan on Dockerfile.critical"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/images/Dockerfile.critical" config
assert_gt "Critical Dockerfile stats.TOTAL" "$(jq '.stats.TOTAL' "$OPA_REPORT")" 0
assert_eq "Critical Dockerfile has_findings" "$(jq -r '.has_findings' "$OPA_REPORT")" "true"

log "Test 3: Config scan on Dockerfile.clean (negative test)"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/images/Dockerfile.clean" config
assert_eq "Clean Dockerfile stats.TOTAL" "$(jq '.stats.TOTAL' "$OPA_REPORT")" "0"
assert_eq "Clean Dockerfile has_findings" "$(jq -r '.has_findings' "$OPA_REPORT")" "false"

log "Test 4: OPA report contract"
assert_keys "OPA schema" "$OPA_REPORT"
assert_eq "scan_type after config scan" "$(jq -r '.scan_type' "$OPA_REPORT")" "config"

if [[ "$IMAGE_TEST_ENABLED" == "true" ]]; then
  log "Test 5: Image scan (optional)"
  bash "$TRIVY_RUNNER" "alpine:3.18" image
  assert_not_not_run "Image scan" "$OPA_REPORT"
  assert_eq "scan_type after image scan" "$(jq -r '.scan_type' "$OPA_REPORT")" "image"
else
  log "Test 5: Image scan skipped (set TRIVY_ENABLE_IMAGE_TEST=true to enable)"
fi

echo ""
echo "============================================="
echo "Results: PASS=$PASS | FAIL=$FAIL"
echo "============================================="

if [[ "$FAIL" -eq 0 ]]; then
  log "SUCCESS: all Trivy integration tests passed."
  exit 0
fi

echo -e "\033[1;31m[CloudSentinel] FAILURE: $FAIL test(s) failed\033[0m"
exit 1
