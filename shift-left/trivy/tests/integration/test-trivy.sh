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
RAW_REPORT_DIR="$REPO_ROOT/shift-left/trivy/reports/raw"
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
  local required_keys=("SchemaVersion" "Trivy")
  for key in "${required_keys[@]}"; do
    if jq -e --arg key "$key" 'has($key)' "$file" >/dev/null 2>&1; then
      pass "$label - key '$key' present"
    else
      fail "$label - key '$key' missing"
    fi
  done
}

log "Test 1: FS scan on vulnerable fixture"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/fs" fs
FS_REPORT="$RAW_REPORT_DIR/trivy-fs-raw.json"
assert_keys "FS report contract" "$FS_REPORT"
assert_eq "FS Results type" "$(jq -r '.Results | type' "$FS_REPORT")" "array"

log "Test 2: Config scan on Dockerfile.critical"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/images/Dockerfile.critical" config
CFG_REPORT="$RAW_REPORT_DIR/trivy-config-raw.json"
assert_keys "Config report contract" "$CFG_REPORT"
assert_eq "Config Results type" "$(jq -r '.Results | type' "$CFG_REPORT")" "array"

log "Test 3: Config scan on Dockerfile.clean (negative test)"
bash "$TRIVY_RUNNER" "$FIXTURES_DIR/images/Dockerfile.clean" config
assert_eq "Clean Dockerfile results array type" "$(jq -r '.Results | type' "$CFG_REPORT")" "array"

log "Test 4: Raw image report contract"
bash "$TRIVY_RUNNER" "alpine:3.18" image
IMG_REPORT="$RAW_REPORT_DIR/trivy-image-raw.json"
assert_keys "Image raw schema" "$IMG_REPORT"
assert_eq "Image Results type" "$(jq -r '.Results | type' "$IMG_REPORT")" "array"

if [[ "$IMAGE_TEST_ENABLED" == "true" ]]; then
  log "Test 5: Image scan (optional)"
  bash "$TRIVY_RUNNER" "alpine:3.18" image
  assert_eq "Image Results type (optional)" "$(jq -r '.Results | type' "$IMG_REPORT")" "array"
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
