#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Gitleaks Smoke Test — CloudSentinel
#
# Vérifie :
#   1. (POSITIVE) La fixture vulnérable déclenche des findings attendus
#   2. (NEGATIVE) La fixture propre ne déclenche aucun finding
#
# Prérequis : gitleaks, jq installés
# ==============================================================================

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CONFIG="$ROOT/shift-left/gitleaks/gitleaks.toml"
OUT_DIR="$ROOT/.cloudsentinel"
FIXTURE_DIR="$ROOT/tests/gitleaks/fixtures"

mkdir -p "$OUT_DIR"

PASS=0
FAIL=0

assert_finding() {
  local label="$1"
  local report="$2"
  local rule_id="$3"
  if jq -e --arg id "$rule_id" '.[] | select(.RuleID == $id)' "$report" > /dev/null 2>&1; then
    echo "[smoke][PASS] $label → finding '$rule_id' detected as expected"
    ((PASS++)) || true
  else
    echo "[smoke][FAIL] $label → expected finding '$rule_id' NOT detected" >&2
    ((FAIL++)) || true
  fi
}

assert_clean() {
  local label="$1"
  local report="$2"
  local count
  count=$(jq 'length' "$report" 2>/dev/null || echo 0)
  if [[ "$count" -eq 0 ]]; then
    echo "[smoke][PASS] $label → no findings detected (clean fixture)"
    ((PASS++)) || true
  else
    echo "[smoke][FAIL] $label → $count unexpected finding(s) in clean fixture" >&2
    jq -r '.[] | "[" + .RuleID + "] " + .File + ":" + (.StartLine|tostring)' "$report" >&2
    ((FAIL++)) || true
  fi
}

# --- TEST 1: Fixture vulnérable ---
echo ""
echo "=== TEST 1: Vulnerable fixture ==="
RAW_VULN="$(mktemp -t gitleaks-smoke-vuln.XXXXXX.json)"
trap 'rm -f "$RAW_VULN"' EXIT

gitleaks detect \
  --no-git \
  --source "$FIXTURE_DIR/secrets_sample.tf" \
  --config "$CONFIG" \
  --report-format json \
  --report-path "$RAW_VULN" \
  --exit-code 0 \
  --redact \
  > /dev/null 2>&1 || true

assert_finding "AWS Access Key"         "$RAW_VULN" "aws-access-key-id"
assert_finding "Terraform Cloud Token"  "$RAW_VULN" "terraform-cloud-token"
assert_finding "JWT Secret"             "$RAW_VULN" "jwt-hardcoded-secret"

# --- TEST 2: Fixture propre ---
echo ""
echo "=== TEST 2: Clean fixture ==="
RAW_CLEAN="$(mktemp -t gitleaks-smoke-clean.XXXXXX.json)"
trap 'rm -f "$RAW_VULN" "$RAW_CLEAN"' EXIT

gitleaks detect \
  --no-git \
  --source "$FIXTURE_DIR/clean_sample.tf" \
  --config "$CONFIG" \
  --report-format json \
  --report-path "$RAW_CLEAN" \
  --exit-code 0 \
  --redact \
  > /dev/null 2>&1 || true

assert_clean "Clean Terraform file" "$RAW_CLEAN"

# --- Résultat final ---
echo ""
echo "========================================"
echo "Results: PASS=$PASS  FAIL=$FAIL"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
  echo "[smoke][FAIL] Gitleaks smoke test failed." >&2
  exit 1
fi

echo "[smoke][PASS] All Gitleaks assertions passed."
exit 0
