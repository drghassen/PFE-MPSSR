#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel Pre-Commit Smoke Test
# Validates non-blocking local behavior:
#   1) secret detected and OPA allow
#   2) secret detected and OPA deny (still advisory)
#   3) OPA unavailable (runner missing) and commit flow still non-blocking
# ==============================================================================

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
PASS=0
FAIL=0

cleanup_repos=()

on_exit() {
  local repo
  for repo in "${cleanup_repos[@]:-}"; do
    rm -rf "$repo"
  done
}
trap on_exit EXIT

pass() {
  echo "[smoke][PASS] $*"
  ((PASS++)) || true
}

fail() {
  echo "[smoke][FAIL] $*" >&2
  ((FAIL++)) || true
}

copy_runtime() {
  local repo=$1
  mkdir -p "$repo/shift-left/pre-commit" \
           "$repo/shift-left/gitleaks" \
           "$repo/shift-left/normalizer/schema" \
           "$repo/shift-left/opa" \
           "$repo/policies/opa"

  cp "$ROOT/shift-left/pre-commit/pre-commit.sh" "$repo/shift-left/pre-commit/pre-commit.sh"
  cp "$ROOT/shift-left/gitleaks/run-gitleaks.sh" "$repo/shift-left/gitleaks/run-gitleaks.sh"
  cp "$ROOT/shift-left/gitleaks/gitleaks.toml" "$repo/shift-left/gitleaks/gitleaks.toml"
  cp "$ROOT/shift-left/normalizer/normalize.sh" "$repo/shift-left/normalizer/normalize.sh"
  cp "$ROOT/shift-left/normalizer/schema/cloudsentinel_report.schema.json" "$repo/shift-left/normalizer/schema/cloudsentinel_report.schema.json"
  cp "$ROOT/shift-left/opa/run-opa.sh" "$repo/shift-left/opa/run-opa.sh"
  cp "$ROOT/policies/opa/pipeline_decision.rego" "$repo/policies/opa/pipeline_decision.rego"
  cp "$ROOT/policies/opa/exceptions.json" "$repo/policies/opa/exceptions.json"

  chmod +x "$repo/shift-left/pre-commit/pre-commit.sh" \
           "$repo/shift-left/gitleaks/run-gitleaks.sh" \
           "$repo/shift-left/normalizer/normalize.sh" \
           "$repo/shift-left/opa/run-opa.sh"
}

make_test_repo() {
  local repo
  repo="$(mktemp -d -t cloudsentinel-precommit.XXXXXX)"
  cleanup_repos+=("$repo")
  copy_runtime "$repo"

  git -C "$repo" init -q
  git -C "$repo" config user.email "precommit-smoke@example.com"
  git -C "$repo" config user.name "precommit-smoke"

  cat > "$repo/README.md" <<'EOF'
# Pre-Commit Smoke Repo
EOF
  git -C "$repo" add README.md
  git -C "$repo" commit -q -m "init"
  echo "$repo"
}

run_precommit() {
  local repo=$1
  local log=$2
  (
    cd "$repo"
    # Force CLI mode to keep tests deterministic even if a local OPA server is running.
    OPA_LOCAL_MODE="cli" \
      OPA_LOCAL_ADVISORY="true" \
      bash shift-left/pre-commit/pre-commit.sh
  ) >"$log" 2>&1
}

echo "=== TEST 1: Secret detected + OPA allow (advisory) ==="
REPO1="$(make_test_repo)"
LOG1="$(mktemp -t precommit-smoke-1.XXXXXX.log)"
cleanup_repos+=("$LOG1")
cat > "$REPO1/app.tf" <<'EOF'
jwt_secret = "supersecretvalue12345"
EOF
git -C "$REPO1" add app.tf
if run_precommit "$REPO1" "$LOG1"; then
  pass "Pre-commit exits 0 when a secret is detected"
else
  fail "Pre-commit exited non-zero when a secret is detected"
fi

if jq -e '.stats.TOTAL >= 1' "$REPO1/.cloudsentinel/gitleaks_opa.json" >/dev/null 2>&1; then
  pass "Gitleaks finding recorded"
else
  fail "Expected finding missing in gitleaks_opa.json"
fi

if jq -e '.result.allow == true' "$REPO1/.cloudsentinel/opa_decision_precommit.json" >/dev/null 2>&1; then
  pass "OPA advisory returned ALLOW"
else
  fail "OPA advisory did not return ALLOW"
fi

echo "=== TEST 2: Secret detected + OPA deny (still non-blocking) ==="
REPO2="$(make_test_repo)"
LOG2="$(mktemp -t precommit-smoke-2.XXXXXX.log)"
cleanup_repos+=("$LOG2")
cat > "$REPO2/critical.tf" <<'EOF'
aws_key = "AKIA1234567890ABCDEF"
EOF
git -C "$REPO2" add critical.tf

# Force a deterministic deny path for this smoke test.
cat >> "$REPO2/policies/opa/pipeline_decision.rego" <<'EOF'

deny[msg] if {
  count(object.get(input, "findings", [])) > 0
  msg := "smoke-test: deny when findings are present"
}
EOF

if run_precommit "$REPO2" "$LOG2"; then
  pass "Pre-commit exits 0 when OPA returns DENY"
else
  fail "Pre-commit exited non-zero when OPA returns DENY"
fi

if jq -e '.stats.TOTAL >= 1' "$REPO2/.cloudsentinel/gitleaks_opa.json" >/dev/null 2>&1; then
  pass "Gitleaks finding recorded"
else
  fail "Expected finding missing in gitleaks_opa.json"
fi

if jq -e '.result.allow == false' "$REPO2/.cloudsentinel/opa_decision_precommit.json" >/dev/null 2>&1; then
  pass "OPA advisory returned DENY"
else
  fail "OPA advisory did not return DENY"
fi

echo "=== TEST 3: OPA runner missing + advisory remains non-blocking ==="
REPO3="$(make_test_repo)"
LOG3="$(mktemp -t precommit-smoke-3.XXXXXX.log)"
cleanup_repos+=("$LOG3")
cat > "$REPO3/local.tf" <<'EOF'
jwt_secret = "anothersecretvalue67890"
EOF
git -C "$REPO3" add local.tf
rm -f "$REPO3/shift-left/opa/run-opa.sh"

if run_precommit "$REPO3" "$LOG3"; then
  pass "Pre-commit exits 0 when OPA runner is missing"
else
  fail "Pre-commit exited non-zero when OPA runner is missing"
fi

if grep -q "OPA runner not found" "$LOG3"; then
  pass "Missing OPA runner warning emitted"
else
  fail "Expected warning for missing OPA runner not found"
fi

echo ""
echo "========================================"
echo "Results: PASS=$PASS  FAIL=$FAIL"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi

exit 0
