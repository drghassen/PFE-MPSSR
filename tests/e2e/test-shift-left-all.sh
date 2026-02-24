#!/usr/bin/env bash
set -euo pipefail

log() { echo "[E2E][SHIFT-LEFT] $*"; }
fail() { echo "[E2E][SHIFT-LEFT][ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

require_cmd bash
require_cmd jq
require_cmd git
require_cmd gitleaks
require_cmd checkov
require_cmd trivy
require_cmd opa

FIXTURES_DIR="$REPO_ROOT/tests/fixtures"
IAC_FIXTURE="$FIXTURES_DIR/iac/azure_storage_public.tf"
DOCKER_FIXTURE="$FIXTURES_DIR/docker/Dockerfile.insecure"

[[ -f "$IAC_FIXTURE" ]] || fail "Missing IaC fixture: $IAC_FIXTURE"
[[ -f "$DOCKER_FIXTURE" ]] || fail "Missing Docker fixture: $DOCKER_FIXTURE"

TMP_SECRET_FILE="$(mktemp "$REPO_ROOT/.tmp_gitleaks_secret.XXXXXX")"
cleanup() {
  git reset -q -- "$TMP_SECRET_FILE" >/dev/null 2>&1 || true
  rm -f "$TMP_SECRET_FILE"
}
trap cleanup EXIT

log "Preparing temp secret for Gitleaks staged scan..."
cat > "$TMP_SECRET_FILE" <<'EOF'
aws_access_key_id = "AKIA1234567890ABCDEF"
aws_secret_access_key = "abcdEFGHijklMNOPqrstUVWXyz1234567890ABCD"
EOF

git add "$TMP_SECRET_FILE"

log "Running Gitleaks pre-commit hook (staged scan)..."
bash shift-left/gitleaks/pre-commit-hook.sh

GITLEAKS_REPORT=".cloudsentinel/gitleaks_opa.json"
[[ -f "$GITLEAKS_REPORT" ]] || fail "Gitleaks report not found: $GITLEAKS_REPORT"
GITLEAKS_TOTAL="$(jq -r '.stats.TOTAL // 0' "$GITLEAKS_REPORT")"
[[ "$GITLEAKS_TOTAL" -gt 0 ]] || fail "Expected Gitleaks findings > 0, got $GITLEAKS_TOTAL"
log "Gitleaks OK: findings=$GITLEAKS_TOTAL"

log "Running Checkov on fixtures..."
bash shift-left/checkov/run-checkov.sh "$FIXTURES_DIR/iac"

CHECKOV_REPORT=".cloudsentinel/checkov_opa.json"
[[ -f "$CHECKOV_REPORT" ]] || fail "Checkov report not found: $CHECKOV_REPORT"
CHECKOV_TOTAL="$(jq -r '.stats.TOTAL // 0' "$CHECKOV_REPORT")"
[[ "$CHECKOV_TOTAL" -gt 0 ]] || fail "Expected Checkov findings > 0, got $CHECKOV_TOTAL"
log "Checkov OK: findings=$CHECKOV_TOTAL"

log "Running Trivy config scan on Dockerfile fixture..."
bash shift-left/trivy/scripts/run-trivy.sh "$DOCKER_FIXTURE" config

TRIVY_REPORT="shift-left/trivy/reports/opa/trivy_opa.json"
[[ -f "$TRIVY_REPORT" ]] || fail "Trivy report not found: $TRIVY_REPORT"
TRIVY_TOOL="$(jq -r '.tool // empty' "$TRIVY_REPORT")"
[[ "$TRIVY_TOOL" == "trivy" ]] || fail "Unexpected Trivy report tool: '$TRIVY_TOOL'"
TRIVY_STATUS="$(jq -r '.status // empty' "$TRIVY_REPORT")"
[[ "$TRIVY_STATUS" != "NOT_RUN" ]] || fail "Trivy status NOT_RUN — check ignorefile/config errors"
TRIVY_TOTAL="$(jq -r '.stats.TOTAL // 0' "$TRIVY_REPORT")"
if [[ "$TRIVY_TOTAL" -eq 0 ]]; then
  log "Trivy completed with 0 findings (acceptable for config fixtures)."
else
  log "Trivy OK: findings=$TRIVY_TOTAL"
fi

log "Normalizing reports..."
CLOUDSENTINEL_EXECUTION_MODE="ci" CLOUDSENTINEL_LOCAL_FAST="false" ENVIRONMENT="dev" \
  bash shift-left/normalizer/normalize.sh

GOLDEN_REPORT=".cloudsentinel/golden_report.json"
[[ -f "$GOLDEN_REPORT" ]] || fail "Golden report not found: $GOLDEN_REPORT"

log "Evaluating OPA (advisory)..."
OPA_PREFER_CLI="true" bash shift-left/opa/run-opa.sh --advisory

OPA_DECISION=".cloudsentinel/opa_decision.json"
[[ -f "$OPA_DECISION" ]] || fail "OPA decision not found: $OPA_DECISION"
OPA_ALLOW="$(jq -r '.result.allow // false' "$OPA_DECISION")"
OPA_DENY="$(jq -r '.result.deny | join(" | ")' "$OPA_DECISION")"
log "OPA decision generated (allow=$OPA_ALLOW)"
[[ -n "$OPA_DENY" ]] && log "OPA deny reasons: $OPA_DENY"

log "SUCCESS: Shift-Left toolchain validated."
