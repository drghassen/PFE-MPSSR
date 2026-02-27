#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel Normalizer Smoke Test
# Validates schema contract, OPA-readiness, and traceability metadata.
# ==============================================================================

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
OUT_DIR="$ROOT/.cloudsentinel"
SCHEMA="$ROOT/shift-left/normalizer/schema/cloudsentinel_report.schema.json"
GOLDEN="$OUT_DIR/golden_report.json"

mkdir -p "$OUT_DIR"

PASS=0
FAIL=0

TMP_DIR="$(mktemp -d -t normalizer-smoke.XXXXXX)"

on_exit() {
  local file
  for file in gitleaks_opa.json checkov_opa.json trivy_opa.json golden_report.json; do
    if [[ -f "$TMP_DIR/$file.bak" ]]; then
      cp "$TMP_DIR/$file.bak" "$OUT_DIR/$file"
    else
      rm -f "$OUT_DIR/$file"
    fi
  done
  rm -rf "$TMP_DIR"
}
trap on_exit EXIT

backup_report() {
  local file=$1
  if [[ -f "$OUT_DIR/$file" ]]; then
    cp "$OUT_DIR/$file" "$TMP_DIR/$file.bak"
  fi
}

pass() {
  echo "[smoke][PASS] $*"
  ((PASS++)) || true
}

fail() {
  echo "[smoke][FAIL] $*" >&2
  ((FAIL++)) || true
}

assert_jq() {
  local label=$1
  local expr=$2
  if jq -e "$expr" "$GOLDEN" >/dev/null 2>&1; then
    pass "$label"
  else
    fail "$label"
  fi
}

backup_report "gitleaks_opa.json"
backup_report "checkov_opa.json"
backup_report "trivy_opa.json"
backup_report "golden_report.json"

cat > "$OUT_DIR/gitleaks_opa.json" <<'EOF'
{
  "tool": "gitleaks",
  "version": "8.21.2",
  "has_findings": true,
  "timestamp": "2026-02-26T23:33:12Z",
  "stats": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "TOTAL": 1,
    "EXEMPTED": 0,
    "FAILED": 1,
    "PASSED": 0
  },
  "findings": [
    {
      "rule_id": "jwt-hardcoded-secret",
      "description": "JWT signing secret hardcoded in code or config",
      "file": "tests/fixtures/app.tf",
      "start_line": 7,
      "severity": "HIGH",
      "fingerprint": "fp:gitleaks:jwt-hardcoded-secret:tests/fixtures/app.tf:7",
      "status": "FAILED"
    }
  ]
}
EOF

cat > "$OUT_DIR/checkov_opa.json" <<'EOF'
{
  "tool": "checkov",
  "version": "3.2.502",
  "status": "NOT_RUN",
  "stats": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "TOTAL": 0,
    "EXEMPTED": 0,
    "FAILED": 0,
    "PASSED": 0
  },
  "errors": ["checkov_execution_error"],
  "findings": []
}
EOF

cat > "$OUT_DIR/trivy_opa.json" <<'EOF'
{
  "tool": "trivy",
  "version": "0.69.1",
  "has_findings": true,
  "timestamp": "2026-02-26T23:45:02Z",
  "scan_type": "config",
  "target": "tests/fixtures/images/Dockerfile.critical",
  "stats": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "TOTAL": 1,
    "EXEMPTED": 0,
    "FAILED": 1,
    "PASSED": 0
  },
  "findings": [
    {
      "id": "DS002",
      "message": "Image should use a non-root user",
      "category": "CONFIGURATION",
      "severity": "HIGH",
      "resource": {
        "name": "Dockerfile.critical",
        "path": "tests/fixtures/images/Dockerfile.critical"
      },
      "line": 1,
      "status": "FAILED"
    }
  ]
}
EOF

echo "[smoke] Running normalizer on controlled reports..."
CLOUDSENTINEL_EXECUTION_MODE=ci CLOUDSENTINEL_LOCAL_FAST=false bash "$ROOT/shift-left/normalizer/normalize.sh" >/dev/null

assert_jq "schema_version=1.1.0" '.schema_version == "1.1.0"'
assert_jq "execution.mode=ci" '.metadata.execution.mode == "ci"'
assert_jq "normalizer trace exists" '.metadata.normalizer.source_reports.gitleaks.tool == "gitleaks"'
assert_jq "source report hash present" '.metadata.normalizer.source_reports.gitleaks.sha256 != null'
assert_jq "checkov marked NOT_RUN" '.scanners.checkov.status == "NOT_RUN"'
assert_jq "not_run_scanners contains checkov" '.quality_gate.details.not_run_scanners | index("checkov") != null'
assert_jq "quality gate not evaluated" '.quality_gate.decision == "NOT_EVALUATED"'
assert_jq "scanner errors exposed" '.scanners.checkov.errors | length >= 1'
assert_jq "finding traceability enforced" '(.findings | map(.context.traceability.source_report != null and (.context.traceability.source_index >= 0))) | all'
assert_jq "by_category secrets count" '.summary.by_category.SECRETS >= 1'

if command -v python >/dev/null 2>&1; then
  if python - "$GOLDEN" "$SCHEMA" <<'PYCODE'
import json
import sys
from jsonschema import validate, Draft7Validator

doc_path, schema_path = sys.argv[1], sys.argv[2]
with open(doc_path, encoding="utf-8") as f:
    doc = json.load(f)
with open(schema_path, encoding="utf-8") as f:
    schema = json.load(f)
Draft7Validator.check_schema(schema)
validate(doc, schema)
PYCODE
  then
    pass "JSON schema validation passed"
  else
    fail "JSON schema validation failed"
  fi
else
  pass "Python not installed: schema validation skipped by smoke"
fi

echo ""
echo "========================================"
echo "Results: PASS=$PASS  FAIL=$FAIL"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi

exit 0
