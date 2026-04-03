#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CLOUD_DIR="$REPO_ROOT/.cloudsentinel"
BACKUP_DIR="$(mktemp -d -t cs-normalizer-smoke-backup-XXXXXX)"

FILES=(
  "gitleaks_opa.json"
  "checkov_opa.json"
  "trivy_opa.json"
  "golden_report.json"
)

restore() {
  for f in "${FILES[@]}"; do
    if [[ -f "$BACKUP_DIR/$f" ]]; then
      cp "$BACKUP_DIR/$f" "$CLOUD_DIR/$f"
    else
      rm -f "$CLOUD_DIR/$f"
    fi
  done
  rm -rf "$BACKUP_DIR"
}
trap restore EXIT

mkdir -p "$CLOUD_DIR"
for f in "${FILES[@]}"; do
  if [[ -f "$CLOUD_DIR/$f" ]]; then
    cp "$CLOUD_DIR/$f" "$BACKUP_DIR/$f"
  fi
done

cat > "$CLOUD_DIR/gitleaks_opa.json" <<'JSON'
{"tool":"gitleaks","version":"test","status":"OK","stats":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"TOTAL":0,"EXEMPTED":0,"FAILED":0,"PASSED":0},"findings":[],"errors":[]}
JSON

cat > "$CLOUD_DIR/checkov_opa.json" <<'JSON'
{"tool":"checkov","version":"test","status":"OK","stats":{"CRITICAL":0,"HIGH":1,"MEDIUM":0,"LOW":0,"INFO":0,"TOTAL":1,"EXEMPTED":0,"FAILED":1,"PASSED":0},"findings":[{"id":"CKV2_CS_AZ_001","resource":{"name":"azurerm_storage_account.example","path":"infra/azure/student-secure/main.tf","location":{"start_line":1,"end_line":1}},"description":"demo finding","severity":"HIGH","status":"FAILED","category":"INFRASTRUCTURE_AS_CODE"}],"errors":[]}
JSON

cat > "$CLOUD_DIR/trivy_opa.json" <<'JSON'
{"tool":"trivy","version":"test","status":"OK","stats":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"TOTAL":0,"EXEMPTED":0,"FAILED":0,"PASSED":0},"findings":[],"errors":[]}
JSON

export CLOUDSENTINEL_SCHEMA_STRICT="false"
export CLOUDSENTINEL_EXECUTION_MODE="local"
python3 "$REPO_ROOT/shift-left/normalizer/normalize.py"

test -f "$CLOUD_DIR/golden_report.json"
jq -e '.schema_version | type == "string"' "$CLOUD_DIR/golden_report.json" >/dev/null
jq -e '.findings | type == "array"' "$CLOUD_DIR/golden_report.json" >/dev/null
jq -e '.quality_gate.decision == "NOT_EVALUATED"' "$CLOUD_DIR/golden_report.json" >/dev/null

echo "[smoke][normalizer] PASS"
