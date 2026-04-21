#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CLOUD_DIR="$REPO_ROOT/.cloudsentinel"
BACKUP_DIR="$(mktemp -d -t cs-normalizer-smoke-backup-XXXXXX)"

FILES=(
  "gitleaks_raw.json"
  "checkov_raw.json"
  "golden_report.json"
)
TRIVY_RAW_DIR="$REPO_ROOT/shift-left/trivy/reports/raw"
TRIVY_FILES=(
  "trivy-fs-raw.json"
  "trivy-config-raw.json"
  "trivy-image-raw.json"
)

restore() {
  for f in "${FILES[@]}"; do
    if [[ -f "$BACKUP_DIR/$f" ]]; then
      cp "$BACKUP_DIR/$f" "$CLOUD_DIR/$f"
    else
      rm -f "$CLOUD_DIR/$f"
    fi
  done
  for f in "${TRIVY_FILES[@]}"; do
    if [[ -f "$BACKUP_DIR/$f" ]]; then
      cp "$BACKUP_DIR/$f" "$TRIVY_RAW_DIR/$f"
    else
      rm -f "$TRIVY_RAW_DIR/$f"
    fi
  done
  rm -rf "$BACKUP_DIR"
}
trap restore EXIT

mkdir -p "$CLOUD_DIR"
mkdir -p "$TRIVY_RAW_DIR"
for f in "${FILES[@]}"; do
  if [[ -f "$CLOUD_DIR/$f" ]]; then
    cp "$CLOUD_DIR/$f" "$BACKUP_DIR/$f"
  fi
done
for f in "${TRIVY_FILES[@]}"; do
  if [[ -f "$TRIVY_RAW_DIR/$f" ]]; then
    cp "$TRIVY_RAW_DIR/$f" "$BACKUP_DIR/$f"
  fi
done

cat > "$CLOUD_DIR/gitleaks_raw.json" <<'JSON'
[]
JSON

cat > "$CLOUD_DIR/checkov_raw.json" <<'JSON'
{"results":{"failed_checks":[{"check_id":"CKV2_CS_AZ_001","check_name":"demo finding","resource":"azurerm_storage_account.example","file_path":"infra/azure/student-secure/main.tf","file_line_range":[1,1]}]}}
JSON

cat > "$TRIVY_RAW_DIR/trivy-fs-raw.json" <<'JSON'
{"SchemaVersion":2,"Trivy":{"Version":"0.69.1"},"Results":[]}
JSON
cat > "$TRIVY_RAW_DIR/trivy-config-raw.json" <<'JSON'
{"SchemaVersion":2,"Trivy":{"Version":"0.69.1"},"Results":[]}
JSON
cat > "$TRIVY_RAW_DIR/trivy-image-raw.json" <<'JSON'
{"SchemaVersion":2,"Trivy":{"Version":"0.69.1"},"Results":[]}
JSON

export CLOUDSENTINEL_SCHEMA_STRICT="false"
export CLOUDSENTINEL_EXECUTION_MODE="local"
python3 "$REPO_ROOT/shift-left/normalizer/normalize.py"

test -f "$CLOUD_DIR/golden_report.json"
jq -e '.schema_version | type == "string"' "$CLOUD_DIR/golden_report.json" >/dev/null
jq -e '.findings | type == "array"' "$CLOUD_DIR/golden_report.json" >/dev/null
jq -e '.quality_gate.decision == "NOT_EVALUATED"' "$CLOUD_DIR/golden_report.json" >/dev/null

echo "[smoke][normalizer] PASS"
