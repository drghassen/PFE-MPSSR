#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel — Contract Test
# Verifies that all raw scanner reports exist, are valid JSON,
# and contain the expected top-level structure before normalization.

fail() { echo "[contract][FAIL] $*" >&2; exit 1; }
ok()   { echo "[contract][OK]   $*"; }

check_json() {
  local file="$1"
  local field="$2"
  local label="$3"

  [[ -f "$file" ]] || fail "$label: file not found → $file"
  jq empty "$file" 2>/dev/null || fail "$label: invalid JSON → $file"
  jq -e "$field" "$file" >/dev/null 2>&1 || fail "$label: missing field '$field' → $file"
  ok "$label"
}

# Gitleaks
check_json ".cloudsentinel/gitleaks_raw.json" \
  "(. | type) == \"array\" or has(\"leaks\") or has(\"findings\")" \
  "gitleaks_raw"

# Checkov
check_json ".cloudsentinel/checkov_raw.json" \
  "has(\"results\") or has(\"checks\")" \
  "checkov_raw"

# Trivy FS
check_json "shift-left/trivy/reports/raw/trivy-fs-raw.json" \
  "has(\"SchemaVersion\")" \
  "trivy_fs_raw"

# Trivy Config
check_json "shift-left/trivy/reports/raw/trivy-config-raw.json" \
  "has(\"SchemaVersion\")" \
  "trivy_config_raw"

# Cloud-init analysis
check_json ".cloudsentinel/cloudinit_analysis.json" \
  "has(\"resources_analyzed\") and has(\"summary\")" \
  "cloudinit_analysis"

echo "[contract][SKIP] Image scan jobs removed from pipeline - monitoring via DefectDojo only"

echo "[contract] All checks passed."
