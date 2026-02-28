#!/usr/bin/env bash
set -euo pipefail

# Smoke test for Checkov policies against known-bad fixtures.

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
OUT="$ROOT/.cloudsentinel/checkov_opa.json"

echo "[smoke] Running Checkov on fixtures..."
bash "$ROOT/shift-left/checkov/run-checkov.sh" "$ROOT/tests/checkov/fixtures" >/tmp/checkov-smoke.log

if [[ ! -f "$OUT" ]]; then
  echo "[smoke][fail] Report not found: $OUT" >&2
  exit 1
fi

assert_id() {
  local id="$1"
  jq -e --arg id "$id" '.findings[] | select(.id==$id)' "$OUT" >/dev/null 2>&1 \
    || { echo "[smoke][fail] Expected finding $id not present"; exit 1; }
}

assert_id "CKV2_CS_AZ_001"   # Storage public access

# Accept either our custom SSH rule or built-in NSG open checks.
if ! jq -e '.findings[] | select(.id=="CKV2_CS_AZ_021" or .id=="CKV2_CS_AZ_017")' "$OUT" >/dev/null 2>&1; then
  echo "[smoke][fail] Expected an SSH/NSG open finding (CKV2_CS_AZ_021 or CKV2_CS_AZ_017)" >&2
  exit 1
fi

# Ensure custom SSH/RDP checks also trigger when NSG uses source_address_prefixes list form.
if ! jq -e '.findings[] | select((.id=="CKV2_CS_AZ_021" or .id=="CKV2_CS_AZ_017") and ((.file // "") | tostring | contains("nsg_open_prefixes.tf")))' "$OUT" >/dev/null 2>&1; then
  echo "[smoke][fail] Expected CKV2_CS_AZ_021/017 finding on nsg_open_prefixes.tf (source_address_prefixes coverage)" >&2
  exit 1
fi

# Ensure at least one K8s finding is raised on manifests fixtures.
jq -e '.findings[] | select(.id | startswith("CKV_K8S_"))' "$OUT" >/dev/null 2>&1 \
  || { echo "[smoke][fail] Expected at least one CKV_K8S_* finding"; exit 1; }

echo "[smoke][pass] Checkov fixtures detected expected violations."
