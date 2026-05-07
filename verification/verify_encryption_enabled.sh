#!/usr/bin/env bash
set -euo pipefail

RESOURCE_ID="${1:-}"
if [[ -z "$RESOURCE_ID" ]]; then
  echo "missing resource id" >&2
  exit 2
fi

if ! command -v az >/dev/null 2>&1; then
  echo "az cli not found" >&2
  exit 3
fi

blob_enabled="$(az storage account show --ids "$RESOURCE_ID" --query 'encryption.services.blob.enabled' -o tsv 2>/dev/null || true)"
file_enabled="$(az storage account show --ids "$RESOURCE_ID" --query 'encryption.services.file.enabled' -o tsv 2>/dev/null || true)"

if [[ "${blob_enabled,,}" == "true" && "${file_enabled,,}" == "true" ]]; then
  exit 0
fi

echo "encryption is not fully enabled for $RESOURCE_ID (blob=${blob_enabled}, file=${file_enabled})" >&2
exit 1
