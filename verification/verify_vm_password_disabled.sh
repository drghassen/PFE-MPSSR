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

value="$(az vm show --ids "$RESOURCE_ID" --query 'osProfile.linuxConfiguration.disablePasswordAuthentication' -o tsv 2>/dev/null || true)"
if [[ "${value,,}" == "true" ]]; then
  exit 0
fi

echo "disablePasswordAuthentication is not true for $RESOURCE_ID" >&2
exit 1
