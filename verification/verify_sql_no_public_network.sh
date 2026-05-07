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

fw_count="$(az sql server firewall-rule list --ids "$RESOURCE_ID" --query 'length(@)' -o tsv 2>/dev/null || true)"
if [[ -z "$fw_count" ]]; then
  echo "failed to evaluate SQL firewall rules for $RESOURCE_ID" >&2
  exit 1
fi

if [[ "$fw_count" == "0" ]]; then
  exit 0
fi

echo "SQL server still has $fw_count firewall rule(s) for $RESOURCE_ID" >&2
exit 1
