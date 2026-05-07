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

deny_count="$(az network nsg show --ids "$RESOURCE_ID" --query "securityRules[?direction=='Inbound' && access=='Deny' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0')] | length(@)" -o tsv 2>/dev/null || true)"

if [[ -z "$deny_count" ]]; then
  echo "failed to evaluate deny-all inbound baseline for $RESOURCE_ID" >&2
  exit 1
fi

if [[ "$deny_count" -gt 0 ]]; then
  exit 0
fi

echo "NSG missing deny-all inbound baseline for $RESOURCE_ID" >&2
exit 1
