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

open_count="$(az network nsg show --ids "$RESOURCE_ID" --query "securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet') && (destinationPortRange=='*' || destinationPortRange=='22' || destinationPortRange=='3389') ] | length(@)" -o tsv 2>/dev/null || true)"

if [[ -z "$open_count" ]]; then
  echo "failed to evaluate NSG rules for $RESOURCE_ID" >&2
  exit 1
fi

if [[ "$open_count" == "0" ]]; then
  exit 0
fi

echo "NSG still has $open_count risky inbound allow rule(s) for $RESOURCE_ID" >&2
exit 1
