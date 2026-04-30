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

public_access="$(az storage account show --ids "$RESOURCE_ID" --query 'allowBlobPublicAccess' -o tsv 2>/dev/null || true)"
default_action="$(az storage account show --ids "$RESOURCE_ID" --query 'networkRuleSet.defaultAction' -o tsv 2>/dev/null || true)"

if [[ "${public_access,,}" == "false" && "${default_action^^}" == "DENY" ]]; then
  exit 0
fi

echo "storage account is not private for $RESOURCE_ID (allowBlobPublicAccess=${public_access}, defaultAction=${default_action})" >&2
exit 1
