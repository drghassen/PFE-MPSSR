#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel shift-right local entrypoint for Azure runtime posture scans with Prowler.
# Auth modes:
#   - az-cli   (default): uses active `az login` session
#   - sp-env: requires AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

if ! command -v prowler >/dev/null 2>&1; then
  echo "ERROR: 'prowler' CLI not found."
  echo "Install (official): pipx install prowler"
  echo "Reference: https://docs.prowler.com/getting-started/installation/prowler-cli"
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "ERROR: 'az' CLI not found."
  echo "Install: https://learn.microsoft.com/cli/azure/install-azure-cli"
  exit 1
fi

AUTH_MODE="${PROWLER_AZURE_AUTH_MODE:-az-cli}"
SUBSCRIPTION_ID="${PROWLER_AZURE_SUBSCRIPTION_ID:-${ARM_SUBSCRIPTION_ID:-}}"
OUTPUT_DIR="${PROWLER_OUTPUT_DIR:-$REPO_ROOT/.cloudsentinel/prowler/output}"
OUTPUT_FORMATS="${PROWLER_OUTPUT_FORMATS:-csv json-ocsf html}"
# Local advisory default: findings should not fail the shell command.
# Set PROWLER_IGNORE_EXIT_CODE_3=false to enforce strict non-zero behavior.
IGNORE_EXIT_CODE_3="${PROWLER_IGNORE_EXIT_CODE_3:-true}"

if [[ -z "$SUBSCRIPTION_ID" ]]; then
  SUBSCRIPTION_ID="$(az account show --query id -o tsv 2>/dev/null || true)"
fi

if [[ -z "$SUBSCRIPTION_ID" ]]; then
  echo "ERROR: Azure subscription not resolved."
  echo "Set PROWLER_AZURE_SUBSCRIPTION_ID (or ARM_SUBSCRIPTION_ID), or run:"
  echo "  az login"
  echo "  az account set --subscription <subscription-id>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

COMMON_ARGS=(
  azure
  --subscription-ids "$SUBSCRIPTION_ID"
  --output-formats $OUTPUT_FORMATS
  --output-directory "$OUTPUT_DIR"
)

echo "[prowler] repo=$REPO_ROOT"
echo "[prowler] subscription_id=$SUBSCRIPTION_ID"
echo "[prowler] auth_mode=$AUTH_MODE"
echo "[prowler] output_dir=$OUTPUT_DIR"
echo "[prowler] ignore_exit_code_3=$IGNORE_EXIT_CODE_3"

PROWLER_ARGS=("${COMMON_ARGS[@]}")
if [[ "$IGNORE_EXIT_CODE_3" == "true" ]]; then
  PROWLER_ARGS+=(--ignore-exit-code-3)
fi

case "$AUTH_MODE" in
  az-cli)
    if ! az account show >/dev/null 2>&1; then
      echo "ERROR: Azure CLI session not found. Run 'az login' first."
      exit 1
    fi
    prowler "${PROWLER_ARGS[@]}" --az-cli-auth
    ;;
  sp-env)
    missing=0
    for v in AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_CLIENT_SECRET; do
      if [[ -z "${!v:-}" ]]; then
        echo "ERROR: Missing required env var: $v"
        missing=1
      fi
    done
    if [[ "$missing" -ne 0 ]]; then
      exit 1
    fi
    prowler "${PROWLER_ARGS[@]}" --sp-env-auth
    ;;
  *)
    echo "ERROR: Invalid PROWLER_AZURE_AUTH_MODE='$AUTH_MODE' (allowed: az-cli, sp-env)"
    exit 1
    ;;
esac

echo "[prowler] Scan completed."
echo "[prowler] Generated reports:"
find "$OUTPUT_DIR" -maxdepth 2 -type f | sed 's/^/  - /'
