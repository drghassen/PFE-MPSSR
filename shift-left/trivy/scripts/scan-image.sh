#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Image Scanner
# Scope  : Container image vulnerability scanning (OS pkgs + library pkgs)
#          + Secrets embedded in image layers
# Output : reports/raw/trivy-image-raw.json
# Note   : Dockerfile config scanning → scan-config.sh
#          Source-level secrets        → Gitleaks
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"
SBOM_DIR="$BASE_DIR/reports/sbom"
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"

IGNORE_FILE="$BASE_DIR/.trivyignore"
IGNORE_ARGS=()
if [[ -f "$IGNORE_FILE" ]]; then
  if [[ "$SCAN_MODE" == "ci" ]]; then
    echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m .trivyignore is IGNORED in CI mode. Use DefectDojo/OPA for exceptions." >&2
  else
    IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
  fi
fi

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][IMAGE]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][IMAGE][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][IMAGE][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-}"
[[ -z "$TARGET" ]] && { err "Usage: $0 <image_name[:tag]>"; exit 1; }

# SCAN_MODE already detected above

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
mkdir -p "$SBOM_DIR"
OUTPUT_FILE="${TRIVY_IMAGE_OUTPUT_PATH:-$REPORT_DIR/trivy-image-raw.json}"
mkdir -p "$(dirname "$OUTPUT_FILE")"
SBOM_FILE="$SBOM_DIR/trivy-image.cdx.json"

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
log "SBOM      : $SBOM_FILE"
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"

# ── SBOM Generation ──────────────────────────────────────────────────────────
AUTH_ARGS=()
if [[ -n "${CI_REGISTRY:-}" && "$TARGET" == "${CI_REGISTRY}"* ]]; then
  AUTH_ARGS+=(--username "${CI_REGISTRY_USER:-}" --password "${CI_REGISTRY_PASSWORD:-}")
fi

log "Generating SBOM (CycloneDX)..."
trivy image \
  "${AUTH_ARGS[@]}" \
  --format cyclonedx \
  --output "$SBOM_FILE" \
  "$TARGET" || warn "Failed to generate SBOM, continuing scan."

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners: vuln covers OS+lib, secret covers embedded secrets
# RC handling:
#   0/1 -> scan executed (findings may exist)
#   >1  -> technical failure
AUTH_ARGS=()
if [[ -n "${CI_REGISTRY:-}" && "$TARGET" == "${CI_REGISTRY}"* ]]; then
  AUTH_ARGS+=(--username "${CI_REGISTRY_USER:-}" --password "${CI_REGISTRY_PASSWORD:-}")
fi

set +e
trivy image \
  "${AUTH_ARGS[@]}" \
  --config "$CONFIG_FILE" \
  "${IGNORE_ARGS[@]}" \
  --scanners vuln,secret \
  --format json \
  --output "$OUTPUT_FILE" \
  "$TARGET"
TRIVY_RC=$?
set -e

if [[ "$TRIVY_RC" -gt 1 ]]; then
  err "Trivy technical error during image scan (rc=$TRIVY_RC): $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) + (.Secrets // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
