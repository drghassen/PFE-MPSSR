#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Filesystem / SCA Scanner
# Scope  : Language package vulnerabilities (npm, pip, maven, go, etc.)
# Output : reports/raw/trivy-fs-raw.json
# Note   : Source-level secret enforcement is handled exclusively by Gitleaks
#          (pre-commit + CI). Trivy FS here is vuln-only.
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"
SBOM_DIR="$BASE_DIR/reports/sbom"
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"
TRIVY_CACHE_DIR_EFF="${TRIVY_CACHE_DIR:-.trivy-cache}"
TRIVY_DB_REPOSITORIES_EFF="${TRIVY_DB_REPOSITORIES:-ghcr.io/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2}"

IGNORE_FILE="$BASE_DIR/.trivyignore"
IGNORE_ARGS=()
if [[ -f "$IGNORE_FILE" ]]; then
  if [[ "$SCAN_MODE" == "ci" ]]; then
    echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m .trivyignore is IGNORED in CI mode. Use DefectDojo/OPA for exceptions." >&2
  else
    IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
  fi
fi

SKIP_ARGS=()
SKIP_DIRS_CSV="${TRIVY_SKIP_DIRS:-}"
if [[ -n "$SKIP_DIRS_CSV" ]]; then
  IFS=',' read -r -a _skip_dirs <<< "$SKIP_DIRS_CSV"
  for _dir in "${_skip_dirs[@]}"; do
    _dir="$(echo "$_dir" | xargs)"
    [[ -z "$_dir" ]] && continue
    SKIP_ARGS+=(--skip-dirs "$_dir")
  done
fi

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][FS]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][FS][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][FS][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-.}"

[[ ! -d "$TARGET" ]] && { err "Target directory not found: $TARGET"; exit 1; }
TARGET="$(realpath "$TARGET")"

# SCAN_MODE already detected above

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
mkdir -p "$SBOM_DIR"
mkdir -p "$TRIVY_CACHE_DIR_EFF"
OUTPUT_FILE="$REPORT_DIR/trivy-fs-raw.json"
SBOM_FILE="$SBOM_DIR/trivy-fs.cdx.json"

DB_REPO_ARGS=()
IFS=',' read -r -a _raw_db_repos <<< "$TRIVY_DB_REPOSITORIES_EFF"
for _repo in "${_raw_db_repos[@]}"; do
  _repo="$(echo "$_repo" | xargs)"
  [[ -z "$_repo" ]] && continue
  DB_REPO_ARGS+=(--db-repository "$_repo")
done

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
log "SBOM      : $SBOM_FILE"
log "Cache dir : $TRIVY_CACHE_DIR_EFF"
log "DB repos  : $TRIVY_DB_REPOSITORIES_EFF"
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"
[[ ${#SKIP_ARGS[@]} -gt 0 ]] && log "Skip dirs: $SKIP_DIRS_CSV"

# ── SBOM Generation ──────────────────────────────────────────────────────────
log "Generating SBOM (CycloneDX)..."
if ! trivy fs \
  --config "$CONFIG_FILE" \
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  --format cyclonedx \
  --output "$SBOM_FILE" \
  "$TARGET"; then
  warn "SBOM generation with DB update failed, retrying with cached DB (--skip-db-update)."
  trivy fs \
    --config "$CONFIG_FILE" \
    --cache-dir "$TRIVY_CACHE_DIR_EFF" \
    --skip-db-update \
    --format cyclonedx \
    --output "$SBOM_FILE" \
    "$TARGET" || warn "Failed to generate SBOM, continuing scan."
fi

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners: vuln only (secrets are scanned by Gitleaks only)
# RC handling:
#   0/1 -> scan executed (findings may exist)
#   >1  -> technical failure
set +e
trivy fs \
  --config "$CONFIG_FILE" \
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  "${IGNORE_ARGS[@]}" \
  "${SKIP_ARGS[@]}" \
  --scanners vuln \
  --format json \
  --output "$OUTPUT_FILE" \
  "$TARGET"
TRIVY_RC=$?

if [[ "$TRIVY_RC" -gt 1 ]] && [[ -n "${CI:-}" ]]; then
  warn "Trivy DB update failed in CI; retrying scan with cached DB (--skip-db-update)."
  trivy fs \
    --config "$CONFIG_FILE" \
    --cache-dir "$TRIVY_CACHE_DIR_EFF" \
    --skip-db-update \
    "${IGNORE_ARGS[@]}" \
    "${SKIP_ARGS[@]}" \
    --scanners vuln \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"
  TRIVY_RC=$?
fi
set -e

if [[ "$TRIVY_RC" -gt 1 ]]; then
  err "Trivy technical error during filesystem scan (rc=$TRIVY_RC): $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
