#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Image Scanner
# Scope  : Container image CVE vulnerabilities + image misconfigurations
# Output : reports/raw/image/trivy-image-{sanitized-name}-raw.json
# Note   : Terraform/K8s IaC → Checkov | Secret scanning → Gitleaks
#          Trivy IMAGE covers: vuln (OS/library pkgs) + misconfig (container config)
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
mkdir -p "$TRIVY_CACHE_DIR_EFF"
OUTPUT_FILE="${TRIVY_IMAGE_OUTPUT_PATH:-$REPORT_DIR/trivy-image-raw.json}"
mkdir -p "$(dirname "$OUTPUT_FILE")"
SBOM_FILE="$SBOM_DIR/trivy-image.cdx.json"

DB_REPO_ARGS=()
IFS=',' read -r -a _raw_db_repos <<< "$TRIVY_DB_REPOSITORIES_EFF"
for _repo in "${_raw_db_repos[@]}"; do
  _repo="$(echo "$_repo" | xargs)"
  [[ -z "$_repo" ]] && continue
  DB_REPO_ARGS+=(--db-repository "$_repo")
done

use_warmed_db_cache() {
  case "${TRIVY_SKIP_DB_UPDATE_IN_SCAN:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

warmed_db_cache_available() {
  local db_file="${TRIVY_CACHE_DIR_EFF}/db/trivy.db"
  local metadata_file="${TRIVY_CACHE_DIR_EFF}/db/metadata.json"

  [[ -s "$db_file" ]] || return 1
  [[ -s "$metadata_file" ]] || return 1
  jq -e '
    type == "object"
    and (.Version | tostring == "2")
    and (.NextUpdate | type == "string")
    and (.DownloadedAt | type == "string")
  ' "$metadata_file" >/dev/null 2>&1 || return 1
}

SKIP_DB_UPDATE_ARGS=()
if use_warmed_db_cache; then
  if warmed_db_cache_available; then
    SKIP_DB_UPDATE_ARGS=(--skip-db-update)
  else
    # Same rationale as scan-fs.sh: if the warm job ran but the cache is absent,
    # the pipeline setup is broken — failing loudly is safer than a silent
    # fallback to a potentially stale or incomplete live download.
    if [[ -n "${CI:-}" ]]; then
      err "TRIVY_SKIP_DB_UPDATE_IN_SCAN=true but no valid DB cache at ${TRIVY_CACHE_DIR_EFF}/db — trivy-db-warm job may have failed or cache was not restored."
      exit 2
    fi
    warn "Warmed Trivy DB cache miss (${TRIVY_CACHE_DIR_EFF}/db/trivy.db) — falling back to live DB download."
  fi
fi

skip_java_db_update() {
  case "${TRIVY_SKIP_JAVA_DB_UPDATE_IN_SCAN:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

JAVA_DB_UPDATE_ARGS=()
if skip_java_db_update; then
  JAVA_DB_UPDATE_ARGS=(--skip-java-db-update)
fi

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
log "SBOM      : $SBOM_FILE"
log "Cache dir : $TRIVY_CACHE_DIR_EFF"
log "DB repos  : $TRIVY_DB_REPOSITORIES_EFF"
if use_warmed_db_cache; then
  if [[ ${#SKIP_DB_UPDATE_ARGS[@]} -gt 0 ]]; then
    log "DB update : disabled (using warmed DB cache)"
  else
    log "DB update : enabled (cache miss — downloading fresh DB)"
  fi
else
  log "DB update : enabled"
fi
if skip_java_db_update; then
  log "Java DB   : disabled"
else
  log "Java DB   : enabled"
fi
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"

# ── SBOM Generation ──────────────────────────────────────────────────────────
AUTH_ARGS=()
if [[ -n "${CI_REGISTRY:-}" && "$TARGET" == "${CI_REGISTRY}"* ]]; then
  AUTH_ARGS+=(--username "${CI_REGISTRY_USER:-}" --password "${CI_REGISTRY_PASSWORD:-}")
fi

log "Generating SBOM (CycloneDX)..."
trivy image \
  "${AUTH_ARGS[@]}" \
  --config "$CONFIG_FILE" \
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  "${SKIP_DB_UPDATE_ARGS[@]}" \
  "${JAVA_DB_UPDATE_ARGS[@]}" \
  --format cyclonedx \
  --output "$SBOM_FILE" \
  "$TARGET" || warn "Failed to generate SBOM, continuing scan."

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners vuln,misconfig:
#   vuln     → CVE in OS packages and language libraries
#   misconfig → container image misconfigurations (USER, HEALTHCHECK, exposed ports, etc.)
# Secrets → Gitleaks | Terraform/K8s IaC → Checkov
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
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  "${SKIP_DB_UPDATE_ARGS[@]}" \
  "${JAVA_DB_UPDATE_ARGS[@]}" \
  "${IGNORE_ARGS[@]}" \
  --scanners vuln,misconfig \
  --format json \
  --output "$OUTPUT_FILE" \
  "$TARGET"
TRIVY_RC=$?

if [[ "$TRIVY_RC" -gt 1 ]] && [[ -n "${CI:-}" ]] && ! use_warmed_db_cache; then
  warn "Trivy DB update failed in CI; retrying image scan with cached DB (--skip-db-update)."
  trivy image \
    "${AUTH_ARGS[@]}" \
    --config "$CONFIG_FILE" \
    --cache-dir "$TRIVY_CACHE_DIR_EFF" \
    --skip-db-update \
    "${JAVA_DB_UPDATE_ARGS[@]}" \
    "${IGNORE_ARGS[@]}" \
    --scanners vuln,misconfig \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"
  TRIVY_RC=$?
fi
set -e

if [[ "$TRIVY_RC" -gt 1 ]]; then
  err "Trivy technical error during image scan (rc=$TRIVY_RC): $TARGET"
  exit 1
fi

if jq -e 'type == "object" and ((has("Results") | not) or (.Results == null))' "$OUTPUT_FILE" >/dev/null 2>&1; then
  tmp_output="$(mktemp)"
  jq '.Results = []' "$OUTPUT_FILE" > "$tmp_output"
  mv "$tmp_output" "$OUTPUT_FILE"
fi

if ! jq -e 'type == "object" and (.Results | type == "array")' "$OUTPUT_FILE" >/dev/null 2>&1; then
  err "Trivy image scan produced an invalid raw report: $OUTPUT_FILE"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
