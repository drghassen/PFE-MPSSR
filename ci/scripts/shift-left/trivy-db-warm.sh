#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-db-warm.sh
# =========================

source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "trivy-db-warm" "guard" "trivy-db"' EXIT

log()  { echo "[CloudSentinel][trivy-db-warm] $*"; }
warn() { echo "[CloudSentinel][trivy-db-warm][WARN] $*" >&2; }
err()  { echo "[CloudSentinel][trivy-db-warm][ERROR] $*" >&2; }

command -v trivy >/dev/null 2>&1 || { err "trivy binary missing"; exit 2; }

readonly TRIVY_CACHE_DIR_EFF="${TRIVY_CACHE_DIR:-.trivy-cache}"
readonly TRIVY_DB_TIMEOUT_EFF="${TRIVY_DB_TIMEOUT:-15m}"
readonly TRIVY_DB_REPOSITORIES_EFF="${TRIVY_DB_REPOSITORIES:-ghcr.io/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2}"
readonly TRIVY_DB_ATTEMPTS_PER_REPO_EFF="${TRIVY_DB_ATTEMPTS_PER_REPO:-2}"
readonly TRIVY_DB_RETRY_BACKOFF_SEC_EFF="${TRIVY_DB_RETRY_BACKOFF_SEC:-5}"

ensure_cache_writable() {
  local cache_dir="$1"
  local probe_file="${cache_dir}/.cs_rw_probe"

  mkdir -p "$cache_dir" 2>/dev/null || true
  if ( : > "$probe_file" ) 2>/dev/null; then
    rm -f "$probe_file" 2>/dev/null || true
    return 0
  fi

  warn "Cache directory is not writable (${cache_dir}). Attempting repair..."

  # Try chmod first — works when runner restores cache owned by a different uid
  chmod -R a+rwX "$cache_dir" 2>/dev/null || true
  if ( : > "$probe_file" ) 2>/dev/null; then
    rm -f "$probe_file" 2>/dev/null || true
    log "Cache directory repaired via chmod (${cache_dir})."
    return 0
  fi

  # Fallback: delete and recreate — works when parent dir is writable by current user
  rm -rf "$cache_dir" 2>/dev/null || true
  mkdir -p "$cache_dir" 2>/dev/null || true
  if ( : > "$probe_file" ) 2>/dev/null; then
    rm -f "$probe_file" 2>/dev/null || true
    log "Cache directory reset succeeded (${cache_dir})."
    return 0
  fi

  return 1
}

EFFECTIVE_CACHE_DIR="$TRIVY_CACHE_DIR_EFF"
if ! ensure_cache_writable "$EFFECTIVE_CACHE_DIR"; then
  if [[ -n "${CI:-}" ]]; then
    err "Cache dir ${EFFECTIVE_CACHE_DIR} is not writable after all repair attempts. CI warm-up must produce reusable DB artifacts."
    exit 2
  else
    warn "Cache dir ${EFFECTIVE_CACHE_DIR} is not writable after all repair attempts."
    warn "Falling back to a temp dir — DB will not be cached this run."
    EFFECTIVE_CACHE_DIR="$(mktemp -d)"
    log "Fallback cache dir: ${EFFECTIVE_CACHE_DIR}"
  fi
fi

IFS=',' read -r -a RAW_REPOS <<< "$TRIVY_DB_REPOSITORIES_EFF"
DB_REPOS=()
for repo in "${RAW_REPOS[@]}"; do
  repo="$(echo "$repo" | xargs)"
  [[ -z "$repo" ]] && continue
  DB_REPOS+=("$repo")
done

if [[ "${#DB_REPOS[@]}" -eq 0 ]]; then
  err "No DB repository configured. Set TRIVY_DB_REPOSITORIES."
  exit 2
fi

trivy --version
log "cache_dir=${EFFECTIVE_CACHE_DIR} timeout=${TRIVY_DB_TIMEOUT_EFF}"
log "db_repositories=${TRIVY_DB_REPOSITORIES_EFF}"
log "attempts_per_repo=${TRIVY_DB_ATTEMPTS_PER_REPO_EFF} retry_backoff_sec=${TRIVY_DB_RETRY_BACKOFF_SEC_EFF}"

validate_warmed_db() {
  local db_file="${EFFECTIVE_CACHE_DIR}/db/trivy.db"
  local metadata_file="${EFFECTIVE_CACHE_DIR}/db/metadata.json"

  [[ -s "$db_file" ]] || { err "Warm-up completed but DB file is missing or empty: $db_file"; return 1; }
  [[ -s "$metadata_file" ]] || { err "Warm-up completed but DB metadata is missing or empty: $metadata_file"; return 1; }
  jq -e '
    type == "object"
    and (.Version | tostring == "2")
    and (.NextUpdate | type == "string")
    and (.DownloadedAt | type == "string")
  ' "$metadata_file" >/dev/null 2>&1 || {
    err "Warm-up completed but DB metadata is invalid: $metadata_file"
    return 1
  }
}

for repo in "${DB_REPOS[@]}"; do
  for attempt in $(seq 1 "${TRIVY_DB_ATTEMPTS_PER_REPO_EFF}"); do
    log "Attempting DB warm-up via ${repo} (attempt ${attempt}/${TRIVY_DB_ATTEMPTS_PER_REPO_EFF})"
    if trivy image \
      --download-db-only \
      --cache-dir "${EFFECTIVE_CACHE_DIR}" \
      --timeout "${TRIVY_DB_TIMEOUT_EFF}" \
      --db-repository "${repo}" \
      --no-progress; then
      validate_warmed_db
      log "DB warm-up succeeded via ${repo}"
      exit 0
    fi
    if [[ "$attempt" -lt "${TRIVY_DB_ATTEMPTS_PER_REPO_EFF}" ]]; then
      warn "DB warm-up failed via ${repo}; retrying after ${TRIVY_DB_RETRY_BACKOFF_SEC_EFF}s"
      sleep "${TRIVY_DB_RETRY_BACKOFF_SEC_EFF}"
    fi
  done
  warn "DB warm-up failed via ${repo}; trying next repository"
done

err "All DB repositories failed: ${TRIVY_DB_REPOSITORIES_EFF}"
exit 1
