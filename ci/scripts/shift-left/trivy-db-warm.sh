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
# Set to "true" (default) to skip downloading the Java advisory DB.
# The Java DB is only needed when scanning Java/Maven/Gradle projects.
# Skipping it saves ~200 MB and several minutes per pipeline run.
readonly TRIVY_SKIP_JAVA_DB_WARM="${TRIVY_SKIP_JAVA_DB_WARM:-true}"

# Returns 0 if the cached DB is still fresh (NextUpdate not yet reached).
# Avoids re-downloading a multi-hundred-MB DB when the GitLab cache already
# holds a valid, current copy — saves 2-8 minutes per pipeline on average.
db_cache_is_fresh() {
  local cache_dir="$1"
  local meta_file="${cache_dir}/db/metadata.json"
  local db_file="${cache_dir}/db/trivy.db"

  [[ -s "$db_file" && -s "$meta_file" ]] || return 1

  local next_update
  next_update="$(jq -r '.NextUpdate // ""' "$meta_file" 2>/dev/null)" || return 1
  [[ -z "$next_update" ]] && return 1

  # Try GNU date first (Linux runners), then BSD date (macOS runners).
  local next_epoch
  next_epoch="$(date -u -d "$next_update" +%s 2>/dev/null)" \
    || next_epoch="$(date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$next_update" +%s 2>/dev/null)" \
    || return 1

  [[ "$(date -u +%s)" -lt "$next_epoch" ]]
}

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
  warn "Cache dir ${EFFECTIVE_CACHE_DIR} is not writable after all repair attempts."
  warn "Falling back to a temp dir — DB will not be cached this run."
  EFFECTIVE_CACHE_DIR="$(mktemp -d)"
  log "Fallback cache dir: ${EFFECTIVE_CACHE_DIR}"
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
log "skip_java_db=${TRIVY_SKIP_JAVA_DB_WARM}"

# Skip the download entirely when the cached DB is still within its validity
# window. The GitLab cache restores the DB from a previous pipeline, so this
# is the common fast path — the download only happens once per DB release cycle
# (typically every 6-12 hours) rather than on every pipeline run.
if db_cache_is_fresh "${EFFECTIVE_CACHE_DIR}"; then
  log "Cached Trivy DB is still fresh (NextUpdate not yet reached) — skipping download."
  exit 0
fi

JAVA_DB_ARGS=()
if [[ "${TRIVY_SKIP_JAVA_DB_WARM}" == "true" ]]; then
  JAVA_DB_ARGS=(--skip-java-db-update)
  log "Java advisory DB skipped (TRIVY_SKIP_JAVA_DB_WARM=true). Set to false if scanning Java projects."
fi

for repo in "${DB_REPOS[@]}"; do
  for attempt in $(seq 1 "${TRIVY_DB_ATTEMPTS_PER_REPO_EFF}"); do
    log "Attempting DB warm-up via ${repo} (attempt ${attempt}/${TRIVY_DB_ATTEMPTS_PER_REPO_EFF})"
    if trivy image \
      --download-db-only \
      --cache-dir "${EFFECTIVE_CACHE_DIR}" \
      --timeout "${TRIVY_DB_TIMEOUT_EFF}" \
      --db-repository "${repo}" \
      "${JAVA_DB_ARGS[@]}" \
      --no-progress; then
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
