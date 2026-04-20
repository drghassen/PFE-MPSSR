#!/usr/bin/env bash
set -euo pipefail

log() { echo "[CloudSentinel][immutability] $*"; }
err() { echo "[CloudSentinel][immutability][ERROR] $*" >&2; }

if [[ -z "${CLOUDSENTINEL_APPSEC_USERS:-}" ]]; then
  err "CLOUDSENTINEL_APPSEC_USERS is not set. Define it as a protected masked CI variable."
  err "Minimum value: appsec-bot,appsec-admin"
  if [[ "${CLOUDSENTINEL_IMMUTABILITY_MODE:-enforcing}" == "advisory" ]]; then
    log "ADVISORY MODE: Bypassing user lookup."
    exit 0
  else
    exit 2
  fi
fi
readonly APPSEC_ALLOWED_USERS="${CLOUDSENTINEL_APPSEC_USERS}"
HEAD_SHA="${CI_COMMIT_SHA:-HEAD}"

# Temporary debug — remove after root cause is identified
log "DEBUG: CI_COMMIT_SHA=${CI_COMMIT_SHA:-<unset>}"
log "DEBUG: CI_COMMIT_BEFORE_SHA=${CI_COMMIT_BEFORE_SHA:-<unset>}"
log "DEBUG: CI_MERGE_REQUEST_TARGET_BRANCH_SHA=${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-<unset>}"
log "DEBUG: CI_DEFAULT_BRANCH=${CI_DEFAULT_BRANCH:-<unset>}"
log "DEBUG: CI_MERGE_REQUEST_TARGET_BRANCH_NAME=${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-<unset>}"
log "DEBUG: git log --oneline -3 = $(git log --oneline -3 2>/dev/null || echo FAILED)"
log "DEBUG: git rev-parse HEAD^ = $(git rev-parse HEAD^ 2>/dev/null || echo FAILED)"
log "DEBUG: git show-ref --heads = $(git show-ref --heads 2>/dev/null | head -5 || echo NONE)"
ZERO_SHA="0000000000000000000000000000000000000000"
DEFAULT_BRANCH="${CI_DEFAULT_BRANCH:-main}"
TARGET_BRANCH="${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-${DEFAULT_BRANCH}}"
FETCH_DEPTH="${IMMUTABILITY_FETCH_DEPTH:-200}"

has_commit() {
  git cat-file -e "${1}^{commit}" 2>/dev/null
}

# Resolve base SHA deterministically.
# Priority:
# 1) CI_COMMIT_BEFORE_SHA (branch/main pipelines)
# 2) HEAD^ fallback (branch/main pipelines, robust with shallow clones)
# 3) CI_MERGE_REQUEST_TARGET_BRANCH_SHA (MR pipelines)
# 4) merge-base with fetched target/default refs
BASE_SHA="${CI_COMMIT_BEFORE_SHA:-}"
[[ "$BASE_SHA" == "$ZERO_SHA" ]] && BASE_SHA=""

if [[ -z "$BASE_SHA" ]] || ! has_commit "$BASE_SHA"; then
  BASE_SHA="$(git rev-parse "${HEAD_SHA}^" 2>/dev/null || true)"
fi

MR_TARGET_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}"
[[ "$MR_TARGET_SHA" == "$ZERO_SHA" ]] && MR_TARGET_SHA=""
if [[ -z "$BASE_SHA" && -n "$MR_TARGET_SHA" ]]; then
  BASE_SHA="$MR_TARGET_SHA"
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  BASE_SHA="$(git merge-base "$HEAD_SHA" "origin/${TARGET_BRANCH}" 2>/dev/null || true)"
fi

# In shallow clones, BASE_SHA can be unresolved or unavailable.
# Never fetch by raw SHA (often denied by GitLab); fetch branch refs and recompute.
if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]] || ! has_commit "$BASE_SHA"; then
  log "Base SHA not present/resolvable in shallow clone. Deepening current branch..."
  git fetch --no-tags --deepen="${FETCH_DEPTH}" origin >/dev/null 2>&1 || true

  if [[ -z "$BASE_SHA" ]] || ! has_commit "$BASE_SHA"; then
    BASE_SHA="$(git rev-parse "${HEAD_SHA}^" 2>/dev/null || true)"
  fi

  if [[ -z "$BASE_SHA" ]] || ! has_commit "$BASE_SHA"; then
    log "Still unresolved after deepen. Fetching target branch refs..."
    git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
      "+refs/heads/${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}" >/dev/null 2>&1 || true
    if [[ "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
      git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
        "+refs/heads/${DEFAULT_BRANCH}:refs/remotes/origin/${DEFAULT_BRANCH}" >/dev/null 2>&1 || true
    fi

    BASE_SHA="$(git merge-base "$HEAD_SHA" "origin/${TARGET_BRANCH}" 2>/dev/null || true)"
    if [[ -z "$BASE_SHA" && "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
      BASE_SHA="$(git merge-base "$HEAD_SHA" "origin/${DEFAULT_BRANCH}" 2>/dev/null || true)"
    fi
    if [[ -z "$BASE_SHA" ]]; then
      BASE_SHA="$(git rev-parse "${HEAD_SHA}^" 2>/dev/null || true)"
    fi
  fi
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  err "Unable to resolve BASE_SHA for immutability check after all fetch attempts."
  exit 2
fi

if ! has_commit "$BASE_SHA"; then
  err "BASE_SHA ${BASE_SHA} unavailable after all fetch attempts."
  exit 2
fi

if ! has_commit "$HEAD_SHA"; then
  err "HEAD_SHA not available in clone: ${HEAD_SHA}"
  exit 2
fi

# .gitlab-ci-image-factory.yml: protected because it controls CI image rebuilds.
# Unauthorized modification could introduce malicious images into the supply chain.
PROTECTED_REGEX='^(policies/opa/.*\.rego|ci/scripts/shift-left/.*\.sh|ci/scripts/shift-left/.*\.py|ci/scripts/shift-right/.*\.sh|ci/scripts/.*\.sh|ci/libs/cloudsentinel_contracts\.py|shift-left/normalizer/.*|shift-left/opa/.*|shift-left/.*/run-.*\.sh|shift-left/opa/schema/exceptions_v2\.schema\.json|shift-left/normalizer/schema/cloudsentinel_report\.schema\.json|shift-left/gitleaks/gitleaks\.toml|shift-left/checkov/\.checkov\.yml|shift-left/checkov/policies/mapping\.json|shift-left/trivy/configs/trivy\.yaml|shift-left/trivy/configs/trivy-ci\.yaml|shift-left/trivy/configs/severity-mapping\.json|\.gitlab-ci\.yml|\.gitlab-ci-image-factory\.yml)$'

CHANGED_PROTECTED_FILES="$({
  git diff --name-only "$BASE_SHA" "$HEAD_SHA"
} | grep -E "$PROTECTED_REGEX" || true)"

if [[ -z "$CHANGED_PROTECTED_FILES" ]]; then
  log "No protected security control changes detected."
  exit 0
fi

ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"

# Exact case-sensitive match — iterate CSV tokens one by one.
# grep -qi was previously used here and allowed case-bypass attacks:
# e.g. actor "AppsecAdmin" passed if "appsecadmin" was in the allowlist.
_authorized=false
IFS=',' read -ra _allowed_tokens <<< "${APPSEC_ALLOWED_USERS}"
for _tok in "${_allowed_tokens[@]}"; do
  _tok="${_tok// /}"  # strip surrounding spaces from each token
  if [[ -n "$_tok" && "$_tok" == "${ACTOR_LOGIN}" ]]; then
    _authorized=true
    break
  fi
done

if [[ "$_authorized" == "true" ]]; then
  log "Authorized AppSec change by ${ACTOR_LOGIN}."
  log "Changed protected files:"
  echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /'
  exit 0
fi

err "Unauthorized modification of protected security controls by ${ACTOR_LOGIN} (${ACTOR_EMAIL})."
err "Changed protected files:"
echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /' >&2

if [[ "${CLOUDSENTINEL_IMMUTABILITY_MODE:-enforcing}" == "advisory" ]]; then
  log "ADVISORY MODE: Allowing unauthorized pipeline modifications."
  exit 0
else
  exit 1
fi
