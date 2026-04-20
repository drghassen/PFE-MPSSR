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
ZERO_SHA="0000000000000000000000000000000000000000"
DEFAULT_BRANCH="${CI_DEFAULT_BRANCH:-main}"
TARGET_BRANCH="${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-${DEFAULT_BRANCH}}"
FETCH_DEPTH="${IMMUTABILITY_FETCH_DEPTH:-200}"

resolve_head_parent() {
  git rev-parse "${HEAD_SHA}^" 2>/dev/null || true
}

resolve_merge_base() {
  local branch_name="$1"
  git merge-base "$HEAD_SHA" "origin/${branch_name}" 2>/dev/null || true
}

# Resolve base SHA deterministically.
# Priority:
# 1) CI_COMMIT_BEFORE_SHA (branch pipelines)
# 2) parent commit of HEAD (fallback for shallow branch pipelines)
# 3) MR target SHA / merge-base with target branch (MR pipelines)
BASE_SHA="${CI_COMMIT_BEFORE_SHA:-}"
[[ "$BASE_SHA" == "$ZERO_SHA" ]] && BASE_SHA=""

if [[ -z "$BASE_SHA" ]]; then
  BASE_SHA="$(resolve_head_parent)"
fi

MR_TARGET_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}"
[[ "$MR_TARGET_SHA" == "$ZERO_SHA" ]] && MR_TARGET_SHA=""
if [[ -z "$BASE_SHA" && -n "$MR_TARGET_SHA" ]]; then
  BASE_SHA="$MR_TARGET_SHA"
fi

if [[ -z "$BASE_SHA" ]]; then
  # Last resort before network fetch: merge-base against origin target branch.
  BASE_SHA="$(resolve_merge_base "$TARGET_BRANCH")"
fi

# In shallow clones, BASE_SHA may exist in CI variables but not be fetched yet.
# Strategy 1: deepen current history — enables HEAD^ resolution in branch pipelines.
# Strategy 2: fetch target branch by ref — covers MR pipelines and the
#   case where BASE_SHA is a merge-base diverged long ago.
if [[ -z "$BASE_SHA" ]] || ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  log "Base SHA not present/resolvable in shallow clone. Deepening current branch..."
  git fetch --no-tags --deepen="${FETCH_DEPTH}" origin 2>/dev/null || true

  if [[ -z "$BASE_SHA" ]] || ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
    BASE_SHA="$(resolve_head_parent)"
  fi

  if [[ -z "$BASE_SHA" ]] || ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
    log "Still unresolved after deepen. Fetching target branch refs..."
    git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
      "+refs/heads/${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}" 2>/dev/null || true
    if [[ "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
      git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
        "+refs/heads/${DEFAULT_BRANCH}:refs/remotes/origin/${DEFAULT_BRANCH}" 2>/dev/null || true
    fi
    if [[ -z "$BASE_SHA" ]] || ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
      BASE_SHA="$(resolve_merge_base "$TARGET_BRANCH")"
      if [[ -z "$BASE_SHA" ]] && [[ "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
        BASE_SHA="$(resolve_merge_base "$DEFAULT_BRANCH")"
      fi
    fi
  fi
fi

if [[ -z "$BASE_SHA" ]]; then
  err "Unable to resolve BASE_SHA for immutability check after all fetch attempts."
  exit 2
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  err "BASE_SHA ${BASE_SHA} unavailable after all fetch attempts."
  exit 2
fi

if ! git cat-file -e "${HEAD_SHA}^{commit}" 2>/dev/null; then
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
