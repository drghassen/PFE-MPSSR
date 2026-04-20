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

resolve_merge_base() {
  local branch_name="$1"
  git merge-base "$HEAD_SHA" "origin/${branch_name}" 2>/dev/null || true
}

# Resolve base SHA deterministically.
BASE_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  BASE_SHA="$(resolve_merge_base "$TARGET_BRANCH")"
fi

# In shallow clones, BASE_SHA may not be present locally. Fetch target/default branch
# refs (never fetch by raw SHA) then recompute merge-base deterministically.
if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]] || ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  log "Base SHA not present/resolvable in shallow clone. Fetching target branch refs..."
  if ! git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
    "refs/heads/${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}" >/dev/null 2>&1; then
    err "Unable to fetch target branch refs for ${TARGET_BRANCH}. Refusing to bypass immutability check."
    exit 2
  fi
  if [[ "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
    git fetch --no-tags --depth="${FETCH_DEPTH}" origin \
      "refs/heads/${DEFAULT_BRANCH}:refs/remotes/origin/${DEFAULT_BRANCH}" >/dev/null 2>&1 || true
  fi
  BASE_SHA="$(resolve_merge_base "$TARGET_BRANCH")"
  if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]] && [[ "$TARGET_BRANCH" != "$DEFAULT_BRANCH" ]]; then
    BASE_SHA="$(resolve_merge_base "$DEFAULT_BRANCH")"
  fi
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  err "Unable to resolve BASE_SHA for immutability check after secure fetch."
  exit 2
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  err "BASE_SHA still unavailable after secure fetch: ${BASE_SHA}"
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
