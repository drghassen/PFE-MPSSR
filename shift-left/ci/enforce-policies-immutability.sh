#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# CloudSentinel Security Immutability Guard
# - Restricts changes to security-critical controls to AppSec identities
# - Covers policies, schemas, scanner configs/mappings and CI pipeline definition
# ------------------------------------------------------------------------------

log() { echo "[CloudSentinel][immutability] $*"; }
err() { echo "[CloudSentinel][immutability][ERROR] $*" >&2; }

readonly APPSEC_ALLOWED_USERS="appsec-bot,appsec-admin,drghassen"
HEAD_SHA="${CI_COMMIT_SHA:-HEAD}"
ZERO_SHA="0000000000000000000000000000000000000000"
DEFAULT_BRANCH="${CI_DEFAULT_BRANCH:-main}"

# Resolve base SHA deterministically.
BASE_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  BASE_SHA="$(git merge-base "$HEAD_SHA" "origin/${DEFAULT_BRANCH}" 2>/dev/null || true)"
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  err "Unable to resolve BASE_SHA for immutability check. Refusing to continue."
  exit 2
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  log "Base SHA not present in clone. Attempting secure fetch..."
  if ! git fetch --no-tags --depth="${IMMUTABILITY_FETCH_DEPTH:-200}" origin "$BASE_SHA" "${DEFAULT_BRANCH}" >/dev/null 2>&1; then
    err "Unable to fetch BASE_SHA=${BASE_SHA}. Refusing to bypass immutability check."
    exit 2
  fi
fi

if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  err "BASE_SHA still unavailable after fetch: ${BASE_SHA}"
  exit 2
fi

if ! git cat-file -e "${HEAD_SHA}^{commit}" 2>/dev/null; then
  err "HEAD_SHA not available in clone: ${HEAD_SHA}"
  exit 2
fi

PROTECTED_REGEX='^(policies/opa/.*\.rego|ci/scripts/.*\.sh|ci/libs/cloudsentinel_contracts\.py|shift-left/normalizer/.*|shift-left/opa/.*|shift-left/.*/run-.*\.sh|shift-left/opa/schema/exceptions_v2\.schema\.json|shift-left/normalizer/schema/cloudsentinel_report\.schema\.json|shift-left/gitleaks/gitleaks\.toml|shift-left/checkov/\.checkov\.yml|shift-left/checkov/policies/mapping\.json|shift-left/trivy/configs/trivy\.yaml|shift-left/trivy/configs/trivy-ci\.yaml|shift-left/trivy/configs/severity-mapping\.json|\.gitlab-ci\.yml)$'

CHANGED_PROTECTED_FILES="$({
  git diff --name-only "$BASE_SHA" "$HEAD_SHA"
} | grep -E "$PROTECTED_REGEX" || true)"

if [[ -z "$CHANGED_PROTECTED_FILES" ]]; then
  log "No protected security control changes detected."
  exit 0
fi

ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"

if echo ",${APPSEC_ALLOWED_USERS}," | grep -qi ",${ACTOR_LOGIN},"; then
  log "Authorized AppSec change by ${ACTOR_LOGIN}."
  log "Changed protected files:"
  echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /'
  exit 0
fi

err "Unauthorized modification of protected security controls by ${ACTOR_LOGIN} (${ACTOR_EMAIL})."
err "Changed protected files:"
echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /' >&2
exit 1
