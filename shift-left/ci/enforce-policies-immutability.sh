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

has_commit() { git cat-file -e "${1}^{commit}" 2>/dev/null; }

# Resolve BASE_SHA from CI variables — no git history needed.
BASE_SHA="${CI_COMMIT_BEFORE_SHA:-}"
[[ "$BASE_SHA" == "$ZERO_SHA" ]] && BASE_SHA=""

MR_TARGET_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}"
[[ "$MR_TARGET_SHA" == "$ZERO_SHA" ]] && MR_TARGET_SHA=""
[[ -z "$BASE_SHA" && -n "$MR_TARGET_SHA" ]] && BASE_SHA="$MR_TARGET_SHA"

# Last resort for local/pre-commit use where CI variables are absent
if [[ -z "$BASE_SHA" ]]; then
  BASE_SHA="$(git rev-parse "${HEAD_SHA}^" 2>/dev/null || true)"
fi

if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
  err "Unable to resolve BASE_SHA. Set CI_COMMIT_BEFORE_SHA or CI_MERGE_REQUEST_TARGET_BRANCH_SHA."
  exit 2
fi

log "base=${BASE_SHA} head=${HEAD_SHA}"

# ── Changed-file detection ─────────────────────────────────────────────────
# Primary: git diff (works locally and when history is available in CI).
# Fallback: GitLab compare API (works when the runner fetches a single SHA
#           with no parent history — the common case with GIT_DEPTH=1).

CHANGED_FILES=""

if has_commit "$BASE_SHA" && has_commit "$HEAD_SHA"; then
  CHANGED_FILES="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || true)"
fi

if [[ -z "$CHANGED_FILES" ]] && \
   [[ -n "${CI_JOB_TOKEN:-}" && -n "${CI_API_V4_URL:-}" && -n "${CI_PROJECT_ID:-}" ]]; then
  log "Git history unavailable; using GitLab compare API..."
  CHANGED_FILES="$(
    curl -sf --max-time 30 \
      -H "JOB-TOKEN: ${CI_JOB_TOKEN}" \
      "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/repository/compare?from=${BASE_SHA}&to=${HEAD_SHA}&straight=true" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
seen = set()
for d in data.get('diffs', []):
    for k in ('new_path', 'old_path'):
        p = d.get(k, '')
        if p and p not in seen:
            seen.add(p)
            print(p)
" 2>/dev/null || true
  )"
fi

if [[ -z "$CHANGED_FILES" ]]; then
  err "Unable to determine changed files (git diff and API both failed)."
  exit 2
fi

# ── Protected-file check ───────────────────────────────────────────────────
PROTECTED_REGEX='^(policies/opa/.*\.rego|ci/scripts/shift-left/.*\.sh|ci/scripts/shift-left/.*\.py|ci/scripts/shift-right/.*\.sh|ci/scripts/.*\.sh|ci/libs/cloudsentinel_contracts\.py|shift-left/normalizer/.*|shift-left/opa/.*|shift-left/.*/run-.*\.sh|shift-left/opa/schema/exceptions_v2\.schema\.json|shift-left/normalizer/schema/cloudsentinel_report\.schema\.json|shift-left/gitleaks/gitleaks\.toml|shift-left/checkov/\.checkov\.yml|shift-left/checkov/policies/mapping\.json|shift-left/trivy/configs/trivy\.yaml|shift-left/trivy/configs/trivy-ci\.yaml|shift-left/trivy/configs/severity-mapping\.json|\.gitlab-ci\.yml|\.gitlab-ci-image-factory\.yml)$'

CHANGED_PROTECTED_FILES="$(echo "$CHANGED_FILES" | grep -E "$PROTECTED_REGEX" || true)"

if [[ -z "$CHANGED_PROTECTED_FILES" ]]; then
  log "No protected security control changes detected."
  exit 0
fi

ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"

_authorized=false
IFS=',' read -ra _allowed_tokens <<< "${APPSEC_ALLOWED_USERS}"
for _tok in "${_allowed_tokens[@]}"; do
  _tok="${_tok// /}"
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
