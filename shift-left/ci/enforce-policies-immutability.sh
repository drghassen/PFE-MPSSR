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
   [[ -n "${CI_JOB_TOKEN:-}" && -n "${CI_SERVER_HOST:-}" && -n "${CI_PROJECT_PATH:-}" ]]; then
  log "Git history unavailable; shallow-cloning for diff (depth=50)..."
  _clone_dir="$(mktemp -d)"
  _clone_err="$(mktemp)"
  if git clone --quiet --depth=50 \
    "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" \
    "$_clone_dir" 2>"$_clone_err"; then
    CHANGED_FILES="$(git -C "$_clone_dir" diff --name-only "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || true)"
    if [[ -z "$CHANGED_FILES" ]]; then
      # BASE_SHA older than depth=50; fall back to HEAD~1..HEAD
      CHANGED_FILES="$(git -C "$_clone_dir" diff --name-only HEAD~1 HEAD 2>/dev/null || true)"
    fi
  else
    err "Shallow clone failed: $(cat "$_clone_err" 2>/dev/null || true)"
  fi
  rm -rf "$_clone_dir" "$_clone_err"
fi

if [[ -z "$CHANGED_FILES" ]]; then
  err "Unable to determine changed files (git diff and API both failed)."
  exit 2
fi

# ── Protected-file check ───────────────────────────────────────────────────
# Each entry below is a path pattern (anchored ERE, relative to repo root).
# Any change to a matching file requires AppSec approval (CLOUDSENTINEL_APPSEC_USERS).
declare -a _PROTECTED_PATTERNS=(
  # ── OPA policies ───────────────────────────────────────────────────────────
  'policies/opa/.*\.rego'

  # ── CI scripts & libraries ─────────────────────────────────────────────────
  'ci/scripts/.*\.sh'
  'ci/scripts/.*\.py'
  'ci/libs/cloudsentinel_contracts\.py'

  # ── CI pipeline definitions ────────────────────────────────────────────────
  'ci/pipelines/.*\.yml'
  '\.gitlab-ci\.yml'
  '\.gitlab-ci-image-factory\.yml'

  # ── CI data contracts (artifact + shift-right integrity) ───────────────────
  'ci/contracts/.*\.json'

  # ── CI OPA authentication ──────────────────────────────────────────────────
  'ci/\.cloudsentinel/.*\.json'

  # ── Scanner container images ───────────────────────────────────────────────
  'ci/images/.*/Dockerfile'

  # ── Shift-left: shared library & immutability enforcement ──────────────────
  'shift-left/lib_scanner_utils\.sh'
  'shift-left/ci/enforce-policies-immutability\.sh'

  # ── Shift-left: scanner run-scripts (checkov, trivy, opa, gitleaks …) ──────
  'shift-left/.*/run-.*\.sh'

  # ── Shift-left: OPA server config & schemas ────────────────────────────────
  'shift-left/opa/.*'

  # ── Shift-left: normalizer & report schema ─────────────────────────────────
  'shift-left/normalizer/.*'

  # ── Shift-left: Checkov ────────────────────────────────────────────────────
  'shift-left/checkov/\.checkov\.yml'
  'shift-left/checkov/config/checkov-suppressions\.yml'
  'shift-left/checkov/policies/.*'

  # ── Shift-left: Trivy (config + CVE exemption list) ───────────────────────
  'shift-left/trivy/configs/trivy\.yaml'
  'shift-left/trivy/configs/trivy-ci\.yaml'
  'shift-left/trivy/configs/severity-mapping\.json'
  'shift-left/trivy/\.trivyignore'

  # ── Shift-left: Gitleaks (config + secret exemption list) ─────────────────
  'shift-left/gitleaks/gitleaks\.toml'
  'shift-left/gitleaks/\.gitleaksignore'

  # ── Shift-left: Cloud-init malicious pattern definitions ───────────────────
  'shift-left/cloudinit-scanner/rules/.*'

  # ── Shift-left: pre-commit developer hook ─────────────────────────────────
  'shift-left/pre-commit/.*\.sh'

  # ── Config: OPA data (exceptions + auth token) ────────────────────────────
  'config/opa/data/.*\.json'

  # ── Config: Prowler mute-list & check exclusions (post-deployment) ─────────
  'config/prowler/.*'

  # ── Config: remediation capability mapping ─────────────────────────────────
  'config/remediation-capabilities\.json'

  # ── Shift-right: drift engine config & report schema ──────────────────────
  'shift-right/drift-engine/config/.*'
  'shift-right/drift-engine/schemas/.*\.json'

  # ── Shift-right: Cloud Custodian automated-remediation policies ────────────
  'shift-right/custodian/policies/.*\.yml'

  # ── Verification scripts & runtime-state schema ────────────────────────────
  'verification/.*\.sh'
  'verification/.*\.json'
)

PROTECTED_REGEX="^($(printf '%s|' "${_PROTECTED_PATTERNS[@]}" | sed 's/|$//'))$"

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
