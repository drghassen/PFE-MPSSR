#!/usr/bin/env bash
set -euo pipefail

# Shared fail-closed helpers for CloudSentinel shift-right scripts.

SHIFT_RIGHT_STAGE="${SHIFT_RIGHT_STAGE:-unknown}"
SHIFT_RIGHT_AUDIT_FILE="${SHIFT_RIGHT_AUDIT_FILE:-.cloudsentinel/shift-right-audit.jsonl}"

sr_derive_pipeline_correlation_id() {
  if [[ -n "${CLOUDSENTINEL_PIPELINE_CORRELATION_ID:-}" ]]; then
    printf '%s\n' "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID"
    return 0
  fi

  if [[ -n "${CI_PIPELINE_ID:-}" ]]; then
    printf 'cspipe-%s\n' "$CI_PIPELINE_ID"
    return 0
  fi

  local seed cid
  seed="${CI_PROJECT_ID:-local}:${CI_PIPELINE_IID:-0}:${CI_RUNNER_ID:-0}:${CI_COMMIT_SHA:-local}:${CI_PROJECT_PATH:-${PWD:-local}}"
  cid="$(
    CLOUDSENTINEL_PIPELINE_CORRELATION_SEED="$seed" python3 -c 'import hashlib, os, uuid; seed = os.environ["CLOUDSENTINEL_PIPELINE_CORRELATION_SEED"].encode("utf-8"); print(uuid.UUID(bytes=hashlib.sha256(seed).digest()[:16], version=4))'
  )"
  printf 'cspipe-%s\n' "$cid"
}

sr_init_guard() {
  local stage="${1:?stage is required}"
  local audit_file="${2:?audit_file is required}"
  SHIFT_RIGHT_STAGE="$stage"
  SHIFT_RIGHT_AUDIT_FILE="$audit_file"
  CLOUDSENTINEL_PIPELINE_CORRELATION_ID="$(sr_derive_pipeline_correlation_id)"
  export CLOUDSENTINEL_PIPELINE_CORRELATION_ID
  mkdir -p "$(dirname "$SHIFT_RIGHT_AUDIT_FILE")"
}

_sr_plain_log() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local message="${3:-}"
  printf '[%s][%s][%s] %s\n' "$SHIFT_RIGHT_STAGE" "$level" "$event" "$message" >&2
}

# Build audit details JSON safely, surfacing jq errors instead of swallowing them.
# Usage: sr_build_details --arg foo "$bar" '{foo:$foo}'
# Always returns exit 0 with valid JSON; logs a WARN on jq failure.
sr_build_details() {
  local _out _err _rc=0
  _err="$(mktemp)"
  _out="$(jq -cn "$@" 2>"$_err")" || _rc=$?
  if [[ $_rc -ne 0 ]]; then
    _sr_plain_log "WARN" "audit_details_build_failed" \
      "jq failed (rc=${_rc}) building audit details: $(cat "$_err" 2>/dev/null)"
    rm -f "$_err"
    printf '%s' '{}'
    return 0
  fi
  rm -f "$_err"
  printf '%s' "$_out"
}

sr_audit() {
  local level="${1:?level is required}"
  local event="${2:?event is required}"
  local message="${3:-}"
  local details_json="${4:-}"
  if [[ -z "$details_json" ]]; then
    details_json='{}'
  fi

  # Last-resort guard: if the caller passed empty or non-JSON, log a visible
  # WARN so the problem is traceable, then replace with a sentinel.
  # Callers should use sr_build_details() to avoid reaching this path.
  if [[ -z "$details_json" ]] || ! jq -e . >/dev/null 2>&1 <<<"$details_json"; then
    _sr_plain_log "WARN" "audit_details_suppressed" \
      "details JSON was empty or invalid for event='${event}'; use sr_build_details() at the call site"
    details_json='{"error":"invalid_details_json_suppressed"}'
  fi

  if command -v jq >/dev/null 2>&1; then
    local line
    line="$(
      jq -cn \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg stage "$SHIFT_RIGHT_STAGE" \
        --arg level "$level" \
        --arg event "$event" \
        --arg message "$message" \
        --arg pipeline_correlation_id "${CLOUDSENTINEL_PIPELINE_CORRELATION_ID:-unknown}" \
        --argjson details "$details_json" \
        '{
          timestamp: $timestamp,
          stage: $stage,
          level: $level,
          event: $event,
          message: $message,
          details: ($details + {pipeline_correlation_id: $pipeline_correlation_id})
        }'
    )"
    printf '%s\n' "$line" >> "$SHIFT_RIGHT_AUDIT_FILE"
    printf '%s\n' "$line" >&2
    return
  fi

  _sr_plain_log "$level" "$event" "$message"
}

sr_fail() {
  local message="${1:?message is required}"
  local code="${2:-1}"
  local details_json="${3:-}"
  if [[ -z "$details_json" ]]; then
    details_json='{}'
  fi
  sr_audit "ERROR" "failure" "$message" "$details_json"
  exit "$code"
}

sr_require_command() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      sr_fail "required command not found: ${cmd}" 1 "{\"command\":\"${cmd}\"}"
    fi
  done
}

sr_require_env() {
  local missing=()
  local var
  for var in "$@"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  if ((${#missing[@]} > 0)); then
    sr_fail \
      "required environment variables are missing" \
      1 \
      "$(printf '%s\n' "${missing[@]}" | jq -R . | jq -sc '{missing_env:.}')"
  fi
}

sr_pipeline_correlation_id() {
  CLOUDSENTINEL_PIPELINE_CORRELATION_ID="$(sr_derive_pipeline_correlation_id)"
  export CLOUDSENTINEL_PIPELINE_CORRELATION_ID
  printf '%s\n' "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID"
}

# ---------------------------------------------------------------------------
# FIX (jq 1.6 reserved keyword): In jq >= 1.6, 'label' is a reserved keyword
# used in the label-break control flow construct. Using '--arg label $label'
# inside a jq expression causes a parse error:
#   "unexpected label, expecting IDENT or __loc__"
# Solution: rename the jq variable to $file_label. The JSON output key
# "label" is preserved using quoted-key syntax '"label": $file_label'.
# ---------------------------------------------------------------------------

sr_require_file() {
  local file="${1:?file is required}"
  local file_label="${2:-$file}"
  if [[ ! -f "$file" ]]; then
    sr_fail "required file is missing: ${file_label}" 1 \
      "$(jq -cn --arg file "$file" --arg file_label "$file_label" \
         '{file:$file,"label":$file_label}')"
  fi
}

sr_require_nonempty_file() {
  local file="${1:?file is required}"
  local file_label="${2:-$file}"
  sr_require_file "$file" "$file_label"
  if [[ ! -s "$file" ]]; then
    sr_fail "required file is empty: ${file_label}" 1 \
      "$(jq -cn --arg file "$file" --arg file_label "$file_label" \
         '{file:$file,"label":$file_label}')"
  fi
}

sr_require_json() {
  local file="${1:?file is required}"
  local jq_filter="${2:?jq filter is required}"
  local file_label="${3:-$file}"
  sr_require_nonempty_file "$file" "$file_label"
  if ! jq -e "$jq_filter" "$file" >/dev/null 2>&1; then
    sr_fail "JSON validation failed: ${file_label}" 1 \
      "$(jq -cn --arg file "$file" --arg file_label "$file_label" --arg filter "$jq_filter" \
         '{file:$file,"label":$file_label,filter:$filter}')"
  fi
}

sr_json_number() {
  local file="${1:?file is required}"
  local jq_expr="${2:?jq expression is required}"
  local file_label="${3:-$file}"
  local value
  if ! value="$(jq -er "${jq_expr} | if type == \"number\" then . else error(\"not_number\") end" "$file" 2>/dev/null)"; then
    sr_fail "numeric JSON query failed: ${file_label}" 1 \
      "$(jq -cn --arg file "$file" --arg file_label "$file_label" --arg expr "$jq_expr" \
         '{file:$file,"label":$file_label,expr:$expr}')"
  fi
  printf '%s\n' "$value"
}

sr_assert_eq() {
  local left="${1:?left is required}"
  local right="${2:?right is required}"
  local message="${3:?message is required}"
  if [[ "$left" != "$right" ]]; then
    sr_fail "$message" 1 "$(jq -cn --arg left "$left" --arg right "$right" '{left:$left,right:$right}')"
  fi
}

sr_assert_int_ge() {
  local left="${1:?left is required}"
  local right="${2:?right is required}"
  local message="${3:?message is required}"
  if (( left < right )); then
    sr_fail "$message" 1 "$(jq -cn --argjson left "$left" --argjson right "$right" '{left:$left,right:$right}')"
  fi
}

sr_assert_positive_if_expected() {
  local expected="${1:?expected is required}"
  local actual="${2:?actual is required}"
  local message="${3:?message is required}"
  if (( expected > 0 && actual == 0 )); then
    sr_fail "$message" 1 "$(jq -cn --argjson expected "$expected" --argjson actual "$actual" '{expected:$expected,actual:$actual}')"
  fi
}
