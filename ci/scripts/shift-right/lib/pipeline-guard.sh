#!/usr/bin/env bash
set -euo pipefail

# Shared fail-closed helpers for CloudSentinel shift-right scripts.

SHIFT_RIGHT_STAGE="${SHIFT_RIGHT_STAGE:-unknown}"
SHIFT_RIGHT_AUDIT_FILE="${SHIFT_RIGHT_AUDIT_FILE:-.cloudsentinel/shift-right-audit.jsonl}"

sr_init_guard() {
  local stage="${1:?stage is required}"
  local audit_file="${2:?audit_file is required}"
  SHIFT_RIGHT_STAGE="$stage"
  SHIFT_RIGHT_AUDIT_FILE="$audit_file"
  mkdir -p "$(dirname "$SHIFT_RIGHT_AUDIT_FILE")"
}

_sr_plain_log() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local message="${3:-}"
  printf '[%s][%s][%s] %s\n' "$SHIFT_RIGHT_STAGE" "$level" "$event" "$message" >&2
}

sr_audit() {
  local level="${1:?level is required}"
  local event="${2:?event is required}"
  local message="${3:-}"
  local details_json="${4:-{}}"

  # Defensive guard: normalise empty or invalid details_json before --argjson.
  # Prevents cascade failure where a caller passes the output of a failed jq
  # sub-shell (empty string), which itself may be caused by the jq-1.6
  # reserved-keyword 'label' bug fixed in sr_require_file/nonempty/json/number.
  if [[ -z "$details_json" ]] || ! printf '%s' "$details_json" | jq -e . >/dev/null 2>&1; then
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
        --argjson details "$details_json" \
        '{
          timestamp: $timestamp,
          stage: $stage,
          level: $level,
          event: $event,
          message: $message,
          details: $details
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
  local details_json="${3:-{}}"
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
