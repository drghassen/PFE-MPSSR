#!/usr/bin/env bash
set -euo pipefail

log()  { echo "[CloudSentinel][Gitleaks] $*"; }
err()  { echo "[CloudSentinel][Gitleaks][ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib_scanner_utils.sh"

# Git ≥ 2.35 refuses to operate on repos owned by a different UID.
# Docker CI runners clone as root while the container process runs as a
# non-root user, triggering "dubious ownership" and silently skipping all
# git-history scanning. Mark the directory trusted before any git call.
if [[ -n "${CI:-}" ]]; then
  export HOME=/tmp
  git config --global --add safe.directory "${CI_PROJECT_DIR:-$PWD}"
fi

REPO_ROOT="$(cs_get_repo_root)"
OUT_DIR="$REPO_ROOT/.cloudsentinel"
REPORT_RAW_OUT="$OUT_DIR/gitleaks_raw.json"
CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/shift-left/gitleaks/gitleaks.toml}"
IGNORE_PATH="${IGNORE_PATH:-$REPO_ROOT/shift-left/gitleaks/.gitleaksignore}"
BASELINE_PATH="${BASELINE_PATH:-${GITLEAKS_BASELINE_PATH:-$REPO_ROOT/shift-left/gitleaks/.gitleaks-baseline.json}}"
USE_BASELINE="${USE_BASELINE:-false}"
SCAN_TARGET="${SCAN_TARGET:-repo}"
GITLEAKS_SOURCE_PATH="${GITLEAKS_SOURCE_PATH:-$REPO_ROOT}"
GITLEAKS_NO_GIT="${GITLEAKS_NO_GIT:-false}"
MAX_SIZE_MB="${GITLEAKS_MAX_SIZE:-5}"

if [[ -n "${CI:-}" ]]; then
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
else
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-60}"
fi

mkdir -p "$OUT_DIR"

command -v git >/dev/null 2>&1 || { err "git binary missing"; exit 2; }
command -v jq >/dev/null 2>&1 || { err "jq binary missing"; exit 2; }
command -v gitleaks >/dev/null 2>&1 || { err "gitleaks binary missing"; exit 2; }
command -v python3 >/dev/null 2>&1 || { err "python3 binary missing"; exit 2; }
[[ -f "$CONFIG_PATH" ]] || { err "gitleaks config missing: $CONFIG_PATH"; exit 2; }

TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout"

run_cmd() {
  if [[ "$TIMEOUT_SEC" -gt 0 && -n "$TIMEOUT_BIN" ]]; then
    timeout "$TIMEOUT_SEC" "$@"
  else
    "$@"
  fi
}

validate_gitleaks_report() {
  local report_path="$1"
  [[ -s "$report_path" ]] || { err "gitleaks raw output missing: $report_path"; exit 2; }
  jq -e 'type=="array"' "$report_path" >/dev/null || { err "gitleaks raw output invalid JSON array: $report_path"; exit 2; }
}

# Returns 0 if <sha> is a commit reachable in the current git clone.
# Needed to guard against shallow/fork clones where CI_MERGE_REQUEST_TARGET_BRANCH_SHA
# or CI_COMMIT_BEFORE_SHA may reference commits not present locally.
git_sha_reachable() {
  git cat-file -e "${1}^{commit}" 2>/dev/null
}

enrich_with_secret_hash() {
  local report_path="$1"
  python3 - "$report_path" "$REPO_ROOT" <<'PY'
import hashlib
import json
import os
import sys
import tempfile


def first_non_empty(*vals):
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def norm_path(path_value, repo_root):
    p = str(path_value or "").replace("\\", "/")
    repo = str(repo_root or "").replace("\\", "/").rstrip("/")
    if repo and p.startswith(repo + "/"):
        p = p[len(repo) + 1 :]
    while "//" in p:
        p = p.replace("//", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


def is_redacted(value):
    s = str(value or "").strip()
    return s.upper() == "REDACTED"


def compute_secret_hash(item, repo_root):
    secret = first_non_empty(
        item.get("Secret"), item.get("secret"), item.get("Match"), item.get("match")
    )
    if secret and not is_redacted(secret):
        material = "v1|secret|" + secret
    else:
        rule_id = first_non_empty(item.get("RuleID"), item.get("rule_id"), "GITLEAKS_UNKNOWN").upper()
        file_path = norm_path(first_non_empty(item.get("File"), item.get("file"), ""), repo_root)
        start_line = first_non_empty(item.get("StartLine"), item.get("start_line"), item.get("line"), "0")
        end_line = first_non_empty(item.get("EndLine"), item.get("end_line"), start_line)
        start_col = first_non_empty(item.get("StartColumn"), item.get("start_column"), "0")
        end_col = first_non_empty(item.get("EndColumn"), item.get("end_column"), "0")
        material = "|".join(
            [
                "v1",
                "location",
                rule_id,
                file_path,
                str(start_line),
                str(end_line),
                str(start_col),
                str(end_col),
            ]
        )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


report_path = sys.argv[1]
repo_root = sys.argv[2]
with open(report_path, "r", encoding="utf-8") as f:
    payload = json.load(f)
if not isinstance(payload, list):
    raise SystemExit("gitleaks report must be a JSON array")

for item in payload:
    if not isinstance(item, dict):
        continue
    digest = compute_secret_hash(item, repo_root)
    item["CloudSentinelSecretHash"] = digest
    item["SecretHash"] = digest

tmp_fd, tmp_path = tempfile.mkstemp(
    prefix=".gitleaks_hash_", suffix=".json", dir=os.path.dirname(report_path) or "."
)
os.close(tmp_fd)
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, separators=(",", ":"))
os.replace(tmp_path, report_path)
PY
}

SCAN_MODE="${SCAN_MODE:-}"
if [[ "$SCAN_MODE" != "ci" && "$SCAN_MODE" != "local" ]]; then
  [[ -n "${CI:-}" ]] && SCAN_MODE="ci" || SCAN_MODE="local"
fi

log "Starting raw scan (mode=$SCAN_MODE, target=$SCAN_TARGET, source=$GITLEAKS_SOURCE_PATH, max_size=${MAX_SIZE_MB}MB)..."

if [[ "$SCAN_MODE" == "local" ]]; then
  rm -f "$OUT_DIR/gitleaks_range_raw.json" "$OUT_DIR/gitleaks_range_raw.json.hmac"
fi

IGNORE_ARGS=()
[[ -f "$IGNORE_PATH" ]] && IGNORE_ARGS=(--gitleaks-ignore-path "$IGNORE_PATH")

BASELINE_ARGS=()
case "${USE_BASELINE,,}" in
  true|1|yes)
    if [[ -f "$BASELINE_PATH" ]]; then
      BASELINE_ARGS=(--baseline-path "$BASELINE_PATH")
      log "Using baseline: $BASELINE_PATH"
    else
      log "Baseline requested but not found: $BASELINE_PATH. Running without baseline."
    fi
    ;;
  false|0|no|"")
    ;;
  *)
    err "invalid USE_BASELINE=${USE_BASELINE}; expected true or false"
    exit 2
    ;;
esac

NO_GIT_ARGS=()
case "${GITLEAKS_NO_GIT,,}" in
  true|1|yes)
    NO_GIT_ARGS=(--no-git)
    log "Using non-git filesystem scan mode."
    ;;
  false|0|no|"")
    ;;
  *)
    err "invalid GITLEAKS_NO_GIT=${GITLEAKS_NO_GIT}; expected true or false"
    exit 2
    ;;
esac

set +e
if [[ "$SCAN_MODE" == "local" ]]; then
  case "$SCAN_TARGET" in
    repo|history)
      run_cmd gitleaks detect --source "$GITLEAKS_SOURCE_PATH" "${NO_GIT_ARGS[@]}" --redact --config "$CONFIG_PATH" "${IGNORE_ARGS[@]}" "${BASELINE_ARGS[@]}" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
      ;;
    staged)
      run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" "${IGNORE_ARGS[@]}" "${BASELINE_ARGS[@]}" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
      ;;
    staged_history|staged+history|all)
      STAGED_OUT="$OUT_DIR/gitleaks_staged_raw.json"
      HISTORY_OUT="$OUT_DIR/gitleaks_history_raw.json"
      RANGE_OUT="$OUT_DIR/gitleaks_range_raw.json"
      rm -f "$STAGED_OUT" "$HISTORY_OUT" "$RANGE_OUT"

      run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" "${IGNORE_ARGS[@]}" "${BASELINE_ARGS[@]}" --report-format json --report-path "$STAGED_OUT" --max-target-megabytes "$MAX_SIZE_MB"
      RC_STAGED=$?
      if [[ "$RC_STAGED" -gt 1 ]]; then
        RC="$RC_STAGED"
      else
        run_cmd gitleaks detect --source "$GITLEAKS_SOURCE_PATH" "${NO_GIT_ARGS[@]}" --redact --config "$CONFIG_PATH" "${IGNORE_ARGS[@]}" "${BASELINE_ARGS[@]}" --report-format json --report-path "$HISTORY_OUT" --max-target-megabytes "$MAX_SIZE_MB"
        RC_HISTORY=$?
        if [[ "$RC_HISTORY" -gt 1 ]]; then
          RC="$RC_HISTORY"
        else
          RC=0
          validate_gitleaks_report "$STAGED_OUT"
          validate_gitleaks_report "$HISTORY_OUT"
          enrich_with_secret_hash "$STAGED_OUT"
          enrich_with_secret_hash "$HISTORY_OUT"

          jq -s --arg repo_root "$REPO_ROOT" '
            def dedup_key:
              def norm_file:
                ((.File // .file // "") | tostring
                 | gsub("\\\\"; "/")
                 | if startswith(($repo_root | tostring) + "/")
                   then .[(($repo_root | tostring | length) + 1):]
                   else .
                   end
                 | gsub("^\\./+"; ""));
              [
                ((.RuleID // .rule_id // "GITLEAKS_UNKNOWN") | tostring | ascii_upcase),
                norm_file,
                ((.StartLine // .start_line // .line // 0) | tostring),
                ((.EndLine // .end_line // .line // 0) | tostring),
                ((.CloudSentinelSecretHash // .SecretHash // .secret_hash // "") | tostring)
              ] | join(":");
            .[0] + .[1] | unique_by(dedup_key)
          ' "$STAGED_OUT" "$HISTORY_OUT" > "$REPORT_RAW_OUT"

          # Local equivalent of the CI range report: only staged findings are
          # considered latest-change findings by the normalizer/OPA gate.
          jq \
            --arg commit "STAGED" \
            --arg email "$(git config user.email 2>/dev/null || printf 'local@example.invalid')" \
            --arg date "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            'map(. + {Commit: ((.Commit // "") | if . == "" then $commit else . end),
                       Email:  ((.Email // "")  | if . == "" then $email  else . end),
                       Date:   ((.Date // "")   | if . == "" then $date   else . end)})' \
            "$STAGED_OUT" > "$RANGE_OUT"
        fi
      fi
      ;;
    *)
      err "invalid SCAN_TARGET=${SCAN_TARGET}; expected repo, history, staged, or staged_history"
      exit 2
      ;;
  esac
else
  # CI scans full git history (GIT_DEPTH=0 guarantees a complete clone).
  # --no-git is intentionally absent: a secret removed in a prior commit
  # stays visible in history and must not be silently dropped from the gate.
  run_cmd gitleaks detect --source "$GITLEAKS_SOURCE_PATH" --redact --config "$CONFIG_PATH" "${IGNORE_ARGS[@]}" "${BASELINE_ARGS[@]}" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
fi
RC="${RC:-$?}"
set -e

if [[ "$RC" -gt 1 ]]; then
  err "gitleaks execution error rc=$RC"
  exit 2
fi

validate_gitleaks_report "$REPORT_RAW_OUT"
enrich_with_secret_hash "$REPORT_RAW_OUT"
jq -e 'all(.[]; ((.CloudSentinelSecretHash // .SecretHash // "") | type == "string" and test("^[0-9a-f]{64}$")))' "$REPORT_RAW_OUT" >/dev/null \
  || { err "gitleaks raw output missing CloudSentinelSecretHash"; exit 2; }

log "Raw report ready: $REPORT_RAW_OUT"

# --- Scan range secondaire (enrichissement metadata — non-gating) ---
# Les findings du scan range sont fusionnés dans gitleaks_raw.json qui est évalué par OPA.
# Déduplication par clé composite stable: RuleID:File:StartLine:SecretHash
# (Fingerprint varie entre modes --no-git et --log-opts).
if [[ -n "${CI:-}" ]]; then
  RANGE_OUT="$OUT_DIR/gitleaks_range_raw.json"
  ZERO_SHA="0000000000000000000000000000000000000000"

  # Pre-initialize range file with an empty JSON array.
  # This guarantees the file always exists after this block. If the range scan
  # fails for any reason, the normalizer will read [] instead of a missing file,
  # preventing it from defaulting all findings to in_latest_push=true (which
  # would block deployments for secrets added months ago).
  printf '[]' > "$RANGE_OUT"

  LOG_OPTS=""
  if [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}" \
        && "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}" != "$ZERO_SHA" ]]; then
    if git_sha_reachable "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}"; then
      LOG_OPTS="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}..${CI_COMMIT_SHA:-HEAD}"
    else
      # SHA exists in CI variables but is not in the local clone (fork clone, shallow
      # fetch, or corrupted variable). Fall back to just the latest commit so the
      # range report is non-empty and correct for the current push.
      log "WARN: CI_MERGE_REQUEST_TARGET_BRANCH_SHA=${CI_MERGE_REQUEST_TARGET_BRANCH_SHA} not reachable in clone — falling back to latest-commit range"
      LOG_OPTS="--max-count=1"
    fi
  elif [[ -n "${CI_COMMIT_BEFORE_SHA:-}" \
          && "${CI_COMMIT_BEFORE_SHA}" != "$ZERO_SHA" ]]; then
    if git_sha_reachable "${CI_COMMIT_BEFORE_SHA}"; then
      LOG_OPTS="${CI_COMMIT_BEFORE_SHA}..${CI_COMMIT_SHA:-HEAD}"
    else
      # Before-SHA not reachable (force-push rewrote history, or rebase rebased
      # commits that aren't locally present). Scan only the latest commit.
      log "WARN: CI_COMMIT_BEFORE_SHA=${CI_COMMIT_BEFORE_SHA} not reachable (force-push?) — falling back to latest-commit range"
      LOG_OPTS="--max-count=1"
    fi
  else
    # First push to a new branch: no before/after SHA available.
    # Scan the last 200 commits as a reasonable approximation of what is new.
    LOG_OPTS="--max-count=200"
  fi

  log "Starting range scan (enrichissement, best-effort, log-opts='$LOG_OPTS')..."
  set +e
  run_cmd gitleaks detect \
    --source "$GITLEAKS_SOURCE_PATH" \
    --log-opts "$LOG_OPTS" \
    --redact \
    --config "$CONFIG_PATH" \
    "${IGNORE_ARGS[@]}" \
    "${BASELINE_ARGS[@]}" \
    --report-format json \
    --report-path "$RANGE_OUT" \
    --max-target-megabytes "$MAX_SIZE_MB"
  RC_RANGE=$?
  set -e

  if [[ "$RC_RANGE" -gt 1 ]]; then
    # Technical failure: keep the pre-initialized [] so the normalizer does not
    # treat all findings as new.
    log "WARN: range scan failed rc=$RC_RANGE — range report stays empty (no in_latest_push enrichment)"
  else
    # Gitleaks may not overwrite the file when there are no findings (version-
    # dependent). Re-validate and reset to [] if the file is absent or non-array.
    if ! jq -e 'type=="array"' "$RANGE_OUT" >/dev/null 2>&1; then
      log "WARN: range report missing or invalid JSON after scan — resetting to empty array"
      printf '[]' > "$RANGE_OUT"
    fi

    if jq -e 'length > 0' "$RANGE_OUT" >/dev/null 2>&1; then
      enrich_with_secret_hash "$RANGE_OUT"
      log "Range report ready: $RANGE_OUT"
      # Merge range findings into the main report for OPA gate evaluation.
      # Deduplication uses composite key (RuleID:File:StartLine:SecretHash), not Fingerprint.
      # File is normalized (absolute repo prefix removed, slashes unified) to align --no-git vs --log-opts.
      MERGED_COUNT=$(jq -s --arg repo_root "$REPO_ROOT" '
        def dedup_key:
          def norm_file:
            ((.File // .file // "") | tostring
             | gsub("\\\\"; "/")
             | if startswith(($repo_root | tostring) + "/")
               then .[(($repo_root | tostring | length) + 1):]
               else .
               end
             | gsub("^\\./+"; ""));
          [
            ((.RuleID // .rule_id // "GITLEAKS_UNKNOWN") | tostring | ascii_upcase),
            norm_file,
            ((.StartLine // .start_line // .line // 0) | tostring),
            ((.CloudSentinelSecretHash // .SecretHash // .secret_hash // "") | tostring)
          ] | join(":");
        .[0] + .[1] | unique_by(dedup_key)
      ' \
        "$REPORT_RAW_OUT" "$RANGE_OUT" | jq 'length')
      jq -s --arg repo_root "$REPO_ROOT" '
        def dedup_key:
          def norm_file:
            ((.File // .file // "") | tostring
             | gsub("\\\\"; "/")
             | if startswith(($repo_root | tostring) + "/")
               then .[(($repo_root | tostring | length) + 1):]
               else .
               end
             | gsub("^\\./+"; ""));
          [
            ((.RuleID // .rule_id // "GITLEAKS_UNKNOWN") | tostring | ascii_upcase),
            norm_file,
            ((.StartLine // .start_line // .line // 0) | tostring),
            ((.CloudSentinelSecretHash // .SecretHash // .secret_hash // "") | tostring)
          ] | join(":");
        .[0] + .[1] | unique_by(dedup_key)
      ' \
        "$REPORT_RAW_OUT" "$RANGE_OUT" > "${REPORT_RAW_OUT}.merged"
      mv "${REPORT_RAW_OUT}.merged" "$REPORT_RAW_OUT"
      log "Merged range findings into main report. Total unique findings: $MERGED_COUNT"
    else
      log "Range scan produced no findings — range report is empty"
    fi
  fi
fi

exit 0
