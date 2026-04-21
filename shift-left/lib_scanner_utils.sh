#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel - Shared Scanner Utilities (v5.2)
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cs_log_info()  { echo -e "${BLUE}[CloudSentinel][INFO]${NC} $*"; }
cs_log_warn()  { echo -e "${YELLOW}[CloudSentinel][WARN]${NC} $*" >&2; }
cs_log_err()   { echo -e "${RED}[CloudSentinel][ERROR]${NC} $*" >&2; }

cs_get_repo_root() {
    local root
    if root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
        echo "$root"
    else
        echo "$PWD"
    fi
}

# Emit a deterministic fail-closed scanner payload.
# Contract: {tool, version, status, findings, errors}
cs_emit_not_run() {
    local tool_name="$1"
    local report_file="$2"
    local reason="$3"
    local repo_root="$4"
    local branch
    local commit

    branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
    commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

    cs_log_warn "Scanner '$tool_name' marked as NOT_RUN: $reason"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
          --arg tool "$tool_name" \
          --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
          --arg branch "$branch" \
          --arg commit "$commit" \
          --arg repo "${repo_root:-unknown}" \
          --arg reason "$reason" \
          '{
            tool: $tool,
            version: "unknown",
            has_findings: false,
            status: "NOT_RUN",
            timestamp: $timestamp,
            branch: $branch,
            commit: $commit,
            repository: $repo,
            stats: {
              CRITICAL: 0,
              HIGH: 0,
              MEDIUM: 0,
              LOW: 0,
              INFO: 0,
              TOTAL: 0,
              EXEMPTED: 0,
              FAILED: 0,
              PASSED: 0,
              by_type: { vulnerability: 0, secret: 0, misconfig: 0 },
              by_category: { INFRASTRUCTURE: 0, APPLICATION: 0, CONFIGURATION: 0, SECRET: 0 }
            },
            errors: [$reason],
            findings: []
          }' > "$report_file"
        return
    fi

    # jq missing fallback: keep strict contract so downstream can fail-closed.
    local safe_reason="${reason//\\/\\\\}"
    safe_reason="${safe_reason//\"/\\\"}"
    cat > "$report_file" <<EOF
{"tool":"$tool_name","version":"unknown","has_findings":false,"status":"NOT_RUN","timestamp":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")","branch":"$branch","commit":"$commit","repository":"${repo_root:-unknown}","stats":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"TOTAL":0,"EXEMPTED":0,"FAILED":0,"PASSED":0,"by_type":{"vulnerability":0,"secret":0,"misconfig":0},"by_category":{"INFRASTRUCTURE":0,"APPLICATION":0,"CONFIGURATION":0,"SECRET":0}},"errors":["$safe_reason"],"findings":[]}
EOF
}