#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel - Shared Scanner Utilities (v5.1)
# ==============================================================================

# --- Couleurs & Logs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cs_log_info()  { echo -e "${BLUE}[CloudSentinel][INFO]${NC} $*"; }
cs_log_warn()  { echo -e "${YELLOW}[CloudSentinel][WARN]${NC} $*" >&2; }
cs_log_err()   { echo -e "${RED}[CloudSentinel][ERROR]${NC} $*" >&2; }

# --- Résolution Robuste du Répertoire Racine ---
# Règle le problème du crash en mode release/tarball sans le dossier .git
cs_get_repo_root() {
    local root
    if root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
        echo "$root"
    else
        echo "$PWD"
    fi
}

# --- Mutualisation du fallback OPA (DRY Pattern) ---
# Empêche le pipeline d'exploser si un composant échoue (timeout/missing bin)
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
}
