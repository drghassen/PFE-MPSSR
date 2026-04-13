#!/usr/bin/env bash
set -euo pipefail

############################################
# CloudSentinel Pre-Commit Hook v5.1 (PFE)
# Thin wrapper delegating to the advisory orchestrator.
############################################

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ORCHESTRATOR="${REPO_ROOT}/shift-left/pre-commit/pre-commit.sh"

# Advisory contract: never block commits due to missing local tooling/scripts.
if [[ ! -f "$ORCHESTRATOR" ]]; then
  echo "[CloudSentinel][pre-commit][WARN] Orchestrator not found: $ORCHESTRATOR. Skipping."
  exit 0
fi

exec bash "$ORCHESTRATOR"
