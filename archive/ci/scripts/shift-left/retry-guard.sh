#!/usr/bin/env bash
set -euo pipefail

# Archived entrypoint (not used by active shift-left pipeline).
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)"

bash "$REPO_ROOT/archive/shift-left/ci/retry-guard.sh"
