#!/bin/bash

set -euo pipefail

echo "[CloudSentinel] Running local secret scan (advisory mode)..."

if ! command -v gitleaks &> /dev/null; then
    echo "[CloudSentinel] Gitleaks not installed. Skipping scan."
    exit 0
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
CONFIG_PATH="$REPO_ROOT/shift-left/gitleaks/gitleaks.toml"

REPORT_PATH=$(mktemp)

gitleaks detect \
    --staged \
    --redact \
    --config "$CONFIG_PATH" \
    --report-format json \
    --report-path "$REPORT_PATH" \
    --no-git

if [ -s "$REPORT_PATH" ]; then
    echo "[CloudSentinel] WARNING: Potential secrets detected."
    echo "[CloudSentinel] Summary (one line per secret type/file):"
    
    jq -r 'group_by(.File, .Description) 
           | map({file: .[0].File, type: .[0].Description, lines: map(.StartLine)}) 
           | .[] 
           | "\(.file) | \(.type) | lignes: \(.lines | join(", "))"' "$REPORT_PATH"
else
    echo "[CloudSentinel] No secrets detected."
fi

rm -f "$REPORT_PATH"

exit 0
