#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel — Artifact Contract Test (detection + normalization)
# Fail-fast guard before OPA decision stage.

bash ci/artifact-integrity-check.sh --up-to normalization

echo "[contract] Detection + normalization artifact integrity checks passed."
