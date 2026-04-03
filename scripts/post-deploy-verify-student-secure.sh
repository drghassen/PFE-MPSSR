#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-infra/azure/student-secure}"
TRIVY_IMAGE_TARGET="${2:-alpine:3.21}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

mkdir -p .cloudsentinel

echo "[post-deploy] running full shift-left verification..."
bash "$REPO_ROOT/scripts/verify-student-secure.sh" "$TARGET_DIR" "$TRIVY_IMAGE_TARGET"

echo "[post-deploy] enforcing zero findings gate..."
bash "$REPO_ROOT/scripts/ci/enforce-zero-findings.sh" ".cloudsentinel/golden_report.json"

if [[ -f ".cloudsentinel/terraform_outputs_student_secure.json" ]]; then
  echo "[post-deploy] validating terraform outputs contract..."
  jq -e 'type == "object"' ".cloudsentinel/terraform_outputs_student_secure.json" >/dev/null
fi

echo "[post-deploy] SUCCESS - deployment verification passed."
