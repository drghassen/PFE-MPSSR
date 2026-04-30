#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel

# advisory -> dry run true
REMEDIATION_MODE=advisory \
OPA_CUSTODIAN_POLICIES="" \
OPA_PROWLER_CUSTODIAN_POLICIES="" \
bash ci/scripts/shift-right/custodian-autofix.sh

grep -q '^CUSTODIAN_DRY_RUN=true$' .cloudsentinel/custodian.env

# enforced -> dry run false
REMEDIATION_MODE=enforced \
OPA_CUSTODIAN_POLICIES="" \
OPA_PROWLER_CUSTODIAN_POLICIES="" \
bash ci/scripts/shift-right/custodian-autofix.sh

grep -q '^CUSTODIAN_DRY_RUN=false$' .cloudsentinel/custodian.env

echo "test_custodian_mode: OK"
