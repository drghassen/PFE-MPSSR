#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "policies-immutability" "guard" "policy-immutability"' EXIT

bash shift-left/ci/enforce-policies-immutability.sh
