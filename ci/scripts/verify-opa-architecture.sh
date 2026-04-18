#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel — OPA subsystem isolation & split test scopes
#
# Verifies:
#   - No textual cross-import between policies/opa/gate and policies/opa/drift
#   - opa check on full tree (includes architecture/, gate/, drift/, system/)
#   - opa test in three scopes: gate, drift, system authz
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

set +e
G1=$(grep -R "cloudsentinel\.gate\|data\.cloudsentinel\.gate" policies/opa/drift --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
G2=$(grep -R "shiftright\.drift\|cloudsentinel\.shiftright" policies/opa/gate --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
set -e
G1=${G1:-0}
G2=${G2:-0}

if [[ "${G1}" -ne 0 ]] || [[ "${G2}" -ne 0 ]]; then
	echo "[verify-opa-architecture] FAIL: cross-subsystem Rego references detected (drift→gate: ${G1}, gate→drift: ${G2})" >&2
	exit 1
fi

set +e
opa check policies/opa
CHK=$?
set -e
[[ "${CHK}" -eq 0 ]] || exit "${CHK}"

set +e
opa test policies/opa/gate policies/opa/pipeline_decision_test.rego policies/opa/test_pipeline_decision.rego -v
TG=$?
set -e
[[ "${TG}" -eq 0 ]] || exit "${TG}"

set +e
opa test policies/opa/drift policies/opa/drift_decision_test.rego -v
TD=$?
set -e
[[ "${TD}" -eq 0 ]] || exit "${TD}"

set +e
opa test policies/opa/system/authz.rego policies/opa/system/authz_test.rego -v
TS=$?
set -e
[[ "${TS}" -eq 0 ]] || exit "${TS}"

echo "[verify-opa-architecture] OK — cross-ref guard, opa check, gate/drift/system test scopes passed."
