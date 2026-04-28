#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel — OPA subsystem isolation & split test scopes
#
# Verifies:
#   - No textual cross-import between policies/opa/gate, drift and prowler
#   - opa check on full tree (includes architecture/, gate/, drift/, system/)
#   - opa test in four scopes: gate, drift, prowler, system authz
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

set +e
D2G=$(grep -R "cloudsentinel\\.gate\\|data\\.cloudsentinel\\.gate" policies/opa/drift --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
G2D=$(grep -R "shiftright\\.drift\\|cloudsentinel\\.shiftright\\.drift" policies/opa/gate --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
P2G=$(grep -R "cloudsentinel\\.gate\\|data\\.cloudsentinel\\.gate" policies/opa/prowler --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
P2D=$(grep -R "shiftright\\.drift\\|cloudsentinel\\.shiftright\\.drift" policies/opa/prowler --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
D2P=$(grep -R "shiftright\\.prowler\\|cloudsentinel\\.shiftright\\.prowler" policies/opa/drift --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
G2P=$(grep -R "shiftright\\.prowler\\|cloudsentinel\\.shiftright\\.prowler" policies/opa/gate --include='*.rego' 2>/dev/null | wc -l | tr -d ' ')
set -e

D2G=${D2G:-0}
G2D=${G2D:-0}
P2G=${P2G:-0}
P2D=${P2D:-0}
D2P=${D2P:-0}
G2P=${G2P:-0}

if [[ "${D2G}" -ne 0 ]] || [[ "${G2D}" -ne 0 ]] || [[ "${P2G}" -ne 0 ]] || [[ "${P2D}" -ne 0 ]] || [[ "${D2P}" -ne 0 ]] || [[ "${G2P}" -ne 0 ]]; then
	echo "[verify-opa-architecture] FAIL: cross-subsystem Rego references detected (drift→gate: ${D2G}, gate→drift: ${G2D}, prowler→gate: ${P2G}, prowler→drift: ${P2D}, drift→prowler: ${D2P}, gate→prowler: ${G2P})" >&2
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
opa test policies/opa/prowler policies/opa/prowler_decision_test.rego -v
TP=$?
set -e
[[ "${TP}" -eq 0 ]] || exit "${TP}"

set +e
opa test policies/opa/system/authz.rego policies/opa/system/authz_test.rego -v
TS=$?
set -e
[[ "${TS}" -eq 0 ]] || exit "${TS}"

echo "[verify-opa-architecture] OK — cross-ref guard, opa check, gate/drift/prowler/system test scopes passed."
