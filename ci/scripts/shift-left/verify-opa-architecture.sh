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

print_line() {
	printf '%s\n' '==============================================================================='
}

print_header() {
	print_line
	printf 'CloudSentinel OPA Unit Tests\n'
	print_line
	printf 'Purpose : Validate policy syntax, decision logic, and subsystem isolation\n'
	printf 'Scope   : Gate + Drift + Prowler + Authz\n'
	printf 'Mode    : fail-closed policy contract\n'
	print_line
}

print_cross_ref_summary() {
	print_line
	printf 'OPA Subsystem Isolation\n'
	print_line
	printf '%-18s %-18s %-8s %-8s\n' 'Source' 'Forbidden target' 'Matches' 'Status'
	printf '%-18s %-18s %-8s %-8s\n' '------' '----------------' '-------' '------'
	printf '%-18s %-18s %-8s %-8s\n' 'drift' 'gate' "${D2G}" 'PASS'
	printf '%-18s %-18s %-8s %-8s\n' 'gate' 'drift' "${G2D}" 'PASS'
	printf '%-18s %-18s %-8s %-8s\n' 'prowler' 'gate' "${P2G}" 'PASS'
	printf '%-18s %-18s %-8s %-8s\n' 'prowler' 'drift' "${P2D}" 'PASS'
	printf '%-18s %-18s %-8s %-8s\n' 'drift' 'prowler' "${D2P}" 'PASS'
	printf '%-18s %-18s %-8s %-8s\n' 'gate' 'prowler' "${G2P}" 'PASS'
}

run_opa_check() {
	local output rc

	set +e
	output="$(opa check policies/opa 2>&1)"
	rc=$?
	set -e

	if [[ "$rc" -ne 0 ]]; then
		print_line
		printf 'OPA Syntax Check: FAIL\n'
		print_line
		printf '%s\n' "$output"
		exit "$rc"
	fi

	print_line
	printf 'OPA Syntax Check\n'
	print_line
	printf '%-28s %-8s %s\n' 'Control' 'Status' 'Path'
	printf '%-28s %-8s %s\n' '-------' '------' '----'
	printf '%-28s %-8s %s\n' 'opa check' 'PASS' 'policies/opa'
}

OPA_TOTAL_PASSED=0
OPA_TOTAL_TESTS=0
OPA_SUITE_ROWS=""

run_opa_suite() {
	local name="$1"
	local perimeter="$2"
	shift 2

	local output rc passed total result_line
	set +e
	output="$("$@" 2>&1)"
	rc=$?
	set -e

	if [[ "$rc" -ne 0 ]]; then
		print_line
		printf 'OPA Suite Failed: %s\n' "$name"
		print_line
		printf '%s\n' "$output"
		exit "$rc"
	fi

	result_line="$(printf '%s\n' "$output" | sed -n 's/^PASS: \([0-9][0-9]*\)\/\([0-9][0-9]*\)$/\1 \2/p' | tail -1)"
	if [[ -z "$result_line" ]]; then
		print_line
		printf 'OPA Suite Result Parse Failed: %s\n' "$name"
		print_line
		printf '%s\n' "$output"
		exit 1
	fi

	read -r passed total <<< "$result_line"
	OPA_TOTAL_PASSED=$((OPA_TOTAL_PASSED + passed))
	OPA_TOTAL_TESTS=$((OPA_TOTAL_TESTS + total))
	OPA_SUITE_ROWS+="${name}"$'\t'"${passed}/${total}"$'\t'"PASS"$'\t'"${perimeter}"$'\n'
}

print_opa_suite_summary() {
	print_line
	printf 'OPA Policy Test Summary\n'
	print_line
	printf '%-12s %-10s %-8s %s\n' 'Family' 'Result' 'Status' 'Perimeter validated'
	printf '%-12s %-10s %-8s %s\n' '------' '------' '------' '-------------------'
	printf '%s' "$OPA_SUITE_ROWS" | while IFS=$'\t' read -r family result status perimeter; do
		[[ -z "$family" ]] && continue
		printf '%-12s %-10s %-8s %s\n' "$family" "$result" "$status" "$perimeter"
	done
	printf '%-12s %-10s %-8s %s\n' 'TOTAL' "${OPA_TOTAL_PASSED}/${OPA_TOTAL_TESTS}" 'PASS' 'All OPA policy suites'
	print_line
	printf 'Decision model      : OPA is the single ALLOW/DENY authority\n'
	printf 'Architecture guard  : gate, drift, prowler, and authz remain isolated\n'
	print_line
}

print_header

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
	echo "[verify-opa-architecture] FAIL: cross-subsystem Rego references detected (drift->gate: ${D2G}, gate->drift: ${G2D}, prowler->gate: ${P2G}, prowler->drift: ${P2D}, drift->prowler: ${D2P}, gate->prowler: ${G2P})" >&2
	exit 1
fi

print_cross_ref_summary
run_opa_check
run_opa_suite \
	"Gate" \
	"severity thresholds, approved exceptions, schema, role-spoofing signals" \
	opa test policies/opa/gate policies/opa/pipeline_decision_test.rego policies/opa/test_pipeline_decision.rego
run_opa_suite \
	"Drift" \
	"runtime drift classification, exceptions, graded corrective actions" \
	opa test policies/opa/drift policies/opa/drift_decision_test.rego
run_opa_suite \
	"Prowler" \
	"runtime posture findings, exceptions, ticket-and-notify routing" \
	opa test policies/opa/prowler policies/opa/prowler_decision_test.rego
run_opa_suite \
	"Authz" \
	"OPA server authentication and decision access control" \
	opa test policies/opa/system/authz.rego policies/opa/system/authz_test.rego
print_opa_suite_summary

echo "[verify-opa-architecture] OK - cross-ref guard, opa check, gate/drift/prowler/system test scopes passed."
