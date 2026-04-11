package cloudsentinel.gate_test

import rego.v1

# ─── Shared fixtures ─────────────────────────────────────────────────────────

_scanners_ok := {
	"gitleaks": {"status": "PASSED"},
	"checkov":  {"status": "PASSED"},
	"trivy":    {"status": "PASSED"},
}

_base := {
	"metadata":     {"environment": "dev"},
	"quality_gate": {"thresholds": {"critical_max": 0, "high_max": 2}},
	"scanners":     _scanners_ok,
	"findings":     [],
}

_critical_finding := {
	"status":   "FAILED",
	"source":   {"tool": "trivy", "id": "CVE-TEST-001"},
	"resource": {"name": "my-package"},
	"severity": {"level": "CRITICAL"},
}

_high_finding := {
	"status":   "FAILED",
	"source":   {"tool": "checkov", "id": "CKV_AZ_001"},
	"resource": {"name": "azurerm_storage_account.example"},
	"severity": {"level": "HIGH"},
}

# Valid exception matching _critical_finding exactly (tool/rule_id/resource)
_valid_exception := {
	"id":           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"tool":         "trivy",
	"rule_id":      "CVE-TEST-001",
	"resource":     "my-package",
	"severity":     "CRITICAL",
	"requested_by": "dev-team",
	"approved_by":  "security-team",
	"approved_at":  "2026-01-01T00:00:00Z",
	"expires_at":   "2099-01-01T00:00:00Z",
	"decision":     "accept",
	"source":       "defectdojo",
	"status":       "approved",
}

# ─── TEST 1: Clean pipeline with 0 findings → allow ──────────────────────────
# All 3 scanners present, no findings → decision.allow must be true.

test_allow_clean_pipeline if {
	result := data.cloudsentinel.gate.decision
		with input as _base
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.metrics.critical == 0
	result.metrics.high == 0
}

# ─── TEST 2: 2 HIGH findings at threshold boundary → allow ───────────────────
# high_max=2, enforced_high_max=min(2,5)=2. effective_high=2. 2>2 is false → allow.

test_allow_with_high_within_threshold if {
	f1 := object.union(_high_finding, {"resource": {"name": "res-1"}})
	f2 := object.union(_high_finding, {"resource": {"name": "res-2"}})

	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [f1, f2]})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	result.metrics.high == 2
	count(result.deny) == 0
}

# ─── TEST 3: Valid exception exempts CRITICAL finding → allow ─────────────────
# Exception matches on tool/rule_id/resource. Finding is removed from
# effective_failed_findings, so effective_critical=0 → no threshold deny.

test_allow_with_valid_exception if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as [_valid_exception]

	result.allow
	result.metrics.excepted == 1
	result.metrics.critical == 0
}

# ─── TEST 4: 1 CRITICAL finding, no exception → deny ─────────────────────────
# enforced_critical_max = min(0, 0) = 0. effective_critical=1 > 0 → deny.

test_deny_on_critical if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CRITICAL findings")
	contains(msg, "exceed enforced threshold")
}

# ─── TEST 5: 3 HIGH findings (threshold=2) → deny ────────────────────────────
# enforced_high_max = min(2, 5) = 2. effective_high=3 > 2 → deny.

test_deny_on_high_exceeds_threshold if {
	f1 := object.union(_high_finding, {"resource": {"name": "r1"}})
	f2 := object.union(_high_finding, {"resource": {"name": "r2"}})
	f3 := object.union(_high_finding, {"resource": {"name": "r3"}})

	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [f1, f2, f3]})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "HIGH findings")
	contains(msg, "exceed enforced threshold")
}

# ─── TEST 6: Trivy scanner missing (NOT_RUN) in CI mode → deny ───────────────
# scanner_not_run fires for trivy (is_local is false in default CI mode).

test_deny_missing_scanner if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {
			"scanners": {
				"gitleaks": {"status": "PASSED"},
				"checkov":  {"status": "PASSED"},
				"trivy":    {"status": "NOT_RUN"},
			},
			"findings": [],
		})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "Scanner trivy")
	contains(msg, "did not run")
}

# ─── TEST 7: CI injects critical_max=999 → ceiling clamps to 0, deny ─────────
# _policy_critical_max_ceiling=0. enforced_critical_max=min(999,0)=0.
# With 1 CRITICAL finding: 1>0 → deny regardless of injected value.

test_deny_threshold_injection_attempt if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {
			"quality_gate": {"thresholds": {"critical_max": 999, "high_max": 2}},
			"findings": [_critical_finding],
		})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	result.thresholds.enforced_critical_max == 0
	some msg in result.deny
	contains(msg, "CRITICAL findings")
}

# ─── TEST 8: Expired exception does not exempt CRITICAL finding → deny ────────
# exception_is_expired fires → valid_exception_definition fails → not exempting.
# Additionally expired_enabled_exception_ids fires → own deny message.

test_deny_expired_exception if {
	expired := object.union(_valid_exception, {"expires_at": "2020-01-01T00:00:00Z"})

	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as [expired]

	not result.allow
	# Expired exception generates its own deny
	some exp_msg in result.deny
	contains(exp_msg, "expires_at is in the past")
	# And the CRITICAL finding is no longer exempted
	result.metrics.critical == 1
}

# ─── TEST 9: Duplicate finding is excluded from counts → allow ───────────────
# context.deduplication.is_duplicate=true filters the finding out of
# failed_findings. effective_critical=0 → allow.

test_duplicate_finding_not_counted if {
	dup := object.union(_critical_finding, {
		"context": {"deduplication": {"is_duplicate": true}},
	})

	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {"findings": [dup]})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	result.metrics.critical == 0
	result.metrics.failed_input == 0
}

# ─── TEST 10: Local mode is advisory for scanner checks → allow ───────────────
# NOTE: local mode only bypasses scanner_not_run — threshold violations still
# deny. This test demonstrates the advisory behavior: checkov+trivy both
# NOT_RUN in local mode with 0 findings → allow (scanner absence not blocked).

test_local_mode_advisory if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {
			"metadata": {
				"environment": "dev",
				"execution":   {"mode": "local"},
			},
			"scanners": {
				"gitleaks": {"status": "PASSED"},
				"checkov":  {"status": "NOT_RUN"},
				"trivy":    {"status": "NOT_RUN"},
			},
			"findings": [],
		})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.execution_mode == "local"
}

# ─── TEST 11: trivy-image-scan-* removed, fs+config only → allow ──────────────
# Simulates pipeline after trivy-image-scan-* jobs were removed.
# trivy scanner status is PASSED (fs+config ran), no image reports produced.
# OPA must ALLOW when all three scanners ran and findings are within thresholds.

test_allow_when_trivy_image_scans_removed if {
	result := data.cloudsentinel.gate.decision
		with input as object.union(_base, {
			"scanners": {
				"gitleaks": {"status": "PASSED"},
				"checkov":  {"status": "PASSED"},
				"trivy":    {"status": "PASSED"},
			},
			"findings": [],
		})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.metrics.critical == 0
	result.metrics.high == 0
}
