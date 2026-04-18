package cloudsentinel.gate

import rego.v1

# Final decision document (module 8b/8)

default allow := false

allow if {
	count(deny) == 0
}

deny_reasons := sort([msg | deny[msg]])

decision := {
	"allow": allow,
	"deny": deny_reasons,
	"metrics": {
		"critical": effective_critical,
		"high": effective_high,
		"medium": effective_medium,
		"low": effective_low,
		"info": 0,
		"failed": count(effective_failed_findings),
		"failed_input": count(failed_findings),
		"failed_effective": count(effective_failed_findings),
		"excepted": count(excepted_failed_findings),
		"excepted_findings": count(excepted_failed_findings),
		"excepted_exception_ids": count(applied_exception_ids),
		"governance": {
			"active_exceptions_by_severity": {
				"CRITICAL": active_exceptions_critical,
				"HIGH": active_exceptions_high,
				"MEDIUM": active_exceptions_medium,
				"LOW": active_exceptions_low,
				"INFO": 0,
			},
			"active_break_glass": active_break_glass_count,
			"expired_enabled_exceptions": count(expired_enabled_exception_ids),
			"avg_approval_time_hours": avg_approval_time_hours,
		},
	},
	"thresholds": {
		"critical_max": critical_max_raw,
		"high_max": high_max_raw,
		"enforced_critical_max": enforced_critical_max,
		"enforced_high_max": enforced_high_max,
	},
	"environment": environment,
	"execution_mode": execution_mode,
	"exceptions": {
		"applied_ids": sort([id | applied_exception_ids[id]]),
		"applied_count": count(applied_exception_ids),
		"applied_audit": [item | applied_exception_audit[item]],
		"partial_matches_audit": [item | partial_matches_audit[item]],
		"strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
		"invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]]),
		"expired_enabled_ids": sort([id | expired_enabled_exception_ids[id]]),
		"legacy_after_sunset_ids": sort([id | legacy_exception_after_sunset[id]]),
	},
}
