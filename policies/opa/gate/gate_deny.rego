package cloudsentinel.gate

import rego.v1

# Deny rules: scanners, thresholds, prod exceptions, exception governance (module 7/8)

deny[msg] if {
	scanner_not_run[name]
	msg := sprintf("Scanner %s did not run or report is invalid", [name])
}

deny[msg] if {
	not thresholds_valid
	msg := "Invalid threshold configuration: critical_max/high_max must be numeric"
}

deny[msg] if {
	effective_critical > enforced_critical_max
	msg := sprintf(
		"CRITICAL findings (%d) exceed enforced threshold (%d)",
		[effective_critical, enforced_critical_max],
	)
}

deny[msg] if {
	effective_high > enforced_high_max
	msg := sprintf(
		"HIGH findings (%d) exceed enforced threshold (%d)",
		[effective_high, enforced_high_max],
	)
}

deny[msg] if {
	prod_critical_exception_violation[ex_id]
	msg := sprintf("Exception %s is invalid for prod: severity CRITICAL is forbidden", [ex_id])
}

deny[msg] if {
	invalid_enabled_exception_ids[ex_id]
	msg := sprintf("Exception %s is malformed: required governance fields are invalid", [ex_id])
}

deny[msg] if {
	exception_status_not_approved_ids[ex_id]
	msg := sprintf("Exception %s is invalid: status must be approved", [ex_id])
}

deny[msg] if {
	exception_missing_approved_by_ids[ex_id]
	msg := sprintf("Exception %s is invalid: approved_by is required", [ex_id])
}

deny[msg] if {
	exception_missing_approved_at_ids[ex_id]
	msg := sprintf("Exception %s is invalid: approved_at is required (RFC3339)", [ex_id])
}

deny[msg] if {
	expired_enabled_exception_ids[ex_id]
	msg := sprintf("Exception %s is invalid: expires_at is in the past", [ex_id])
}
