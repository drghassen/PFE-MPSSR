# ==============================================================================
# Shift-Right Prowler — remediation capabilities registry helpers
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

default _capabilities := {}

_capabilities := caps if {
	caps := object.get(input, "capabilities", {})
	is_object(caps)
}

capability_for_check(check_id) := cap if {
	is_string(check_id)
	check_id != ""
	key := sprintf("prowler:%s", [check_id])
	cap := object.get(_capabilities, key, {})
	is_object(cap)
} else := {}

check_remediation_supported(check_id) := true if {
	cap := capability_for_check(check_id)
	object.get(cap, "remediation_supported", false)
} else := false

check_custodian_policy(check_id) := policy if {
	cap := capability_for_check(check_id)
	policy := object.get(cap, "custodian_policy", "")
	is_string(policy)
	policy != ""
} else := null

check_verification_script(check_id) := script if {
	cap := capability_for_check(check_id)
	script := object.get(cap, "verification_script", "")
	is_string(script)
	script != ""
} else := ""
