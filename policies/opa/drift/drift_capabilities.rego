# ==============================================================================
# Shift-Right Drift — remediation capabilities registry helpers
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

default _capabilities := {}

_capabilities := caps if {
	caps := object.get(input, "capabilities", {})
	is_object(caps)
}

capability_for_policy(policy) := cap if {
	is_string(policy)
	policy != ""
	cap := object.get(_capabilities, policy, {})
	is_object(cap)
} else := {}

policy_remediation_supported(policy) if {
	cap := capability_for_policy(policy)
	object.get(cap, "remediation_supported", false)
}

policy_verification_script(policy) := script if {
	cap := capability_for_policy(policy)
	script := object.get(cap, "verification_script", "")
	is_string(script)
	script != ""
} else := ""
