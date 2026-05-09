# ==============================================================================
# Shift-Right Drift — changed_paths helpers
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# A changed path matches a key when:
# - exact match: "security_rule"
# - nested object path: "security_rule.name"
# - indexed list path: "security_rule[0].access"
path_matches_key(path, key) if {
	path == key
}

path_matches_key(path, key) if {
	startswith(path, sprintf("%s.", [key]))
}

path_matches_key(path, key) if {
	startswith(path, sprintf("%s[", [key]))
}

changed_paths_has_key(finding, key) if {
	some p in object.get(finding, "changed_paths", [])
	is_string(p)
	path_matches_key(p, key)
}
