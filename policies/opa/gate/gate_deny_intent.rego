package cloudsentinel.gate

import rego.v1

# Cloud-init role-spoofing v2 rules.
# Non-waivable in production.

non_waivable_violations := {
	"CS-CLOUDINIT-ROLE-TAG-MISSING",
	"CS-CLOUDINIT-REMOTE-EXEC",
	"CS-MULTI-SIGNAL-ROLE-SPOOFING-V2",
	"CS-SCHEMA-VERSION-UNSUPPORTED",
}

resources_analyzed := object.get(input, "resources_analyzed", [])

resource_signals(resource) := object.get(resource, "signals", {})

resource_env(resource) := lower(trim_space(object.get(resource, "environment", environment)))

resource_is_prod(resource) if {
	resource_env(resource) == "prod"
}

resource_role(resource) := lower(trim_space(object.get(resource, "role_tag", "")))

# Missing mandatory cs:role tag on VM resources in prod.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_prod(resource)
	object.get(resource_signals(resource), "role_tag_missing", false)
	msg := sprintf(
		"CS-CLOUDINIT-ROLE-TAG-MISSING [CRITICAL|non_waivable]: cs:role is missing on VM resource %s",
		[object.get(resource, "resource_address", "unknown")],
	)
}

# Remote execution payload in cloud-init is forbidden in prod.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_prod(resource)
	object.get(resource_signals(resource), "remote_exec_detected", false)
	patterns := object.get(resource_signals(resource), "remote_exec_patterns", [])
	msg := sprintf(
		"CS-CLOUDINIT-REMOTE-EXEC [CRITICAL|non_waivable]: remote execution pattern detected on %s (patterns=%v)",
		[object.get(resource, "resource_address", "unknown"), patterns],
	)
}

# Multi-signal role spoofing detection (3 independent signals):
#   signal_1: IaC tag cs:role=web-server
#   signal_2: cloud-init behavior indicates database workload on same VM
#   signal_3: failed checkov HIGH/CRITICAL finding present in raw findings
# Enforced only in prod and non-waivable.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_prod(resource)
	resource_role(resource) == "web-server"
	object.get(resource_signals(resource), "role_spoofing_candidate", false)

	some finding in object.get(input, "findings", [])
	finding_tool(finding) == "checkov"
	finding_severity_level(finding) in {"HIGH", "CRITICAL"}

	msg := sprintf(
		"CS-MULTI-SIGNAL-ROLE-SPOOFING-V2 [CRITICAL|non_waivable]: role spoofing detected on %s (signals=tag:web-server, cloud-init:db-workload, finding:%s|%s)",
		[
			object.get(resource, "resource_address", "unknown"),
			finding_tool(finding),
			finding_severity_level(finding),
		],
	)
}

# Keep schema governance deny for gate payload compatibility.
deny[msg] if {
	schema_version := object.get(input, "schema_version", "")
	not regex.match(`^1\.[2-9][0-9]*\.\d+$`, schema_version)
	msg := "CS-SCHEMA-VERSION-UNSUPPORTED [CRITICAL|non_waivable]: schema_version is unsupported or missing"
}
