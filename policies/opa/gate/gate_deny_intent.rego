package cloudsentinel.gate

import rego.v1

# Cloud-init role-spoofing v2 rules.
# Non-waivable in production and staging.

non_waivable_violations := {
	"CS-CLOUDINIT-ROLE-TAG-MISSING",
	"CS-CLOUDINIT-REMOTE-EXEC",
	"CS-CLOUDINIT-SSH-KEY-INJECTION",
	"CS-CLOUDINIT-FIREWALL-DISABLE",
	"CS-CLOUDINIT-HARDCODED-CREDENTIALS",
	"CS-MULTI-SIGNAL-ROLE-SPOOFING-V2",
	"CS-SCHEMA-VERSION-UNSUPPORTED",
}

resources_analyzed := object.get(input, "resources_analyzed", [])

resource_signals(resource) := object.get(resource, "signals", {})

resource_env(resource) := lower(trim_space(object.get(resource, "environment", environment)))

# Enforced environments: prod and staging both block critical cloud-init violations.
# Rationale: staging VMs share internal networks and service accounts with prod;
# a remote exec payload in staging is a realistic lateral movement vector.
resource_is_enforced(resource) if {
	resource_env(resource) in {"prod", "staging"}
}

resource_is_prod(resource) if {
	resource_env(resource) == "prod"
}

resource_role(resource) := lower(trim_space(object.get(resource, "role_tag", "")))

_same_resource(vm_address, vm_file, finding_resource, finding_file) if {
	vm_addr := lower(trim_space(vm_address))
	vm_parts := split(vm_addr, ".")
	count(vm_parts) > 1
	vm_name := trim_space(vm_parts[1])
	vm_name != ""
	contains(lower(trim_space(finding_resource)), vm_name)
}

_same_resource(vm_address, vm_file, finding_resource, finding_file) if {
	vm_tf_file := normalize_path(vm_file)
	finding_tf_file := normalize_path(finding_file)
	vm_tf_file != ""
	finding_tf_file != ""
	lower(vm_tf_file) == lower(finding_tf_file)
	endswith(lower(vm_tf_file), ".tf")
}

# Missing mandatory cs:role tag on VM resources (all environments).
# Governance decision: tag contract is always required.
deny[msg] if {
	some resource in resources_analyzed
	object.get(resource_signals(resource), "role_tag_missing", false)
	msg := sprintf(
		"CS-CLOUDINIT-ROLE-TAG-MISSING [CRITICAL|non_waivable]: cs:role is missing on VM resource %s",
		[object.get(resource, "resource_address", "unknown")],
	)
}

# Remote execution payload in cloud-init is forbidden in staging AND prod.
# Rationale: curl|bash / wget|bash / eval $(curl ...) etc. in a bootstrap script
# represents unverified remote code execution at VM root — a supply chain attack vector.
# Dev is advisory-only (block=false set by the scanner).
deny[msg] if {
	some resource in resources_analyzed
	resource_is_enforced(resource)
	object.get(resource_signals(resource), "remote_exec_detected", false)
	patterns := object.get(resource_signals(resource), "remote_exec_patterns", [])
	msg := sprintf(
		"CS-CLOUDINIT-REMOTE-EXEC [CRITICAL|non_waivable]: remote execution pattern detected on %s (patterns=%v, env=%s)",
		[
			object.get(resource, "resource_address", "unknown"),
			patterns,
			resource_env(resource),
		],
	)
}

# SSH key injection in cloud-init — persistent backdoor access.
# Non-waivable in staging and prod: ssh_authorized_keys stanza plants attacker keys.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_enforced(resource)
	bypass_patterns := object.get(resource_signals(resource), "security_bypass_patterns", [])
	"ssh_key_injection" in bypass_patterns
	msg := sprintf(
		"CS-CLOUDINIT-SSH-KEY-INJECTION [CRITICAL|non_waivable]: SSH authorized_keys injection on %s (env=%s)",
		[object.get(resource, "resource_address", "unknown"), resource_env(resource)],
	)
}

# Firewall / security daemon disable — exposes VM to direct network attacks.
# Non-waivable in staging and prod.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_enforced(resource)
	bypass_patterns := object.get(resource_signals(resource), "security_bypass_patterns", [])
	"firewall_disable" in bypass_patterns
	msg := sprintf(
		"CS-CLOUDINIT-FIREWALL-DISABLE [CRITICAL|non_waivable]: firewall/security daemon disabled on %s (env=%s)",
		[object.get(resource, "resource_address", "unknown"), resource_env(resource)],
	)
}

# Hardcoded credentials in cloud-init runcmd.
# Non-waivable in staging and prod: secrets end up in Terraform state and VM metadata API.
deny[msg] if {
	some resource in resources_analyzed
	resource_is_enforced(resource)
	bypass_patterns := object.get(resource_signals(resource), "security_bypass_patterns", [])
	"hardcoded_credentials" in bypass_patterns
	msg := sprintf(
		"CS-CLOUDINIT-HARDCODED-CREDENTIALS [CRITICAL|non_waivable]: hardcoded secrets in cloud-init on %s (env=%s)",
		[object.get(resource, "resource_address", "unknown"), resource_env(resource)],
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
	_same_resource(
		object.get(resource, "resource_address", ""),
		object.get(resource, "file", ""),
		finding_resource_id(finding),
		finding_occurrence_file(finding),
	)

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
	not regex.match(`^1\.([2-9]|[1-9][0-9]+)\.\d+$`, schema_version)
	msg := "CS-SCHEMA-VERSION-UNSUPPORTED [CRITICAL|non_waivable]: schema_version is unsupported or missing"
}
