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
	"CS-ROLE-SPOOFING-INTENT",
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

# Heuristic 1 (priority): exact resource address match.
# "azurerm_linux_virtual_machine.this" == finding resource name.
# Most precise — no false positives between VMs in the same file.
_same_resource(vm_address, vm_file, finding_resource, finding_file) if {
	lower(trim_space(vm_address)) == lower(trim_space(finding_resource))
}

# Heuristic 2: VM logical name is contained in the finding resource identifier.
# Handles cases where checkov reports the resource as just "this" or "module.compute.this".
_same_resource(vm_address, vm_file, finding_resource, finding_file) if {
	vm_parts := split(lower(trim_space(vm_address)), ".")
	count(vm_parts) > 1
	vm_name := trim_space(vm_parts[count(vm_parts) - 1])
	vm_name != ""
	contains(lower(trim_space(finding_resource)), vm_name)
}

# NOTE: file-based heuristic deliberately removed.
# Matching on .tf file path alone caused inter-VM pollution: a Checkov finding
# on VM-B in the same file would trigger the role-spoofing deny for VM-A.

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

# Multi-signal role spoofing detection — two severity levels.
#
# Signals:
#   signal_1: IaC tag cs:role=web-server       — static governance contract
#   signal_2: cloud-init installs DB packages  — behavioral evidence of mismatch
#   signal_3: corroborating Checkov finding    — independent scanner confirmation
#
# LEVEL 1 (CS-ROLE-SPOOFING-INTENT): signals 1+2 alone.
#   Blocks in prod. Advisory warn in dev/staging.
#   Catches the "clean IaC + malicious cloud-init" evasion: a dev who writes
#   a perfectly Checkov-compliant IaC (encrypted disks, tight NSG, managed
#   identity) but installs a DB in cloud-init would bypass a 3-signal gate.
#   Signals 1+2 are sufficient evidence of intent mismatch in prod.
#
# LEVEL 2 (CS-MULTI-SIGNAL-ROLE-SPOOFING-V2): signals 1+2+3.
#   Blocks in all environments including dev — Checkov independently
#   confirms a misconfiguration on the same resource, elevating confidence.
#   Non-waivable everywhere.

# Level 1 — prod blocking (signals 1+2 sufficient).
deny[msg] if {
	some resource in resources_analyzed
	resource_is_prod(resource)
	resource_role(resource) == "web-server"
	object.get(resource_signals(resource), "role_spoofing_candidate", false)
	db_pkgs := object.get(resource_signals(resource), "db_packages_detected", [])
	msg := sprintf(
		"CS-ROLE-SPOOFING-INTENT [CRITICAL|non_waivable]: tag:web-server conflicts with cloud-init DB workload on %s (packages=%v, env=%s)",
		[object.get(resource, "resource_address", "unknown"), db_pkgs, resource_env(resource)],
	)
}

# Level 1 — dev/staging advisory warn (signals 1+2, non-prod).
warn[msg] if {
	some resource in resources_analyzed
	not resource_is_prod(resource)
	resource_role(resource) == "web-server"
	object.get(resource_signals(resource), "role_spoofing_candidate", false)
	db_pkgs := object.get(resource_signals(resource), "db_packages_detected", [])
	msg := sprintf(
		"CS-ROLE-SPOOFING-INTENT [WARNING|advisory]: tag:web-server conflicts with cloud-init DB workload on %s (packages=%v, env=%s) — will block in prod",
		[object.get(resource, "resource_address", "unknown"), db_pkgs, resource_env(resource)],
	)
}

# Level 2 — 3-signal corroboration, all environments including dev.
# Fires when Checkov independently confirms a HIGH/CRITICAL misconfiguration
# on the same VM resource, corroborating the intent mismatch.
deny[msg] if {
	some resource in resources_analyzed
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
		"CS-MULTI-SIGNAL-ROLE-SPOOFING-V2 [CRITICAL|non_waivable|3-signal-corroborated]: role spoofing on %s — tag:web-server + cloud-init:db-workload + checkov:%s/%s (env=%s)",
		[
			object.get(resource, "resource_address", "unknown"),
			finding_tool(finding),
			finding_severity_level(finding),
			resource_env(resource),
		],
	)
}

# Keep schema governance deny for gate payload compatibility.
deny[msg] if {
	schema_version := object.get(input, "schema_version", "")
	not regex.match(`^1\.([2-9]|[1-9][0-9]+)\.\d+$`, schema_version)
	msg := "CS-SCHEMA-VERSION-UNSUPPORTED [CRITICAL|non_waivable]: schema_version is unsupported or missing"
}
