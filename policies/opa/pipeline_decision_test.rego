package cloudsentinel.gate_test

# Functional scenarios for gate allow/deny behavior.

import rego.v1

# Shared fixtures
_scanners_ok := {
	"gitleaks":  {"status": "PASSED"},
	"checkov":   {"status": "PASSED"},
	"trivy":     {"status": "PASSED"},
	"cloudinit": {"status": "PASSED"},
}

_base := {
	"schema_version": "1.3.0",
	"metadata": {"environment": "dev"},
	"quality_gate": {"thresholds": {"critical_max": 0, "high_max": 2}},
	"scanners": _scanners_ok,
	"findings": [],
}

_critical_finding := {
	"status": "FAILED",
	"source": {"tool": "trivy", "id": "CVE-TEST-001"},
	"resource": {"name": "my-package", "path": "my-package", "location": {"file": "my-package", "start_line": 0}},
	"severity": {"level": "CRITICAL"},
}

_high_finding := {
	"status": "FAILED",
	"source": {"tool": "checkov", "id": "CKV_AZ_001"},
	"resource": {"name": "azurerm_storage_account.example", "path": "azurerm_storage_account.example", "location": {"file": "azurerm_storage_account.example", "start_line": 0}},
	"severity": {"level": "HIGH"},
}

_high_finding_same_vm := {
	"status": "FAILED",
	"source": {"tool": "checkov", "id": "CKV_AZ_001"},
	"resource": {
		"name": "azurerm_linux_virtual_machine.web",
		"path": "azurerm_linux_virtual_machine.web",
		"location": {
			"file": "infra/azure/student-secure/modules/compute/main.tf",
			"start_line": 24,
		},
	},
	"severity": {"level": "HIGH"},
}

_critical_storage_finding := {
	"status": "FAILED",
	"source": {"tool": "checkov", "id": "CKV_AZ_999"},
	"resource": {
		"name": "azurerm_storage_account.logs",
		"path": "azurerm_storage_account.logs",
		"location": {
			"file": "infra/azure/student-secure/modules/storage/main.tf",
			"start_line": 42,
		},
	},
	"severity": {"level": "CRITICAL"},
}

_valid_exception := {
	"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"tool": "trivy",
	"rule_id": "CVE-TEST-001",
	"resource": "my-package",
	"severity": "CRITICAL",
	"requested_by": "dev-team",
	"approved_by": "security-team",
	"approved_at": "2026-01-01T00:00:00Z",
	"expires_at": "2099-01-01T00:00:00Z",
	"decision": "accept",
	"source": "defectdojo",
	"status": "approved",
	"occurrence": {"file_path": "my-package", "line": 0, "hash_code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
}

_valid_checkov_exception := {
	"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"tool": "checkov",
	"rule_id": "CKV_AZ_001",
	"resource": "azurerm_storage_account.example",
	"severity": "HIGH",
	"requested_by": "dev-team",
	"approved_by": "security-team",
	"approved_at": "2026-01-01T00:00:00Z",
	"expires_at": "2099-01-01T00:00:00Z",
	"decision": "accept",
	"source": "defectdojo",
	"status": "approved",
	"occurrence": {"file_path": "azurerm_storage_account.example", "line": 0, "hash_code": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
}

_valid_checkov_exception_same_vm := {
	"id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	"tool": "checkov",
	"rule_id": "CKV_AZ_001",
	"resource": "azurerm_linux_virtual_machine.web",
	"severity": "HIGH",
	"requested_by": "dev-team",
	"approved_by": "security-team",
	"approved_at": "2026-01-01T00:00:00Z",
	"expires_at": "2099-01-01T00:00:00Z",
	"decision": "accept",
	"source": "defectdojo",
	"status": "approved",
	"occurrence": {
		"file_path": "infra/azure/student-secure/modules/compute/main.tf",
		"line": 24,
		"hash_code": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	},
}

_cloudinit_web_prod_spoofing := {
	"resource_address": "azurerm_linux_virtual_machine.web",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "web",
	"file": "infra/azure/student-secure/modules/compute/main.tf",
	"environment": "prod",
	"role_tag": "web-server",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": true,
		"remote_exec_detected": false,
		"db_packages_detected": ["postgresql"],
		"remote_exec_patterns": [],
	},
	"violations": [],
}

_cloudinit_prod_missing_tag := {
	"resource_address": "azurerm_linux_virtual_machine.web",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "web",
	"file": "infra/azure/student-secure/modules/compute/main.tf",
	"environment": "prod",
	"role_tag": null,
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": true,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
	},
	"violations": [],
}

_cloudinit_dev_missing_tag := {
	"resource_address": "azurerm_linux_virtual_machine.web",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "web",
	"file": "infra/azure/student-secure/modules/compute/main.tf",
	"environment": "dev",
	"role_tag": null,
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": true,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
	},
	"violations": [],
}

_cloudinit_prod_remote_exec := {
	"resource_address": "azurerm_linux_virtual_machine.web",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "web",
	"file": "infra/azure/student-secure/modules/compute/main.tf",
	"environment": "prod",
	"role_tag": "worker",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": ["curl_pipe_shell"],
	},
	"violations": [],
}

_cloudinit_web_dev_spoofing := {
	"resource_address": "azurerm_linux_virtual_machine.web",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "web",
	"file": "infra/azure/student-secure/modules/compute/main.tf",
	"environment": "dev",
	"role_tag": "web-server",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": true,
		"remote_exec_detected": false,
		"db_packages_detected": ["postgresql"],
		"remote_exec_patterns": [],
	},
	"violations": [],
}

# TEST 1

test_allow_clean_pipeline if {
	result := data.cloudsentinel.gate.decision with input as _base
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.metrics.critical == 0
	result.metrics.high == 0
}

# TEST 2

test_allow_with_high_within_threshold if {
	f1 := object.union(_high_finding, {"resource": {"name": "res-1"}})
	f2 := object.union(_high_finding, {"resource": {"name": "res-2"}})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [f1, f2]})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	result.metrics.high == 2
	count(result.deny) == 0
}

# TEST 3

test_allow_with_valid_exception if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as [_valid_exception]

	result.allow
	result.metrics.excepted == 1
	result.metrics.critical == 0
}

# TEST 4

test_deny_on_critical if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CRITICAL findings")
	contains(msg, "exceed enforced threshold")
}

# TEST 5

test_deny_on_high_exceeds_threshold if {
	f1 := object.union(_high_finding, {"resource": {"name": "r1"}})
	f2 := object.union(_high_finding, {"resource": {"name": "r2"}})
	f3 := object.union(_high_finding, {"resource": {"name": "r3"}})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [f1, f2, f3]})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "HIGH findings")
	contains(msg, "exceed enforced threshold")
}

# TEST 6

test_deny_missing_scanner if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"scanners": {
			"gitleaks": {"status": "PASSED"},
			"checkov": {"status": "PASSED"},
			"trivy": {"status": "NOT_RUN"},
		},
		"findings": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "Scanner trivy")
	contains(msg, "did not run")
}

# TEST 7

test_deny_threshold_injection_attempt if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"quality_gate": {"thresholds": {"critical_max": 999, "high_max": 2}},
		"findings": [_critical_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	result.thresholds.enforced_critical_max == 0
	some msg in result.deny
	contains(msg, "CRITICAL findings")
}

# TEST 8

test_deny_expired_exception if {
	expired := object.union(_valid_exception, {"expires_at": "2020-01-01T00:00:00Z"})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as [expired]

	not result.allow
	some exp_msg in result.deny
	contains(exp_msg, "expires_at is in the past")
	result.metrics.critical == 1
}

# TEST 9

test_duplicate_finding_not_counted if {
	dup := object.union(_critical_finding, {"context": {"deduplication": {"is_duplicate": true}}})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [dup]})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	result.metrics.critical == 0
	result.metrics.failed_input == 0
}

# TEST 10

test_local_mode_advisory if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {
			"environment": "dev",
			"execution": {"mode": "local"},
		},
		"scanners": {
			"gitleaks": {"status": "PASSED"},
			"checkov": {"status": "NOT_RUN"},
			"trivy": {"status": "NOT_RUN"},
		},
		"findings": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.execution_mode == "local"
}

# TEST 11

test_allow_when_trivy_image_scans_removed if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"scanners": {
			"gitleaks": {"status": "PASSED"},
			"checkov": {"status": "PASSED"},
			"trivy": {"status": "PASSED"},
		},
		"findings": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	result.metrics.critical == 0
	result.metrics.high == 0
}

# TESTS 12-17 removed (legacy intent contract flow)

# TEST 18: prod multi-signal role spoofing deny

test_role_spoofing_v2_prod_three_signals_deny if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_web_prod_spoofing],
		"findings": [_high_finding_same_vm],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2")
	contains(msg, "non_waivable")
}

# TEST 19: non-waivable in prod even with valid exception

test_role_spoofing_v2_exception_refused_in_prod if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_web_prod_spoofing],
		"findings": [_high_finding_same_vm],
	})
		with data.cloudsentinel.exceptions.exceptions as [_valid_checkov_exception_same_vm]

	not result.allow
	result.metrics.excepted == 1
	some msg in result.deny
	contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2")
}

# TEST 19b: spoofing signal does not correlate with Checkov finding on another resource

test_role_spoofing_v2_prod_different_resource_not_correlated if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_web_prod_spoofing],
		"findings": [_critical_storage_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CRITICAL findings")
	every msg in result.deny {
		not contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2")
	}
}

# TEST 20: missing cs:role in prod deny

test_cloudinit_role_tag_missing_prod_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_prod_missing_tag],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-ROLE-TAG-MISSING")
}

# TEST 20b: missing cs:role in dev still denied
test_cloudinit_role_tag_missing_dev_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "dev"},
		"resources_analyzed": [_cloudinit_dev_missing_tag],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-ROLE-TAG-MISSING")
}

# TEST 21: remote exec in prod deny

test_cloudinit_remote_exec_prod_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_prod_remote_exec],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-REMOTE-EXEC")
}

# TEST 22: dev environment does not block cloud-init spoofing signal

test_cloudinit_dev_env_not_blocking if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "dev"},
		"resources_analyzed": [_cloudinit_web_dev_spoofing],
		"findings": [_high_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	every msg in result.deny {
		not contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2")
		not contains(msg, "CS-CLOUDINIT-ROLE-TAG-MISSING")
		not contains(msg, "CS-CLOUDINIT-REMOTE-EXEC")
	}
}

# TEST 23: schema version missing deny

test_schema_version_missing_denied if {
	invalid_base := object.remove(_base, {"schema_version"})
	result := data.cloudsentinel.gate.decision with input as object.union(invalid_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_web_prod_spoofing],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-SCHEMA-VERSION-UNSUPPORTED")
}

# TEST 24: schema version accepted

test_schema_version_1_3_0_accepted if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"schema_version": "1.3.0",
		"resources_analyzed": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	every msg in result.deny { not contains(msg, "CS-SCHEMA-VERSION-UNSUPPORTED") }
}

# ==============================================================================
# TESTS 25-32 : Cloud-init extended coverage (added post-audit)
# Covers: staging enforcement, SSH injection, firewall disable, hardcoded creds,
#         new remote exec patterns (eval, process substitution, two-stage download).
# ==============================================================================

# ── Test fixtures for new violation types ──────────────────────────────────

_cloudinit_staging_remote_exec := {
	"resource_address": "azurerm_linux_virtual_machine.worker",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "worker",
	"file": "infra/azure/student-secure/main.tf",
	"line": 10,
	"environment": "staging",
	"role_tag": "worker",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": true,
		"security_bypass_detected": false,
		"db_packages_detected": [],
		"remote_exec_patterns": ["eval_remote_exec"],
		"security_bypass_patterns": [],
	},
	"violations": [
		{
			"rule": "CS-CLOUDINIT-REMOTE-EXEC",
			"severity": "CRITICAL",
			"message": "Remote execution pattern detected: eval_remote_exec",
			"non_waivable_in_prod": true,
			"block": true,
		},
	],
}

_cloudinit_prod_ssh_injection := {
	"resource_address": "azurerm_linux_virtual_machine.bastion",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "bastion",
	"file": "infra/azure/student-secure/main.tf",
	"line": 42,
	"environment": "prod",
	"role_tag": "bastion",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"security_bypass_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
		"security_bypass_patterns": ["ssh_key_injection"],
	},
	"violations": [
		{
			"rule": "CS-CLOUDINIT-SSH-KEY-INJECTION",
			"severity": "CRITICAL",
			"message": "SSH authorized_keys injection detected",
			"non_waivable_in_prod": true,
			"block": true,
		},
	],
}

_cloudinit_prod_firewall_disable := {
	"resource_address": "azurerm_linux_virtual_machine.app",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "app",
	"file": "infra/azure/student-secure/main.tf",
	"line": 78,
	"environment": "prod",
	"role_tag": "app-server",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"security_bypass_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
		"security_bypass_patterns": ["firewall_disable"],
	},
	"violations": [
		{
			"rule": "CS-CLOUDINIT-FIREWALL-DISABLE",
			"severity": "CRITICAL",
			"message": "Firewall disabled via cloud-init",
			"non_waivable_in_prod": true,
			"block": true,
		},
	],
}

_cloudinit_prod_hardcoded_creds := {
	"resource_address": "azurerm_linux_virtual_machine.db",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "db",
	"file": "infra/azure/student-secure/main.tf",
	"line": 100,
	"environment": "prod",
	"role_tag": "db-server",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"security_bypass_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
		"security_bypass_patterns": ["hardcoded_credentials"],
	},
	"violations": [
		{
			"rule": "CS-CLOUDINIT-HARDCODED-CREDENTIALS",
			"severity": "CRITICAL",
			"message": "Hardcoded credentials detected in cloud-init runcmd",
			"non_waivable_in_prod": true,
			"block": true,
		},
	],
}

_cloudinit_staging_ssh_injection := {
	"resource_address": "azurerm_linux_virtual_machine.staging-worker",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "staging-worker",
	"file": "infra/azure/student-secure/staging.tf",
	"line": 15,
	"environment": "staging",
	"role_tag": "worker",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"security_bypass_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
		"security_bypass_patterns": ["ssh_key_injection"],
	},
	"violations": [
		{
			"rule": "CS-CLOUDINIT-SSH-KEY-INJECTION",
			"severity": "CRITICAL",
			"message": "SSH authorized_keys injection detected in staging",
			"non_waivable_in_prod": true,
			"block": true,
		},
	],
}

# TEST 25: staging remote exec is NOW blocked (regression guard for audit fix)
# Previously only prod was enforced — this test ensures staging enforcement.

test_cloudinit_staging_remote_exec_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "staging"},
		"resources_analyzed": [_cloudinit_staging_remote_exec],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-REMOTE-EXEC")
	contains(msg, "staging")
}

# TEST 26: SSH key injection in prod is denied

test_cloudinit_ssh_key_injection_prod_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_prod_ssh_injection],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-SSH-KEY-INJECTION")
}

# TEST 27: SSH key injection in staging is denied

test_cloudinit_ssh_key_injection_staging_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "staging"},
		"resources_analyzed": [_cloudinit_staging_ssh_injection],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-SSH-KEY-INJECTION")
}

# TEST 28: Firewall disable in prod is denied

test_cloudinit_firewall_disable_prod_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_prod_firewall_disable],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-FIREWALL-DISABLE")
}

# TEST 29: Hardcoded credentials in prod are denied

test_cloudinit_hardcoded_credentials_prod_denied if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [_cloudinit_prod_hardcoded_creds],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-CLOUDINIT-HARDCODED-CREDENTIALS")
}

# TEST 30: Dev environment — SSH injection is advisory, not blocking
# (block=false set by scanner for dev; OPA does not fire since resource_is_enforced requires prod|staging)

_cloudinit_dev_ssh_injection := {
	"resource_address": "azurerm_linux_virtual_machine.dev-vm",
	"resource_type": "azurerm_linux_virtual_machine",
	"resource_name": "dev-vm",
	"file": "infra/azure/student-secure/dev.tf",
	"line": 5,
	"environment": "dev",
	"role_tag": "developer",
	"cloud_init_field": "custom_data",
	"signals": {
		"role_tag_missing": false,
		"role_spoofing_candidate": false,
		"remote_exec_detected": false,
		"security_bypass_detected": true,
		"db_packages_detected": [],
		"remote_exec_patterns": [],
		"security_bypass_patterns": ["ssh_key_injection"],
	},
	"violations": [],
}

test_cloudinit_dev_ssh_injection_not_blocking if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "dev"},
		"resources_analyzed": [_cloudinit_dev_ssh_injection],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	every msg in result.deny {
		not contains(msg, "CS-CLOUDINIT-SSH-KEY-INJECTION")
		not contains(msg, "CS-CLOUDINIT-FIREWALL-DISABLE")
		not contains(msg, "CS-CLOUDINIT-HARDCODED-CREDENTIALS")
	}
}

# TEST 31: non_waivable_violations set includes all new cloud-init rules

test_non_waivable_violations_complete if {
	nwv := data.cloudsentinel.gate.non_waivable_violations
	"CS-CLOUDINIT-REMOTE-EXEC" in nwv
	"CS-CLOUDINIT-SSH-KEY-INJECTION" in nwv
	"CS-CLOUDINIT-FIREWALL-DISABLE" in nwv
	"CS-CLOUDINIT-HARDCODED-CREDENTIALS" in nwv
	"CS-MULTI-SIGNAL-ROLE-SPOOFING-V2" in nwv
	"CS-CLOUDINIT-ROLE-TAG-MISSING" in nwv
	"CS-SCHEMA-VERSION-UNSUPPORTED" in nwv
}

# TEST 32: Multiple violations on same resource — all are independently denied

test_cloudinit_multiple_bypass_violations_all_denied if {
	multi_violation_resource := {
		"resource_address": "azurerm_linux_virtual_machine.compromised",
		"resource_type": "azurerm_linux_virtual_machine",
		"resource_name": "compromised",
		"file": "infra/main.tf",
		"line": 1,
		"environment": "prod",
		"role_tag": "worker",
		"cloud_init_field": "custom_data",
		"signals": {
			"role_tag_missing": false,
			"role_spoofing_candidate": false,
			"remote_exec_detected": true,
			"security_bypass_detected": true,
			"db_packages_detected": [],
			"remote_exec_patterns": ["curl_pipe_shell"],
			"security_bypass_patterns": ["ssh_key_injection", "firewall_disable"],
		},
		"violations": [],
	}
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"metadata": {"environment": "prod"},
		"resources_analyzed": [multi_violation_resource],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	# All three deny rules must fire independently
	count([msg | some msg in result.deny; contains(msg, "CS-CLOUDINIT-REMOTE-EXEC")]) >= 1
	count([msg | some msg in result.deny; contains(msg, "CS-CLOUDINIT-SSH-KEY-INJECTION")]) >= 1
	count([msg | some msg in result.deny; contains(msg, "CS-CLOUDINIT-FIREWALL-DISABLE")]) >= 1
}

# TEST 33: MEDIUM finding produces a warn signal — pipeline still allowed

_medium_finding := {
	"status": "FAILED",
	"source": {"tool": "checkov", "id": "CKV_AZ_MEDIUM_001"},
	"resource": {"name": "azurerm_storage_account.medium", "path": "azurerm_storage_account.medium", "location": {"file": "azurerm_storage_account.medium", "start_line": 0}},
	"severity": {"level": "MEDIUM"},
}

test_medium_finding_warns_not_blocks if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"findings": [_medium_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	count(result.warn) == 1
	result.metrics.warn_count == 1
	some msg in result.warn
	contains(msg, "MEDIUM findings (1)")
}

# TEST 34: LOW finding produces a warn signal — pipeline still allowed

_low_finding := {
	"status": "FAILED",
	"source": {"tool": "trivy", "id": "CVE-LOW-001"},
	"resource": {"name": "pkg-low", "path": "pkg-low", "location": {"file": "pkg-low", "start_line": 0}},
	"severity": {"level": "LOW"},
}

test_low_finding_warns_not_blocks if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"findings": [_low_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
	count(result.warn) == 1
	result.metrics.warn_count == 1
	some msg in result.warn
	contains(msg, "LOW findings (1)")
}
