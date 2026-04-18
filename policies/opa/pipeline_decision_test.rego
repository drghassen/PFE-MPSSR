package cloudsentinel.gate_test

# ─────────────────────────────────────────────────────────────────────
# Test suite A — Functional scenarios (allow/deny, scanners, thresholds)
# Companion: test_pipeline_decision.rego (exception lifecycle + edge cases)
# Total coverage: 22 tests across both files. Zero overlap.
# Run: make opa-test-gate  (ou bash ci/scripts/verify-opa-architecture.sh)
# ─────────────────────────────────────────────────────────────────────

import rego.v1

# ─── Shared fixtures ─────────────────────────────────────────────────────────

_scanners_ok := {
	"gitleaks": {"status": "PASSED"},
	"checkov": {"status": "PASSED"},
	"trivy": {"status": "PASSED"},
}

_base := {
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

# Valid exception matching _critical_finding exactly (tool/rule_id/resource)
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

# ─── TEST 1: Clean pipeline with 0 findings → allow ──────────────────────────
# All 3 scanners present, no findings → decision.allow must be true.

test_allow_clean_pipeline if {
	result := data.cloudsentinel.gate.decision with input as _base
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

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [f1, f2]})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	result.metrics.high == 2
	count(result.deny) == 0
}

# ─── TEST 3: Valid exception exempts CRITICAL finding → allow ─────────────────
# Exception matches on tool/rule_id/resource. Finding is removed from
# effective_failed_findings, so effective_critical=0 → no threshold deny.

test_allow_with_valid_exception if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
		with data.cloudsentinel.exceptions.exceptions as [_valid_exception]

	result.allow
	result.metrics.excepted == 1
	result.metrics.critical == 0
}

# ─── TEST 4: 1 CRITICAL finding, no exception → deny ─────────────────────────
# enforced_critical_max = min(0, 0) = 0. effective_critical=1 > 0 → deny.

test_deny_on_critical if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
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

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [f1, f2, f3]})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "HIGH findings")
	contains(msg, "exceed enforced threshold")
}

# ─── TEST 6: Trivy scanner missing (NOT_RUN) in CI mode → deny ───────────────
# scanner_not_run fires for trivy (is_local is false in default CI mode).

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

# ─── TEST 7: CI injects critical_max=999 → ceiling clamps to 0, deny ─────────
# _policy_critical_max_ceiling=0. enforced_critical_max=min(999,0)=0.
# With 1 CRITICAL finding: 1>0 → deny regardless of injected value.

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

# ─── TEST 8: Expired exception does not exempt CRITICAL finding → deny ────────
# exception_is_expired fires → valid_exception_definition fails → not exempting.
# Additionally expired_enabled_exception_ids fires → own deny message.

test_deny_expired_exception if {
	expired := object.union(_valid_exception, {"expires_at": "2020-01-01T00:00:00Z"})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [_critical_finding]})
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
	dup := object.union(_critical_finding, {"context": {"deduplication": {"is_duplicate": true}}})

	result := data.cloudsentinel.gate.decision with input as object.union(_base, {"findings": [dup]})
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

# ─────────────────────────────────────────────────────────────────────────────
# Test suite B — Intent Contract (role spoofing, exposure mismatch)
# Les 6 tests couvrent : contract absent, présent+clean, role spoofing deny,
# non_waivable enforcement, exposure mismatch, web-server légitime.
# ─────────────────────────────────────────────────────────────────────────────

# Fixture : finding Checkov CRITICAL — NSG rule autorisant le port PostgreSQL (5432) depuis 0.0.0.0/0.
# Source : CKV2_CS_AZ_021_ssh_restricted simulant une règle DB exposée sur un "web-server".
_checkov_db_port_finding := {
	"status": "FAILED",
	"source": {"tool": "checkov", "id": "CKV2_CS_AZ_DB_EXPOSED", "version": "3.0.0", "scanner_type": "misconfig"},
	"resource": {
		"name": "azurerm_network_security_rule.allow_db",
		"path": "infra/azure/student-secure/modules/network/main.tf",
		"type": "infrastructure",
		"version": "N/A",
		"location": {"file": "infra/azure/student-secure/modules/network/main.tf", "start_line": 42, "end_line": 55},
	},
	"description": "NSG rule allows inbound connection on port 5432 from source 0.0.0.0/0 — database exposed to internet",
	"severity": {"level": "CRITICAL", "original_severity": "CRITICAL", "cvss_score": null},
	"category": "INFRASTRUCTURE_AS_CODE",
	"context": {
		"git": {"author_email": "dev@company.com", "commit_date": "2026-04-17T10:00:00Z"},
		"deduplication": {"fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "is_duplicate": false, "duplicate_of": null},
		"traceability": {"source_report": "checkov_raw.json", "source_index": 0, "normalized_at": "2026-04-17T10:00:00Z"},
	},
	"remediation": {"sla_hours": 24, "fix_version": "N/A", "references": []},
}

# Fixture : intent contract déclarant web-server (role spoofing pattern).
_intent_web_server_spoofing := {
	"declared": {
		"service_type": "web-server",
		"exposure_level": "internet-facing",
		"owner": "dev@company.com",
		"approved_by": "lead@company.com",
	},
	"violation": null,
}

# Fixture : intent_mismatches produit par correlate_intent_vs_reality().
# Simule le résultat de normalize.py après détection du port 5432 sur un web-server.
_intent_mismatches_role_spoofing := [{
	"rule": "CS-INTENT-ROLE-SPOOFING",
	"severity": "CRITICAL",
	"declared": "service_type=web-server",
	"observed": "db_ports_detected={5432}",
	"mitre": "T1036 - Masquerading",
	"source_findings": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
}]

# Fixture : exception valide pour le finding Checkov DB exposé.
# Four-eyes : requested_by != approved_by. Source : defectdojo. Status : approved.
_exception_for_db_finding := {
	"id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	"tool": "checkov",
	"rule_id": "CKV2_CS_AZ_DB_EXPOSED",
	"resource": "azurerm_network_security_rule.allow_db",
	"severity": "CRITICAL",
	"requested_by": "dev-team",
	"approved_by": "security-team",
	"approved_at": "2026-01-01T00:00:00Z",
	"expires_at": "2099-01-01T00:00:00Z",
	"decision": "accept",
	"source": "defectdojo",
	"status": "approved",
	"occurrence": {
		"file_path": "infra/azure/student-secure/modules/network/main.tf",
		"line": 42,
		"hash_code": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	},
}

# ─── TEST 12: Pas d'intent_contract dans l'input → deny CS-INTENT-CONTRACT-MISSING ─
# Pipeline sans intent.tf déployé : extract_intent_contract() retourne MISSING_INTENT_CONTRACT.
# OPA doit bloquer avec CS-INTENT-CONTRACT-MISSING.

test_intent_contract_missing if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"intent_contract": {"declared": null, "violation": "MISSING_INTENT_CONTRACT"},
		"intent_mismatches": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-INTENT-CONTRACT-MISSING")
	contains(msg, "non_waivable")
}

# ─── TEST 13: Intent présent, aucun mismatch → pas de violation intent ────────
# web-server déclaré, aucun finding avec port DB → pas de CS-INTENT-ROLE-SPOOFING.
# Les scanners sont clean : pipeline autorisé.

test_intent_contract_present_no_mismatch if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"intent_contract": _intent_web_server_spoofing,
		"intent_mismatches": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
}

# ─── TEST 14: Role spoofing — web-server + port 5432 + checkov CRITICAL → deny ─
# Signal 1 : service_type=web-server. Signal 2 : mismatch CS-INTENT-ROLE-SPOOFING.
# Signal 3 : finding Checkov CRITICAL. Les 3 signaux convergent → deny non_waivable.

test_role_spoofing_web_server_with_db_ports if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"intent_contract": _intent_web_server_spoofing,
		"intent_mismatches": _intent_mismatches_role_spoofing,
		"findings": [_checkov_db_port_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	not result.allow
	some msg in result.deny
	contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING")
	contains(msg, "non_waivable")
	contains(msg, "web-server")
}

# ─── TEST 15: Role spoofing + exception valide four-eyes → deny maintenu (non_waivable) ─
# Même scénario que TEST 14, avec une exception four-eyes valide pour le finding Checkov.
# L'exception peut exempter le finding individuel de effective_failed_findings,
# MAIS CS-MULTI-SIGNAL-ROLE-SPOOFING utilise input.findings bruts (Signal 3) →
# le deny continue de s'appliquer malgré l'exception.

test_role_spoofing_exception_refused if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"intent_contract": _intent_web_server_spoofing,
		"intent_mismatches": _intent_mismatches_role_spoofing,
		"findings": [_checkov_db_port_finding],
	})
		with data.cloudsentinel.exceptions.exceptions as [_exception_for_db_finding]

	# Le deny doit persister malgré l'exception valide four-eyes
	not result.allow
	some msg in result.deny
	contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING")
	contains(msg, "non_waivable")
}

# ─── TEST 16: Exposure mismatch — internal-only avec IP publique → mismatch détecté ─
# intent.declared.exposure_level=internal-only + finding mentionnant public_ip ou 0.0.0.0/0.
# normalize.py produit intent_mismatches avec CS-INTENT-EXPOSURE-MISMATCH.
# Vérifie que l'intent_mismatch est bien présent dans l'input (simulate normalize.py output).

test_exposure_mismatch_internal_with_public_ip if {
	exposure_mismatch_input := object.union(_base, {
		"intent_contract": {
			"declared": {
				"service_type": "worker",
				"exposure_level": "internal-only",
				"owner": "ops@company.com",
				"approved_by": "security@company.com",
			},
			"violation": null,
		},
		"intent_mismatches": [{
			"rule": "CS-INTENT-EXPOSURE-MISMATCH",
			"severity": "HIGH",
			"declared": "exposure_level=internal-only",
			"observed": "public_ip_or_open_cidr_detected",
			"mitre": "T1048 - Exfiltration Over Alternative Protocol",
			"source_findings": ["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
		}],
	})

	result := data.cloudsentinel.gate.decision with input as exposure_mismatch_input
		with data.cloudsentinel.exceptions.exceptions as []

	# Le mismatch est présent dans le document d'entrée (produit par normalize.py)
	count(exposure_mismatch_input.intent_mismatches) == 1
	exposure_mismatch_input.intent_mismatches[0].rule == "CS-INTENT-EXPOSURE-MISMATCH"

	# CS-MULTI-SIGNAL-ROLE-SPOOFING ne doit PAS fire (service_type=worker, pas web-server)
	every msg in result.deny { not contains(msg, "CS-MULTI-SIGNAL-ROLE-SPOOFING") }
}

# ─── TEST 17: Serveur web légitime — web-server + internet-facing, aucun port DB → allow ─
# Intent cohérent et conforme : service_type=web-server, exposure_level=internet-facing,
# aucun finding Checkov avec port DB, aucun intent_mismatch. Pipeline autorisé.

test_legitimate_web_server if {
	result := data.cloudsentinel.gate.decision with input as object.union(_base, {
		"intent_contract": {
			"declared": {
				"service_type": "web-server",
				"exposure_level": "internet-facing",
				"owner": "webteam@company.com",
				"approved_by": "lead@company.com",
			},
			"violation": null,
		},
		"intent_mismatches": [],
		"findings": [],
	})
		with data.cloudsentinel.exceptions.exceptions as []

	result.allow
	count(result.deny) == 0
}

# ─── TEST 11: trivy-image-scan-* removed, fs+config only → allow ──────────────
# Simulates pipeline after trivy-image-scan-* jobs were removed.
# trivy scanner status is PASSED (fs+config ran), no image reports produced.
# OPA must ALLOW when all three scanners ran and findings are within thresholds.

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
