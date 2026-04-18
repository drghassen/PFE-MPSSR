package cloudsentinel.gate

# ─────────────────────────────────────────────────────────────────────
# Test suite B — Exception lifecycle + threshold ceiling edge cases
# Companion: pipeline_decision_test.rego (functional allow/deny scenarios)
# Total coverage: 22 tests across both files. Zero overlap.
# Run: make opa-test-gate  (ou bash ci/scripts/verify-opa-architecture.sh)
# ─────────────────────────────────────────────────────────────────────

import rego.v1

base_input := {
  "schema_version": "1.2.1",
  "metadata": {
    "environment": "dev"
  },
  "quality_gate": {
    "thresholds": {
      "critical_max": 0,
      "high_max": 2
    }
  },
  "scanners": {
    "gitleaks": {"status": "PASSED"},
    "checkov": {"status": "PASSED"},
    "trivy": {"status": "PASSED"}
  }
}

base_failed_finding := {
  "status": "FAILED",
  "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
  "resource": {
    "name": "azurerm_storage_account.insecure",
    "path": "/infra/azure/student-secure/modules/storage/main.tf",
    "location": {
      "file": "/infra/azure/student-secure/modules/storage/main.tf",
      "start_line": 1
    }
  },
  "severity": {"level": "HIGH"}
}

base_v2_exception := {
  "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "tool": "checkov",
  "rule_id": "CKV2_CS_AZ_001",
  "resource": "azurerm_storage_account.insecure",
  "severity": "HIGH",
  "requested_by": "dev-team",
  "approved_by": "security-team",
  "approved_at": "2026-01-01T00:00:00Z",
  "expires_at": "2099-01-01T00:00:00Z",
  "decision": "accept",
  "source": "defectdojo",
  "status": "approved",
  "occurrence": {
    "file_path": "infra/azure/student-secure/modules/storage/main.tf",
    "line": 1,
    "hash_code": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}

test_allow_when_thresholds_respected if {
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [base_failed_finding]
    })
    with data.cloudsentinel.exceptions.exceptions as []

  result.allow
  count(result.deny) == 0
}

test_deny_on_critical_over_threshold if {
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 1, "HIGH": 0, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "trivy", "id": "CVE-1"},
          "resource": {"path": "/image/alpine"},
          "severity": {"level": "CRITICAL"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as []

  not result.allow
  contains(result.deny[0], "CRITICAL findings")
}

test_allow_when_v2_exception_is_valid if {
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [base_failed_finding]
    })
    with data.cloudsentinel.exceptions.exceptions as [base_v2_exception]

  result.allow
  result.metrics.excepted == 1
  result.exceptions.applied_ids[0] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

test_deny_when_scanner_not_run if {
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "scanners": {
        "gitleaks": {"status": "PASSED"},
        "checkov": {"status": "NOT_RUN"},
        "trivy": {"status": "PASSED"}
      },
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as []

  not result.allow
  contains(result.deny[0], "Scanner checkov")
}

test_allow_when_scanners_not_run_in_local_mode if {
  result := decision
    with input as object.union(base_input, {
      "metadata": {
        "environment": "dev",
        "execution": {"mode": "local"}
      },
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "scanners": {
        "gitleaks": {"status": "PASSED"},
        "checkov": {"status": "NOT_RUN"},
        "trivy": {"status": "NOT_RUN"}
      },
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as []

  result.allow
  count(result.deny) == 0
}

test_deny_when_exception_status_not_approved if {
  bad := object.union(base_v2_exception, {"status": "pending"})
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [bad]

  not result.allow
  contains(concat(" ", result.deny), "status must be approved")
}

test_deny_when_exception_missing_approved_by if {
  bad := object.remove(base_v2_exception, ["approved_by"])
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [bad]

  not result.allow
  contains(concat(" ", result.deny), "approved_by is required")
}

test_deny_when_exception_is_expired if {
  expired := object.union(base_v2_exception, {
    "expires_at": "2020-01-01T00:00:00Z"
  })
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [expired]

  not result.allow
  contains(concat(" ", result.deny), "expires_at is in the past")
}

test_deny_when_exception_schema_is_malformed if {
  malformed := object.union(base_v2_exception, {
    "id": "short"
  })

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [malformed]

  not result.allow
  contains(concat(" ", result.deny), "malformed")
}

# Test : une tentative d'override CI (critical_max=99) doit toujours deny
# si un finding CRITICAL est présent — le plafond policy à 0 s'applique.
test_threshold_ceiling_blocks_ci_override_on_critical if {
  result := decision
    with input as object.union(base_input, {
      "quality_gate": {"thresholds": {"critical_max": 99, "high_max": 100}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "trivy", "id": "CVE-CRITICAL-1"},
          "resource": {"path": "/image/scan-tools"},
          "severity": {"level": "CRITICAL"},
        }
      ],
    })
    with data.cloudsentinel.exceptions.exceptions as []

  not result.allow
  contains(result.deny[0], "CRITICAL findings")
  result.thresholds.enforced_critical_max == 0
}

# Test : high_max passé à 100 en CI doit être capé au plafond policy (5).
test_threshold_ceiling_caps_high_max_to_policy_floor if {
  result := decision
    with input as object.union(base_input, {
      "quality_gate": {"thresholds": {"critical_max": 0, "high_max": 100}},
      "findings": [],
    })
    with data.cloudsentinel.exceptions.exceptions as []

  result.allow
  result.thresholds.enforced_high_max == 5
}
