package cloudsentinel.gate

import rego.v1

base_input := {
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
    "path": "/infra/azure/student-secure/modules/storage/main.tf"
  },
  "severity": {"level": "HIGH"}
}

base_v2_exception := {
  "exception_id": "11111111-1111-4111-8111-111111111111",
  "schema_version": "2.0.0",
  "enabled": true,
  "status": "APPROVED",
  "scanner": "checkov",
  "rule_id": "CKV2_CS_AZ_001",
  "resource_id": "azurerm_storage_account.insecure",
  "fingerprint": "fp-abc-123",
  "repo": "unknown",
  "branch_scope": "*",
  "scope_type": "repo",
  "severity": "HIGH",
  "break_glass": false,
  "approved_by_role": "APPSEC_L3",
  "requested_by": "dev@example.com",
  "approved_by": "security@example.com",
  "justification": "Temporary exception with compensating controls",
  "created_at": "2026-02-21T08:00:00Z",
  "approved_at": "2026-02-21T09:00:00Z"
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
  result.exceptions.applied_ids[0] == "11111111-1111-4111-8111-111111111111"
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
  bad := object.union(base_v2_exception, {"status": "PENDING"})
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [bad]

  not result.allow
  contains(concat(" ", result.deny), "status must be APPROVED")
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

test_deny_when_exception_missing_approved_at if {
  bad := object.remove(base_v2_exception, ["approved_at"])
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [bad]

  not result.allow
  contains(concat(" ", result.deny), "approved_at is required")
}

test_deny_when_exception_is_expired if {
  expired := object.union(base_v2_exception, {
    "created_at": "2019-01-01T00:00:00Z",
    "approved_at": "2019-01-02T00:00:00Z",
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

test_deny_legacy_exception_schema if {
  legacy := {
    "id": "EXC-LEGACY-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "/infra/azure/student-secure/modules/storage/main.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "legacy format",
    "ticket": "SEC-LEGACY",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as [legacy]

  not result.allow
  contains(concat(" ", result.deny), "legacy schema which is no longer accepted")
}
