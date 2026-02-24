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

test_allow_when_thresholds_respected if {
  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        }
      ]
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
  count(result.deny) == 1
  contains(result.deny[0], "CRITICAL findings")
}

test_apply_exception_in_dev if {
  exceptions := [{
    "id": "EXC-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "/infra/azure/dev/state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Temporary unblock while remediation is in progress",
    "ticket": "SEC-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "metadata": {"environment": "dev"},
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  result.allow
  result.metrics.excepted == 1
  result.exceptions.applied_ids[0] == "EXC-1"
}

test_allow_when_exception_resource_name_matches if {
  exceptions := [{
    "id": "EXC-NAME-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_name": "azurerm_storage_account.insecure",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Resource name exception",
    "ticket": "SEC-NAME-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {
            "name": "azurerm_storage_account.insecure",
            "path": "/infra/azure/dev/state_storage.tf"
          },
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  result.allow
  result.metrics.excepted == 1
  result.exceptions.applied_ids[0] == "EXC-NAME-1"
}

test_apply_exception_with_rule_alias_and_path_normalization if {
  exceptions := [{
    "id": "EXC-ALIAS-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_999",
    "rule_id_aliases": ["CKV2_CS_AZ_001"],
    "resource_path": "./infra\\azure/dev/./state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Alias-based matching for scanner drift",
    "ticket": "SEC-ALIAS-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  result.allow
  result.metrics.excepted == 1
  result.exceptions.applied_ids[0] == "EXC-ALIAS-1"
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

test_deny_invalid_prod_critical_exception if {
  exceptions := [{
    "id": "EXC-PROD-CRIT",
    "enabled": true,
    "tool": "trivy",
    "rule_id": "CVE-1",
    "resource_path": "/image/alpine",
    "environments": ["prod"],
    "max_severity": "CRITICAL",
    "reason": "Emergency exception request",
    "ticket": "SEC-2",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "metadata": {"environment": "prod"},
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  not result.allow
  contains(result.deny[0], "invalid for prod")
}

test_deny_when_enabled_exception_is_malformed if {
  exceptions := [{
    "id": "EXC-BAD-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "/infra/azure/dev/state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Invalid because requested_by is missing",
    "ticket": "SEC-3",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  not result.allow
  result.exceptions.invalid_enabled_ids[0] == "EXC-BAD-1"
  contains(result.deny[0], "malformed")
}

test_deny_when_exception_aliases_are_invalid if {
  exceptions := [{
    "id": "EXC-BAD-ALIAS",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "rule_id_aliases": ["CKV2_CS_AZ_001", 123],
    "resource_path": "/infra/azure/dev/state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Invalid alias payload",
    "ticket": "SEC-ALIAS-2",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  not result.allow
  result.exceptions.invalid_enabled_ids[0] == "EXC-BAD-ALIAS"
  contains(result.deny[0], "malformed")
}

test_metrics_excepted_counts_findings_not_exception_ids if {
  exceptions := [{
    "id": "EXC-MULTI-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "/infra/azure/dev/state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Single exception for repeated finding instances",
    "ticket": "SEC-MULTI-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 2, "FAILED": 2}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        },
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  result.allow
  result.metrics.excepted == 2
  result.metrics.excepted_exception_ids == 1
  result.exceptions.applied_count == 1
}

test_deny_when_threshold_config_is_invalid if {
  result := decision
    with input as object.union(base_input, {
      "quality_gate": {
        "thresholds": {
          "critical_max": 0,
          "high_max": "invalid"
        }
      },
      "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
      "findings": []
    })
    with data.cloudsentinel.exceptions.exceptions as []

  not result.allow
  contains(result.deny[0], "Invalid threshold configuration")
}

# --- Test: expired exception must NOT suppress findings ---
# An exception past its expires_at must be treated as non-existent.
# The finding must remain effective and trigger a deny if it exceeds the threshold.
test_deny_when_exception_is_expired if {
  exceptions := [{
    "id": "EXC-EXPIRED-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "/infra/azure/dev/state_storage.tf",
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Grace period — remediation in progress",
    "ticket": "SEC-EXP-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2020-01-01T00:00:00Z",
    "expires_at":   "2020-06-01T00:00:00Z"
  }]

  # Override high_max to 0 so the HIGH finding must be denied when not excepted
  result := decision
    with input as object.union(base_input, {
      "quality_gate": {"thresholds": {"critical_max": 0, "high_max": 0}},
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  # Expired exception must NOT apply → finding stays effective → deny
  not result.allow
  result.metrics.excepted == 0
  result.exceptions.applied_count == 0
  contains(result.deny[0], "HIGH findings")
}

# --- Test: path suffix matching ---
# An exception with only the filename (no full path) must match a finding
# whose resource path is the full path ending with that filename.
# Validates the suffix_segments_match logic in the policy.
test_allow_when_exception_path_suffix_matches if {
  exceptions := [{
    "id": "EXC-SUFFIX-1",
    "enabled": true,
    "tool": "checkov",
    "rule_id": "CKV2_CS_AZ_001",
    "resource_path": "state_storage.tf",   # short suffix — no directory prefix
    "environments": ["dev"],
    "max_severity": "HIGH",
    "reason": "Suffix path exception for environment-agnostic resource matching",
    "ticket": "SEC-SUFFIX-1",
    "requested_by": "dev@example.com",
    "approved_by": "security@example.com",
    "commit_hash": "abc1234",
    "request_date": "2026-02-21T08:00:00Z",
    "expires_at":   "2099-01-01T00:00:00Z"
  }]

  result := decision
    with input as object.union(base_input, {
      "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
      "findings": [
        {
          "status": "FAILED",
          "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
          "resource": {"path": "/infra/azure/dev/state_storage.tf"},  # full path
          "severity": {"level": "HIGH"}
        }
      ]
    })
    with data.cloudsentinel.exceptions.exceptions as exceptions

  result.allow
  result.metrics.excepted == 1
  result.exceptions.applied_ids[0] == "EXC-SUFFIX-1"
}
