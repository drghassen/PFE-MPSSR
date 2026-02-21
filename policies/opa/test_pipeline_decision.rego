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
    "ticket": "SEC-1",
    "approved_by": "security@example.com",
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

test_deny_invalid_prod_critical_exception if {
  exceptions := [{
    "id": "EXC-PROD-CRIT",
    "enabled": true,
    "tool": "trivy",
    "rule_id": "CVE-1",
    "resource_path": "/image/alpine",
    "environments": ["prod"],
    "max_severity": "CRITICAL",
    "ticket": "SEC-2",
    "approved_by": "security@example.com",
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
