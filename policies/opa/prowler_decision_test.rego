package cloudsentinel.shiftright.prowler

import rego.v1

base_input := {
  "environment": "production",
  "repo": "group/project",
  "branch": "main",
  "meta": {
    "mode": "ENFORCING",
    "allow_degraded": false,
    "allow_legacy_exceptions": true,
  },
}

test_empty_input_returns_empty_violations if {
  result := violations with input as base_input
  result == []
}

test_high_finding_is_actionable_ticket_and_notify if {
  result := violations with input as object.union(base_input, {
    "findings": [
      {
        "check_id": "storage_default_network_access_rule_is_denied",
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "resource_type": "microsoft.storage/storageaccounts",
        "severity": "HIGH",
        "status_code": "FAIL",
        "status_detail": "Default action is Allow",
      }
    ],
  })

  count(result) == 1
  result[0].action_required == "ticket_and_notify"
  result[0].requires_remediation == false
  result[0].severity == "HIGH"
  result[0].manual_review_required == false
}

test_critical_finding_without_capability_is_manual_review if {
  result := violations with input as object.union(base_input, {
    "findings": [
      {
        "check_id": "some_unmapped_critical_check",
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "resource_type": "microsoft.storage/storageaccounts",
        "severity": "CRITICAL",
        "status_code": "FAIL",
      }
    ],
  })

  count(result) == 1
  result[0].action_required == "manual_review"
  result[0].requires_remediation == false
  result[0].manual_review_required == true
  result[0].custodian_policy == null
}

test_critical_finding_with_capability_is_runtime_remediation if {
  in_data := object.union(base_input, {
    "capabilities": {
      "prowler:storage_default_network_access_rule_is_denied": {
        "remediation_supported": true,
        "custodian_policy": "deny-public-storage",
        "verification_script": "verify_storage_private.sh",
      }
    },
    "findings": [
      {
        "check_id": "storage_default_network_access_rule_is_denied",
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "resource_type": "microsoft.storage/storageaccounts",
        "severity": "CRITICAL",
        "status_code": "FAIL",
      }
    ],
  })

  result := violations with input as in_data
  count(result) == 1
  result[0].action_required == "runtime_remediation"
  result[0].requires_remediation == true
  result[0].manual_review_required == false
  result[0].custodian_policy == "deny-public-storage"
  result[0].verification_script == "verify_storage_private.sh"
}

test_missing_required_fields_falls_back_to_manual_review if {
  result := violations with input as object.union(base_input, {
    "findings": [
      {
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "severity": "HIGH",
      }
    ],
  })

  count(result) == 1
  result[0].action_required == "manual_review"
  result[0].severity == "LOW"
}

test_exception_removes_effective_violation if {
  in_data := object.union(base_input, {
    "findings": [
      {
        "check_id": "storage_default_network_access_rule_is_denied",
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "resource_type": "microsoft.storage/storageaccounts",
        "severity": "HIGH",
        "status_code": "FAIL",
      }
    ],
  })

  result := effective_violations
    with input as in_data
    with data.cloudsentinel.prowler_exceptions as {
      "exceptions": [
        {
          "source": "defectdojo",
          "status": "approved",
          "check_id": "storage_default_network_access_rule_is_denied",
          "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
          "resource_type": "microsoft.storage/storageaccounts",
          "requested_by": "alice",
          "approved_by": "bob",
          "approved_at": "2026-01-01T00:00:00Z",
          "environments": ["production"],
        }
      ],
    }

  result == []
}

test_exception_with_missing_resource_type_is_rejected if {
  in_data := object.union(base_input, {
    "findings": [
      {
        "check_id": "storage_default_network_access_rule_is_denied",
        "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        "resource_type": "microsoft.storage/storageaccounts",
        "severity": "HIGH",
        "status_code": "FAIL",
      }
    ],
  })

  result := effective_violations
    with input as in_data
    with data.cloudsentinel.prowler_exceptions as {
      "exceptions": [
        {
          "source": "defectdojo",
          "status": "approved",
          "check_id": "storage_default_network_access_rule_is_denied",
          "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
          # resource_type intentionally absent — exception must be rejected
          "requested_by": "alice",
          "approved_by": "bob",
          "approved_at": "2026-01-01T00:00:00Z",
          "environments": ["production"],
        }
      ],
    }

  count(result) == 1
}

test_deny_when_input_missing_environment if {
  in_data := {
    "repo": "group/project",
    "branch": "main",
    "meta": {
      "mode": "ENFORCING",
      "allow_degraded": false,
      "allow_legacy_exceptions": true,
    },
    "findings": [],
  }
  result := deny with input as in_data
  count(result) > 0
}
