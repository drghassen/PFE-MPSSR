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

test_high_finding_is_actionable_schedule_review if {
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
  result[0].action_required == "schedule_review"
  result[0].severity == "HIGH"
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
