package cloudsentinel.shiftright.drift

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

test_l0_output_type if {
  result := evaluate_drift({
    "address": "output.vm_name",
    "type": "output",
    "provider_name": "unknown",
    "changed_paths": ["$"],
  })
  result.severity == "INFO"
  result.remediation_level == "L0"
}

test_l1_low_no_remediation if {
  result := evaluate_drift({
    "address": "azurerm_log_analytics_workspace.law",
    "type": "azurerm_log_analytics_workspace",
    "provider_name": "registry.terraform.io/hashicorp/azurerm",
    "changed_paths": ["retention_in_days"],
  })
  result.remediation_level == "L1"
}

test_l2_medium_no_custodian if {
  result := evaluate_drift({
    "address": "azurerm_monitor_diagnostic_setting.diag",
    "type": "azurerm_monitor_diagnostic_setting",
    "provider_name": "registry.terraform.io/hashicorp/azurerm",
    "changed_paths": ["enabled_log"],
  })
  result.remediation_level == "L2"
}

test_l2_high_no_custodian if {
  result := evaluate_drift({
    "address": "azurerm_storage_account.sa",
    "type": "azurerm_storage_account",
    "provider_name": "registry.terraform.io/hashicorp/azurerm",
    "changed_paths": ["min_tls_version"],
  })
  result.remediation_level == "L2"
}

test_l2_critical_no_custodian if {
  result := evaluate_drift({
    "address": "azurerm_network_security_group.nsg",
    "type": "azurerm_network_security_group",
    "provider_name": "registry.terraform.io/hashicorp/azurerm",
    "changed_paths": ["security_rule"],
  })
  result.severity == "CRITICAL"
  result.requires_remediation == false
  result.remediation_level == "L2"
}

test_l3_critical_with_custodian if {
  result := evaluate_drift({
    "address": "azurerm_network_security_group.nsg",
    "type": "azurerm_network_security_group",
    "provider_name": "registry.terraform.io/hashicorp/azurerm",
    "changed_paths": ["security_rule"],
  }) with input as object.union(base_input, {
    "capabilities": {
      "enforce-nsg-no-open-inbound": {
        "remediation_supported": true,
        "verification_script": "verify_nsg_no_open_inbound.sh",
      }
    }
  })
  result.requires_remediation == true
  result.custodian_policy == "enforce-nsg-no-open-inbound"
  result.remediation_level == "L3"
}

test_block_reason_deny if {
  reason := block_reason with input as object.union(base_input, {
    "meta": {"mode": "DEGRADED", "allow_degraded": false},
    "findings": [],
  })
  reason == "deny"
}

test_block_reason_l3 if {
  reason := block_reason with input as object.union(base_input, {
    "capabilities": {
      "enforce-nsg-no-open-inbound": {
        "remediation_supported": true,
        "verification_script": "verify_nsg_no_open_inbound.sh",
      }
    },
    "findings": [{
      "address": "azurerm_network_security_group.nsg",
      "type": "azurerm_network_security_group",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "changed_paths": ["security_rule"],
    }],
  })
  reason == "auto_remediation_required"
}

test_block_reason_l2 if {
  reason := block_reason with input as object.union(base_input, {
    "findings": [{
      "address": "azurerm_storage_account.sa",
      "type": "azurerm_storage_account",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "changed_paths": ["min_tls_version"],
    }],
  })
  reason == "ticket_and_notify_required"
}

test_block_reason_none if {
  reason := block_reason with input as object.union(base_input, {
    "findings": [{
      "address": "output.vm_name",
      "type": "output",
      "provider_name": "unknown",
      "changed_paths": ["$"],
    }],
  })
  reason == "none"
}
