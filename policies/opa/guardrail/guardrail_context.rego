# ==============================================================================
# CloudSentinel — State Backend Guardrail: Context Detection
# Package: cloudsentinel.guardrail.tfstate
# ==============================================================================
#
# Responsibility:
#   Determines whether a drift or Prowler finding targets a resource that is
#   classified as a Terraform state backend. This is the only place in the
#   policy stack where the terraform_state_backend classification is resolved.
#
# Detection priority (first match wins):
#   1. Explicit context tag on the finding itself (finding.resource_context)
#   2. Terraform resource address in protected_resources data registry
#   3. ARM resource_id substring match against known backend names
#   4. Input-injected override list (CI runtime / test harness)
#
# Data root key: cloudsentinel.protected_resources
# Data file    : config/opa/data/protected_resources.json
#
# ==============================================================================

package cloudsentinel.guardrail.tfstate

import rego.v1

# ---------------------------------------------------------------------------
# Protected resource registry — loaded from data file
# Shape: [{ arm_resource_name: "sttfstate...", resource_address: "module.x.azurerm_storage_account.y", ... }]
# ---------------------------------------------------------------------------
_registry := object.get(
  data,
  ["cloudsentinel", "protected_resources", "terraform_state_backends"],
  [],
)

_backend_arm_names := {name |
  some entry in _registry
  name := object.get(entry, "arm_resource_name", "")
  name != ""
}

_backend_tf_addresses := {addr |
  some entry in _registry
  addr := object.get(entry, "resource_address", "")
  addr != ""
}

# ---------------------------------------------------------------------------
# Input-injected overrides — for CI runtime injection and test harness.
# CI can pass: input.protected_resources.terraform_state_backends = ["sttfstate01"]
# ---------------------------------------------------------------------------
_input_backend_list := names if {
  names := object.get(input, ["protected_resources", "terraform_state_backends"], [])
  is_array(names)
} else := []

# ---------------------------------------------------------------------------
# is_state_backend_finding(finding)
#
# TRUE if the finding targets a known Terraform state backend resource.
# All four detection methods are tried; any match is sufficient.
# ---------------------------------------------------------------------------

# Priority 1 — explicit context tag (highest confidence, set by drift engine)
is_state_backend_finding(finding) if {
  object.get(finding, "resource_context", "") == "terraform_state_backend"
}

# Priority 2 — Terraform resource address in registry (drift findings)
is_state_backend_finding(finding) if {
  addr := object.get(finding, "address", "")
  addr != ""
  addr in _backend_tf_addresses
}

# Priority 3a — ARM resource_id substring match against registry (Prowler findings)
is_state_backend_finding(finding) if {
  rid := lower(object.get(finding, "resource_id", ""))
  rid != ""
  some name in _backend_arm_names
  contains(rid, lower(name))
}

# Priority 3b — Terraform address substring in resource_id (cross-format match)
is_state_backend_finding(finding) if {
  rid := lower(object.get(finding, "resource_id", ""))
  rid != ""
  some addr in _backend_tf_addresses
  contains(rid, lower(addr))
}

# Priority 4 — Input-injected list (CI runtime / test override)
is_state_backend_finding(finding) if {
  addr := object.get(finding, "address", "")
  addr != ""
  addr in _input_backend_list
}

is_state_backend_finding(finding) if {
  rid := lower(object.get(finding, "resource_id", ""))
  rid != ""
  some name in _input_backend_list
  contains(rid, lower(name))
}
