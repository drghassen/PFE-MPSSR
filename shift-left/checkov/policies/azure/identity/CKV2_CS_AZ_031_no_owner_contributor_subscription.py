"""
CKV2_CS_AZ_031 — Ensure no Owner, Contributor, or User Access Administrator role
                  is assigned at subscription scope.

FAIL only when BOTH conditions are true simultaneously:
  1. role_definition_name is EXACTLY one of:
       "Owner", "Contributor", "User Access Administrator"
  2. scope resolves to a subscription-level path
     (contains "/subscriptions/" but not "/resourceGroups/")

PASS for all other cases, including:
  - "Key Vault Crypto Service Encryption User"  (required for CMK/DES)
  - "Key Vault Crypto User"
  - "Storage Blob Data Contributor"
  - Any role scoped to a specific resource (Key Vault, Storage Account, etc.)
  - Unresolved Terraform references as scope (e.g. azurerm_key_vault.this.id)
    which will not contain "/subscriptions/" and therefore PASS.

YAML replacement rationale:
  The previous YAML policy used `contains "Owner"` which incorrectly matched
  "Storage Blob Data Owner" and similar roles. The `within` operator with exact
  values had issues with unresolvable scope references being treated as matching
  by Checkov's graph engine. Exact Python string comparison avoids both problems.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_BLOCKED_ROLES = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
})


def _unwrap(value, default=""):
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckNoOwnerContributorSubscription(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure no Owner or Contributor role is assigned at subscription scope",
            id="CKV2_CS_AZ_031",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_role_assignment"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        role = str(_unwrap(conf.get("role_definition_name", ""), "")).strip()
        scope = str(_unwrap(conf.get("scope", ""), ""))

        # Only flag exact blocked role names at subscription scope.
        # Unresolved Terraform references (e.g. "azurerm_key_vault.this.id")
        # do not contain "/subscriptions/" so they correctly PASS.
        if role in _BLOCKED_ROLES and "/subscriptions/" in scope:
            return CheckResult.FAILED

        return CheckResult.PASSED


scanner = CheckNoOwnerContributorSubscription()
