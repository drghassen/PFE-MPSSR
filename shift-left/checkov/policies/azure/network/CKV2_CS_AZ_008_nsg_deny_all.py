"""
CKV2_CS_AZ_008 — Ensure Network Security Groups have an explicit deny-all
                  inbound rule (CIS 6.5)

PASS if the azurerm_network_security_group contains at least one security_rule
where ALL of the following are true simultaneously:
  - access                  == "Deny"
  - direction               == "Inbound"
  - destination_port_range  == "*"
  - source_address_prefix   == "*"

FAIL if no such catch-all deny-all inbound rule exists.

Why Python instead of YAML:
  The previous YAML policy targeted azurerm_network_security_rule (standalone
  resource) but the student-secure IaC uses inline security_rule blocks inside
  azurerm_network_security_group — the YAML policy silently passed every NSG
  without evaluating a single rule. Python checks the correct resource type and
  evaluates each rule atomically, matching the pattern in CKV2_CS_AZ_017/021.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=""):
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckNSGDenyAll(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Network Security Groups have explicit deny-all inbound rule (CIS 6.5)",
            id="CKV2_CS_AZ_008",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_network_security_group"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        # security_rule is wrapped by Checkov: [[rule_dict, rule_dict, ...]]
        rules_outer = conf.get("security_rule", [[]])
        rules = rules_outer[0] if (isinstance(rules_outer, list) and rules_outer) else []
        if not isinstance(rules, list):
            rules = [rules]

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            access = str(_unwrap(rule.get("access", ""), "")).lower()
            direction = str(_unwrap(rule.get("direction", ""), "")).lower()
            dst_port = str(_unwrap(rule.get("destination_port_range", ""), ""))
            src_addr = str(_unwrap(rule.get("source_address_prefix", ""), ""))

            if (
                access == "deny"
                and direction == "inbound"
                and dst_port == "*"
                and src_addr == "*"
            ):
                return CheckResult.PASSED

        # No catch-all deny-all inbound rule found.
        return CheckResult.FAILED


scanner = CheckNSGDenyAll()
