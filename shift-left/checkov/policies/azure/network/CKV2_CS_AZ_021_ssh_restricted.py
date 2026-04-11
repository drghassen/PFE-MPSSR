"""
CKV2_CS_AZ_021 — Ensure SSH (port 22) access from the Internet is restricted (CIS 6.4)

FAIL only when a SINGLE security_rule simultaneously satisfies ALL of:
  - access    == "Allow"
  - direction == "Inbound"
  - source_address_prefix in {"*", "0.0.0.0/0", "::/0", "Internet", "Any"}
    OR source_address_prefixes contains any of those values
  - destination_port_range covers port 22 (exact "22", wildcard "*",
    or a range lo-hi where lo <= 22 <= hi)
    OR destination_port_ranges contains any such value

YAML policies evaluate attributes across different rules in the same NSG,
causing false positives when deny-all rules have source="*" while only the
Allow rule exposes port 22. This Python check evaluates each rule atomically.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_INTERNET_SOURCES = frozenset({"*", "0.0.0.0/0", "::/0", "Internet", "Any"})
_TARGET_PORT = 22


def _unwrap(value, default=""):
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _covers_port(rule: dict, port: int) -> bool:
    """Return True if the rule's destination port specification covers *port*."""
    # Single destination_port_range
    single = str(_unwrap(rule.get("destination_port_range", ""), ""))
    if single == "*":
        return True
    if single == str(port):
        return True
    if "-" in single:
        try:
            lo, hi = single.split("-", 1)
            if int(lo) <= port <= int(hi):
                return True
        except (ValueError, TypeError):
            pass

    # List form: destination_port_ranges  (can be [[...]] or [...])
    ranges_raw = rule.get("destination_port_ranges", [])
    if isinstance(ranges_raw, list) and ranges_raw:
        # Checkov wraps the list in an outer list: [[val1, val2, ...]]
        inner = ranges_raw[0] if isinstance(ranges_raw[0], list) else ranges_raw
        for pr in inner:
            pr = str(pr)
            if pr == "*" or pr == str(port):
                return True
            if "-" in pr:
                try:
                    lo, hi = pr.split("-", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _from_internet(rule: dict) -> bool:
    """Return True if the rule allows traffic from an Internet-equivalent source."""
    # Single source_address_prefix
    src = str(_unwrap(rule.get("source_address_prefix", ""), ""))
    if src in _INTERNET_SOURCES:
        return True

    # List form: source_address_prefixes
    prefixes_raw = rule.get("source_address_prefixes", [])
    if isinstance(prefixes_raw, list) and prefixes_raw:
        inner = prefixes_raw[0] if isinstance(prefixes_raw[0], list) else prefixes_raw
        for p in inner:
            if str(p) in _INTERNET_SOURCES:
                return True
    return False


class CheckSSHRestricted(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure SSH access from the Internet is evaluated and restricted (CIS 6.4)",
            id="CKV2_CS_AZ_021",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_network_security_group"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        # security_rule is wrapped: [[rule_dict, rule_dict, ...]]
        rules_outer = conf.get("security_rule", [[]])
        rules = rules_outer[0] if (isinstance(rules_outer, list) and rules_outer) else []
        if not isinstance(rules, list):
            rules = [rules]

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            access = str(_unwrap(rule.get("access", ""), "")).lower()
            direction = str(_unwrap(rule.get("direction", ""), "")).lower()

            if (
                access == "allow"
                and direction == "inbound"
                and _from_internet(rule)
                and _covers_port(rule, _TARGET_PORT)
            ):
                return CheckResult.FAILED

        return CheckResult.PASSED


scanner = CheckSSHRestricted()
