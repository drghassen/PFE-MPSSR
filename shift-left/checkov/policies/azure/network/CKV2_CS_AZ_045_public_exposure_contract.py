"""
CKV2_CS_AZ_045 - Ensure public inbound exposure follows CloudSentinel contract.

Internet-facing application traffic is not automatically a vulnerability, but it
must be intentional and narrowly scoped. This check allows public HTTP/HTTPS
only when the NSG carries an explicit frontend exposure contract:

  tags = {
    "cs:role"          = "frontend"
    "cs:exposure"      = "public"
    "cs:allowed_ports" = "80,443"
  }

All public SSH/RDP exposure fails, regardless of tags. Backend, admin, private,
or untagged NSGs cannot expose inbound Internet traffic.

This resource-level check deliberately validates the enforcement point (NSG
rules). A future graph check can add VM/NIC/subnet correlation, but this policy
already blocks the practical bypass: adding an Internet-facing NSG rule without
declaring and limiting the exposure contract.
"""

from __future__ import annotations

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_INTERNET_SOURCES = {"*", "0.0.0.0/0", "::/0", "Internet", "Any", "internet", "any"}
_ALLOWED_FRONTEND_PORTS = {80, 443}
_ADMIN_PORTS = {22, 3389}
_FRONTEND_ROLES = {"frontend"}
_PUBLIC_EXPOSURES = {"public", "internet-facing", "internet"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _as_blocks(value):
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        blocks = []
        for item in value:
            blocks.extend(_as_blocks(item))
        return blocks
    return []


def _as_strings(value):
    raw = _unwrap(value, [])
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if raw is None:
        return []
    text = str(raw).strip()
    return [text] if text else []


def _is_inbound_allow(rule: dict) -> bool:
    access = str(_unwrap(rule.get("access"), "")).strip().lower()
    direction = str(_unwrap(rule.get("direction"), "")).strip().lower()
    return access == "allow" and direction == "inbound"


def _from_internet(rule: dict) -> bool:
    sources = _as_strings(rule.get("source_address_prefix")) + _as_strings(
        rule.get("source_address_prefixes")
    )
    return any(source in _INTERNET_SOURCES for source in sources)


def _parse_ports(rule: dict):
    specs = _as_strings(rule.get("destination_port_range")) + _as_strings(
        rule.get("destination_port_ranges")
    )
    if not specs:
        return set(), False

    ports = set()
    broad = False
    for spec in specs:
        if spec == "*":
            broad = True
            continue
        if "-" in spec:
            start, end = spec.split("-", 1)
            try:
                start_i = int(start)
                end_i = int(end)
            except ValueError:
                broad = True
                continue
            if start_i > end_i:
                broad = True
                continue
            if end_i - start_i > 32:
                broad = True
                continue
            ports.update(range(start_i, end_i + 1))
            continue
        try:
            ports.add(int(spec))
        except ValueError:
            broad = True
    return ports, broad


def _extract_tags(conf: dict) -> dict[str, str]:
    tags_raw = _unwrap(conf.get("tags"), {})
    if isinstance(tags_raw, list):
        tags_raw = _unwrap(tags_raw, {})
    if not isinstance(tags_raw, dict):
        return {}
    return {str(key).strip(): str(_unwrap(value, "")).strip() for key, value in tags_raw.items()}


def _parse_allowed_ports(tags: dict[str, str]) -> set[int]:
    raw = tags.get("cs:allowed_ports", "")
    allowed = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            allowed.add(int(part))
        except ValueError:
            return set()
    return allowed


def _has_frontend_public_contract(conf: dict, ports: set[int]) -> bool:
    tags = _extract_tags(conf)
    role = tags.get("cs:role", "").strip().lower()
    exposure = tags.get("cs:exposure", "").strip().lower()
    allowed_ports = _parse_allowed_ports(tags)
    return (
        role in _FRONTEND_ROLES
        and exposure in _PUBLIC_EXPOSURES
        and ports
        and ports <= _ALLOWED_FRONTEND_PORTS
        and ports <= allowed_ports
    )


class CheckPublicExposureContract(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure public inbound exposure follows CloudSentinel contract",
            id="CKV2_CS_AZ_045",
            categories=[CheckCategories.NETWORKING],
            supported_resources=[
                "azurerm_network_security_group",
                "azurerm_network_security_rule",
            ],
        )

    def _rules_for_resource(self, conf: dict) -> list[dict]:
        inline_rules = _as_blocks(conf.get("security_rule", []))
        return inline_rules if inline_rules else [conf]

    def scan_resource_conf(self, conf):  # noqa: ANN001
        for rule in self._rules_for_resource(conf):
            if not _is_inbound_allow(rule) or not _from_internet(rule):
                continue

            ports, broad = _parse_ports(rule)
            if broad:
                return CheckResult.FAILED
            if ports & _ADMIN_PORTS:
                return CheckResult.FAILED
            if not _has_frontend_public_contract(conf, ports):
                return CheckResult.FAILED

        return CheckResult.PASSED


scanner = CheckPublicExposureContract()
