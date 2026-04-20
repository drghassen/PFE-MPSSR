"""
CKV2_CS_AZ_037 — Ensure PostgreSQL Flexible Server disables public network access

PASS if public_network_access_enabled is explicitly false.
FAIL if the attribute is absent (Azure default: true) or set to true.

Why Python: YAML 'equals false' evaluates absent attributes as truthy,
producing false negatives when public_network_access_enabled is simply omitted.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckPostgreSQLNoPublicAccess(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure PostgreSQL Flexible Server has public network access disabled (CIS 4.3.8)",
            id="CKV2_CS_AZ_037",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_postgresql_flexible_server"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        pub_raw = conf.get("public_network_access_enabled", [None])
        pub = _unwrap(pub_raw)
        if pub is None:
            return CheckResult.FAILED  # attribute absent → Azure default is public=true
        if str(pub).strip().lower() in {"false", "0"}:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckPostgreSQLNoPublicAccess()
