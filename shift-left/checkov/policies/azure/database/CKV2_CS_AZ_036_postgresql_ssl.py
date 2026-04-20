"""
CKV2_CS_AZ_036 — Ensure PostgreSQL Flexible Server enforces TLS 1.2 minimum

PASS if ssl_minimal_tls_version_enforced is "TLS1_2" or "TLS1_3".
FAIL if the attribute is absent (Azure default: TLS 1.0) or set to "TLS1_0" / "TLS1_1".

Why Python: YAML 'equals' operators silently pass on absent attributes,
producing false negatives when ssl_minimal_tls_version_enforced is simply omitted.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_SECURE_TLS = frozenset({"TLS1_2", "TLS1_3"})


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckPostgreSQLSSL(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure PostgreSQL Flexible Server enforces TLS 1.2 minimum (CIS 4.3.7)",
            id="CKV2_CS_AZ_036",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_postgresql_flexible_server"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        tls_raw = conf.get("ssl_minimal_tls_version_enforced", [None])
        tls = _unwrap(tls_raw)
        if tls is None:
            return CheckResult.FAILED  # attribute absent → Azure default TLS 1.0
        if str(tls).strip().upper() in _SECURE_TLS:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckPostgreSQLSSL()
