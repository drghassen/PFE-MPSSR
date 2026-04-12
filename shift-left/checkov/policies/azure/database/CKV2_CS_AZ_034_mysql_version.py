"""
CKV2_CS_AZ_034 — Ensure MySQL Flexible Server uses version 8.0 or higher

MySQL 5.7 reaches end-of-life October 2025. Only MySQL 8.x is supported
for new deployments. The IaC uses version = "8.0.21".

PASS if major version >= 8  (e.g. "8.0.21", "8.0", "8")
FAIL if major version < 8   (e.g. "5.7", "5.6")
FAIL if version is missing or unparseable
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_MIN_MAJOR_VERSION = 8


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckMySQLVersion(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure MySQL Flexible Server uses version 8.0 or higher (EOL policy)",
            id="CKV2_CS_AZ_034",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["azurerm_mysql_flexible_server"],
        )

    def scan_resource_conf(self, conf):
        raw = conf.get("version", [None])
        version = _unwrap(raw)
        if version is None:
            return CheckResult.FAILED
        try:
            major = int(str(version).strip().split(".")[0])
            if major >= _MIN_MAJOR_VERSION:
                return CheckResult.PASSED
        except (ValueError, IndexError):
            pass
        return CheckResult.FAILED


scanner = CheckMySQLVersion()
