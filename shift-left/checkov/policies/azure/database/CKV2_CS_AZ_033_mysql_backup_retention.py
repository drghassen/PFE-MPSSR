"""
CKV2_CS_AZ_033 — Ensure MySQL Flexible Server backup retention >= 7 days (CIS 4.13)

Azure MySQL Flexible Server default backup retention is 7 days.
The IaC sets backup_retention_days = 7 explicitly.
This check enforces the minimum is >= 7 and the attribute is present.

PASS if backup_retention_days >= 7
FAIL if backup_retention_days < 7 or attribute is missing/null
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_MIN_BACKUP_DAYS = 7


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckMySQLBackupRetention(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure MySQL Flexible Server backup retention is >= 7 days (CIS 4.13)",
            id="CKV2_CS_AZ_033",
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["azurerm_mysql_flexible_server"],
        )

    def scan_resource_conf(self, conf):
        raw = conf.get("backup_retention_days", [None])
        days = _unwrap(raw)
        if days is None:
            return CheckResult.FAILED
        try:
            if int(days) >= _MIN_BACKUP_DAYS:
                return CheckResult.PASSED
        except (TypeError, ValueError):
            pass
        return CheckResult.FAILED


scanner = CheckMySQLBackupRetention()
