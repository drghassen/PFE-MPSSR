"""CKV2_CS_AZ_044 - Ensure VM backup policy keeps daily backups for at least 7 days."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_MIN_DAILY_RETENTION = 7


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _first_block(conf, key):
    raw = conf.get(key, [])
    block = _unwrap(raw, {})
    if isinstance(block, list):
        return block[0] if block and isinstance(block[0], dict) else {}
    return block if isinstance(block, dict) else {}


class CheckVMBackupRetention(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure VM backup policy keeps daily backups for at least 7 days",
            id="CKV2_CS_AZ_044",
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["azurerm_backup_policy_vm"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        retention_daily = _first_block(conf, "retention_daily")
        count = _unwrap(retention_daily.get("count"), None)
        try:
            if int(count) >= _MIN_DAILY_RETENTION:
                return CheckResult.PASSED
        except (TypeError, ValueError):
            pass
        return CheckResult.FAILED


scanner = CheckVMBackupRetention()
