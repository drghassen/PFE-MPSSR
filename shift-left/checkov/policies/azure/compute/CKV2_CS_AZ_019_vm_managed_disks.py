"""CKV2_CS_AZ_019 - Ensure Virtual Machines use explicit managed OS disks."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_MANAGED_OS_DISK_SKUS = {
    "STANDARD_LRS",
    "STANDARDSSD_LRS",
    "PREMIUM_LRS",
    "STANDARDSSD_ZRS",
    "PREMIUM_ZRS",
    "ULTRASSD_LRS",
}


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


class CheckVMManagedOSDisk(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Virtual Machines use explicit managed OS disks",
            id="CKV2_CS_AZ_019",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=[
                "azurerm_linux_virtual_machine",
                "azurerm_windows_virtual_machine",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        os_disk = _first_block(conf, "os_disk")
        storage_type = str(_unwrap(os_disk.get("storage_account_type"), "")).strip().upper()
        if storage_type in _MANAGED_OS_DISK_SKUS:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckVMManagedOSDisk()
