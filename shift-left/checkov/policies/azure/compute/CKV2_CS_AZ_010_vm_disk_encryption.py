"""
CKV2_CS_AZ_010 — Ensure VM OS disk uses Customer-Managed Key (CMK) via DES (CIS 7.1)

The YAML operator 'exists' returns PASSED for null values.
This Python check explicitly rejects null, empty string, and None.

PASS only if os_disk.disk_encryption_set_id is a non-empty, non-null string.
FAIL if null, empty, missing, or not a string.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_NULL_VALUES = {"", "null", "none", "${null}"}


def _unwrap(value, default=None):
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckVMDiskEncryption(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure disk encryption is enabled on VMs via Disk Encryption Set (CIS 7.1)",
            id="CKV2_CS_AZ_010",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=[
                "azurerm_linux_virtual_machine",
                "azurerm_windows_virtual_machine",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        # os_disk is double-wrapped: [[{...}]] or [[dict, ...]]
        os_disk_outer = conf.get("os_disk", [[]])
        os_disk_inner = _unwrap(os_disk_outer, [])
        if isinstance(os_disk_inner, list):
            os_disk = os_disk_inner[0] if os_disk_inner else {}
        else:
            os_disk = os_disk_inner if isinstance(os_disk_inner, dict) else {}

        des_id_raw = os_disk.get("disk_encryption_set_id", [None])
        des_id = _unwrap(des_id_raw)

        if des_id is None:
            return CheckResult.FAILED
        des_str = str(des_id).strip().lower()
        if des_str in _NULL_VALUES:
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckVMDiskEncryption()
