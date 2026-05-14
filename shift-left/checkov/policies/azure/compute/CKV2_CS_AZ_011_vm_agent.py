"""CKV2_CS_AZ_011 - Ensure VM extension operations are disabled unless explicitly required."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckVMExtensionOperationsDisabled(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure VM extension operations are disabled unless explicitly required",
            id="CKV2_CS_AZ_011",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=[
                "azurerm_linux_virtual_machine",
                "azurerm_windows_virtual_machine",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        value = _unwrap(conf.get("allow_extension_operations", [None]))
        if value is None:
            return CheckResult.FAILED
        if str(value).strip().lower() in {"false", "0"}:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckVMExtensionOperationsDisabled()
