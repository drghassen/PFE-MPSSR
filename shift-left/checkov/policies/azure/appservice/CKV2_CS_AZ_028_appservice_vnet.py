"""CKV2_CS_AZ_028 - Ensure App Service is integrated with a VNet."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_NULL_VALUES = {"", "null", "none", "${null}"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckAppServiceVNetIntegration(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure App Service is integrated with a VNet",
            id="CKV2_CS_AZ_028",
            categories=[CheckCategories.NETWORKING],
            supported_resources=[
                "azurerm_linux_web_app",
                "azurerm_windows_web_app",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        subnet_id = _unwrap(conf.get("virtual_network_subnet_id", [None]))
        if subnet_id is None:
            return CheckResult.FAILED
        if str(subnet_id).strip().lower() in _NULL_VALUES:
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckAppServiceVNetIntegration()
