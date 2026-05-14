"""CKV2_CS_AZ_043 - Ensure Storage Account network rules deny by default."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckStorageNetworkDefaultDeny(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Storage Account network rules deny by default",
            id="CKV2_CS_AZ_043",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_storage_account_network_rules"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        default_action = str(_unwrap(conf.get("default_action", [""]), "")).strip().lower()
        if default_action == "deny":
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckStorageNetworkDefaultDeny()
