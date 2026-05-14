"""CKV2_CS_AZ_024 - Ensure Microsoft Defender for Storage is enabled."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckDefenderStorageEnabled(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Microsoft Defender for Storage is enabled",
            id="CKV2_CS_AZ_024",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["azurerm_security_center_subscription_pricing"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        resource_type = str(_unwrap(conf.get("resource_type", [""]), "")).strip()
        tier = str(_unwrap(conf.get("tier", [""]), "")).strip()
        if resource_type == "StorageAccounts" and tier == "Standard":
            return CheckResult.PASSED
        if resource_type == "StorageAccounts":
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckDefenderStorageEnabled()
