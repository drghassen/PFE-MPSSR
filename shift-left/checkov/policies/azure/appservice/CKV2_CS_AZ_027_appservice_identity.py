"""CKV2_CS_AZ_027 - Ensure App Service uses a managed identity."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_IDENTITY_TYPES = {"SystemAssigned", "UserAssigned"}


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


class CheckAppServiceManagedIdentity(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure App Service uses a managed identity",
            id="CKV2_CS_AZ_027",
            categories=[CheckCategories.IAM],
            supported_resources=[
                "azurerm_linux_web_app",
                "azurerm_windows_web_app",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        identity = _first_block(conf, "identity")
        identity_type = str(_unwrap(identity.get("type"), "")).strip()
        configured = {part.strip() for part in identity_type.split(",") if part.strip()}
        if configured & _IDENTITY_TYPES:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckAppServiceManagedIdentity()
