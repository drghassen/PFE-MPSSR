"""CKV2_CS_AZ_015 - Ensure Key Vault uses Azure RBAC authorization."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckKeyVaultRBAC(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Key Vault uses Azure RBAC authorization",
            id="CKV2_CS_AZ_015",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_key_vault"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        for attr in ("rbac_authorization_enabled", "enable_rbac_authorization"):
            value = _unwrap(conf.get(attr, [None]))
            if str(value).strip().lower() in {"true", "1"}:
                return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckKeyVaultRBAC()
