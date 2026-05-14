"""CKV2_CS_AZ_029 - Ensure Key Vault keys have an expiration date."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_NULL_VALUES = {"", "null", "none", "${null}"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckKeyVaultKeyExpiration(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Key Vault keys have an expiration date",
            id="CKV2_CS_AZ_029",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_key_vault_key"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        expiration = _unwrap(conf.get("expiration_date", [None]))
        if expiration is None:
            return CheckResult.FAILED
        if str(expiration).strip().lower() in _NULL_VALUES:
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckKeyVaultKeyExpiration()
