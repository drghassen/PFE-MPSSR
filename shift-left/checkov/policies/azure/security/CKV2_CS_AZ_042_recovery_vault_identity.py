"""CKV2_CS_AZ_042 - Ensure Recovery Services Vault uses managed identity."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


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


class CheckRecoveryVaultIdentity(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Recovery Services Vault uses managed identity",
            id="CKV2_CS_AZ_042",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_recovery_services_vault"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        identity = _first_block(conf, "identity")
        identity_type = str(_unwrap(identity.get("type"), "")).strip()
        if identity_type in {"SystemAssigned", "UserAssigned"}:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckRecoveryVaultIdentity()
