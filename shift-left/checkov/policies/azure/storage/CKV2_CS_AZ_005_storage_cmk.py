"""CKV2_CS_AZ_005 - Ensure storage CMK configuration is complete."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_REQUIRED_ATTRIBUTES = ("storage_account_id", "key_vault_id", "key_name")
_NULL_VALUES = {"", "null", "none", "${null}"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _has_value(value) -> bool:
    raw = _unwrap(value)
    if raw is None:
        return False
    return str(raw).strip().lower() not in _NULL_VALUES


class CheckStorageCMKComplete(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure storage CMK configuration is complete",
            id="CKV2_CS_AZ_005",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_storage_account_customer_managed_key"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        if all(_has_value(conf.get(attr, [None])) for attr in _REQUIRED_ATTRIBUTES):
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckStorageCMKComplete()
