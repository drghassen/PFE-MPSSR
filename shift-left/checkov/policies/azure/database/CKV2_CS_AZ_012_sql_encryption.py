"""CKV2_CS_AZ_012 - Ensure Azure SQL TDE uses a Customer-Managed Key."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_NULL_VALUES = {"", "null", "none", "${null}"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckSQLTDECustomerManagedKey(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Azure SQL TDE uses a Customer-Managed Key",
            id="CKV2_CS_AZ_012",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_mssql_server_transparent_data_encryption"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        key_id = _unwrap(conf.get("key_vault_key_id", [None]))
        if key_id is None:
            return CheckResult.FAILED
        if str(key_id).strip().lower() in _NULL_VALUES:
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckSQLTDECustomerManagedKey()
