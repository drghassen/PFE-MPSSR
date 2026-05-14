"""CKV2_CS_AZ_038 - Ensure Cosmos DB local authentication is disabled."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckCosmosLocalAuthDisabled(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Cosmos DB local authentication is disabled",
            id="CKV2_CS_AZ_038",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_cosmosdb_account"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        value = _unwrap(conf.get("local_authentication_disabled", [None]))
        if str(value).strip().lower() in {"true", "1"}:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckCosmosLocalAuthDisabled()
