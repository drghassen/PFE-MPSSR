"""CKV2_CS_AZ_039 - Ensure Cosmos DB public network access is disabled."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckCosmosNetworkRestricted(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Cosmos DB public network access is disabled",
            id="CKV2_CS_AZ_039",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_cosmosdb_account"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        public_access = _unwrap(conf.get("public_network_access_enabled", [None]))
        if str(public_access).strip().lower() in {"false", "0"}:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckCosmosNetworkRestricted()
