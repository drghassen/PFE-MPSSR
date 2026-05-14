"""CKV2_CS_AZ_039 - Ensure Cosmos DB network access is restricted."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _as_blocks(value):
    raw = _unwrap(value, [])
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


class CheckCosmosNetworkRestricted(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Cosmos DB network access is restricted",
            id="CKV2_CS_AZ_039",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_cosmosdb_account"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        public_access = _unwrap(conf.get("public_network_access_enabled", [None]))
        if str(public_access).strip().lower() in {"false", "0"}:
            return CheckResult.PASSED

        vnet_filter = _unwrap(conf.get("is_virtual_network_filter_enabled", [None]))
        vnet_rules = _as_blocks(conf.get("virtual_network_rule", []))
        if str(vnet_filter).strip().lower() in {"true", "1"} and vnet_rules:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckCosmosNetworkRestricted()
