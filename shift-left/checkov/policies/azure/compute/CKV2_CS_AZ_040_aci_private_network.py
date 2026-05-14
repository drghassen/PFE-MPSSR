"""CKV2_CS_AZ_040 - Ensure Azure Container Instance uses private networking."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _has_non_empty_list(value) -> bool:
    raw = _unwrap(value, [])
    if isinstance(raw, list):
        return any(str(item).strip() for item in raw)
    return bool(str(raw).strip())


class CheckACIPrivateNetwork(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Azure Container Instance uses private networking",
            id="CKV2_CS_AZ_040",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_container_group"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        ip_type = str(_unwrap(conf.get("ip_address_type", [""]), "")).strip().lower()
        if ip_type == "private" and _has_non_empty_list(conf.get("subnet_ids", [])):
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckACIPrivateNetwork()
