"""CKV2_CS_AZ_026 - Ensure App Service uses TLS 1.2 or higher."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_SECURE_TLS = {"1.2", "1.3"}


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


class CheckAppServiceTLS(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure App Service uses TLS 1.2 or higher",
            id="CKV2_CS_AZ_026",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=[
                "azurerm_linux_web_app",
                "azurerm_windows_web_app",
            ],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        site_config = _first_block(conf, "site_config")
        min_tls = str(_unwrap(site_config.get("minimum_tls_version"), "")).strip()
        scm_tls = str(_unwrap(site_config.get("scm_minimum_tls_version"), min_tls)).strip()

        if min_tls in _SECURE_TLS and scm_tls in _SECURE_TLS:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckAppServiceTLS()
