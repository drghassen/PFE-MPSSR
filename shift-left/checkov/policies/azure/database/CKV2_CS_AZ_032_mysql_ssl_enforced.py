"""
CKV2_CS_AZ_032 — Ensure MySQL Flexible Server enforces SSL (CIS 4.14)

Azure MySQL Flexible Server enforces SSL via a server configuration parameter.
In Terraform this is set via azurerm_mysql_flexible_server_configuration:
  name  = "require_secure_transport"
  value = "ON"

PASS if: resource name == "require_secure_transport" AND value == "ON"
FAIL if: name is "require_secure_transport" AND value != "ON"
PASS (vacuously) if: resource is a different configuration parameter

Note: this check is per-configuration-resource, not per-server.
The pipeline will flag if require_secure_transport is explicitly set to OFF.
If the resource is missing entirely, CKV2_CS_AZ_033 covers the server level.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_SSL_PARAM_NAME = "require_secure_transport"
_SSL_PARAM_VALUE_REQUIRED = "ON"


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckMySQLSSLEnforced(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure MySQL Flexible Server enforces SSL connections (CIS 4.14)",
            id="CKV2_CS_AZ_032",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_mysql_flexible_server_configuration"],
        )

    def scan_resource_conf(self, conf):
        name = str(_unwrap(conf.get("name", [""]), "")).strip().lower()
        if name != _SSL_PARAM_NAME:
            return CheckResult.PASSED
        value = str(_unwrap(conf.get("value", [""]), "")).strip().upper()
        if value == _SSL_PARAM_VALUE_REQUIRED:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckMySQLSSLEnforced()
