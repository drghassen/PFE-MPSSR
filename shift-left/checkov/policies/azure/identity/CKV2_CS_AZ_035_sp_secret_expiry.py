"""
CKV2_CS_AZ_035 — Ensure Service Principal secrets have expiration date set

Static Service Principal secrets without expiry are a permanent credential
exposure risk if compromised. All azurerm_service_principal_password resources
must have an end_date or end_date_relative set.

PASS if end_date or end_date_relative is present and non-empty
FAIL if both are absent, null, or empty string

Note: this policy detects SP secrets managed via Terraform.
The ARM_CLIENT_SECRET stored in GitLab CI variables cannot be scanned
by Checkov — see pipeline governance check in ci/scripts/deploy-infrastructure.sh.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_NULL_VALUES = {"", "null", "none"}


def _unwrap(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _has_value(raw) -> bool:
    val = _unwrap(raw)
    if val is None:
        return False
    return str(val).strip().lower() not in _NULL_VALUES


class CheckSPSecretExpiry(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Service Principal password has expiration date (NIST IA-5)",
            id="CKV2_CS_AZ_035",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_service_principal_password"],
        )

    def scan_resource_conf(self, conf):
        has_end_date = _has_value(conf.get("end_date", [None]))
        has_end_date_relative = _has_value(conf.get("end_date_relative", [None]))
        if has_end_date or has_end_date_relative:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckSPSecretExpiry()
