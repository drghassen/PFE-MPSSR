"""
CKV2_CS_AZ_013 — Ensure Log Analytics Workspace retention >= 90 days (CIS 5.1)

Replaces the deprecated azurerm_monitor_log_profile resource type.
The IaC uses azurerm_log_analytics_workspace with retention_in_days.
Azure Student subscriptions cap free retention at 90 days.

PASS if retention_in_days >= 90
FAIL if retention_in_days < 90 or attribute missing.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_MIN_RETENTION_DAYS = 90


def _unwrap(value, default=None):
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


class CheckLogAnalyticsRetention(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure Log Analytics Workspace has retention >= 90 days (CIS 5.1)",
            id="CKV2_CS_AZ_013",
            categories=[CheckCategories.LOGGING],
            supported_resources=["azurerm_log_analytics_workspace"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        raw = conf.get("retention_in_days", [None])
        days = _unwrap(raw)
        try:
            if days is not None and int(days) >= _MIN_RETENTION_DAYS:
                return CheckResult.PASSED
        except (TypeError, ValueError):
            pass
        return CheckResult.FAILED


scanner = CheckLogAnalyticsRetention()
