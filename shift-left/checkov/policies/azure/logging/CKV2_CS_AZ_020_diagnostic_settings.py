"""CKV2_CS_AZ_020 - Ensure diagnostic settings emit logs to an approved sink."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_SINK_ATTRIBUTES = (
    "log_analytics_workspace_id",
    "storage_account_id",
    "eventhub_authorization_rule_id",
)


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


def _has_value(value) -> bool:
    raw = _unwrap(value)
    if raw is None:
        return False
    return str(raw).strip().lower() not in {"", "null", "none", "${null}"}


class CheckDiagnosticSettings(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure diagnostic settings emit logs to an approved sink",
            id="CKV2_CS_AZ_020",
            categories=[CheckCategories.LOGGING],
            supported_resources=["azurerm_monitor_diagnostic_setting"],
        )

    def scan_resource_conf(self, conf):  # noqa: ANN001
        if not any(_has_value(conf.get(attr, [None])) for attr in _SINK_ATTRIBUTES):
            return CheckResult.FAILED

        enabled_logs = _as_blocks(conf.get("enabled_log", []))
        legacy_logs = _as_blocks(conf.get("log", []))
        if enabled_logs:
            return CheckResult.PASSED
        for log in legacy_logs:
            enabled = _unwrap(log.get("enabled", [True]), True)
            if str(enabled).strip().lower() in {"true", "1"}:
                return CheckResult.PASSED
        return CheckResult.FAILED


scanner = CheckDiagnosticSettings()
