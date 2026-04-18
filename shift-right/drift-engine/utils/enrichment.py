"""
Enrich drift findings with OPA decisions.
"""

from __future__ import annotations

import structlog
from typing import Any

logger = structlog.get_logger(__name__)

# OPA policy uses upper-case severities; CloudSentinel uses title case.
_OPA_SEVERITY_NORMALIZE: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "INFORMATIONAL": "Info",
}


def enrich_drift_items_with_opa(
    drift_items: list[dict[str, Any]],
    opa_decisions: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Merge normalized drift items with OPA decisions.

    Expected OPA decision shape:
      {
        "violations": [...],              # raw policy violations
        "effective_violations": [...],    # violations after approved exceptions
        "excepted_violations": [...],     # violations suppressed by exceptions
        "compliant": [...]
      }
    """

    effective_violations = opa_decisions.get("effective_violations")
    if not isinstance(effective_violations, list):
        effective_violations = opa_decisions.get("violations", [])

    excepted_violations = opa_decisions.get("excepted_violations")
    if not isinstance(excepted_violations, list):
        excepted_violations = []

    compliant = opa_decisions.get("compliant")
    if not isinstance(compliant, list):
        compliant = []

    for v in effective_violations:
        if not v.get("resource_id"):
            logger.warning(
                "opa_violation_missing_resource_id",
                violation=v,
                hint="normalize_drift_for_opa() must set resource_id to Terraform address",
            )

    effective_violations_by_address = {
        v["resource_id"]: v for v in effective_violations if v.get("resource_id")
    }

    excepted_addresses = {
        v["resource_id"] for v in excepted_violations if v.get("resource_id")
    }

    compliant_addresses = {c["resource_id"] for c in compliant if c.get("resource_id")}

    enriched_items: list[dict[str, Any]] = []

    for item in drift_items:
        address = item.get("address")

        if address in effective_violations_by_address:
            decision = effective_violations_by_address[address]
            raw_severity = str(decision.get("severity", "MEDIUM"))
            item["severity"] = _OPA_SEVERITY_NORMALIZE.get(
                raw_severity, raw_severity.capitalize()
            )
            item["opa_reason"] = decision.get("reason", "OPA violation detected")
            item["action_required"] = decision.get("action_required", "manual_review")
            item["custodian_policy"] = decision.get("custodian_policy")
            item["opa_evaluated"] = True
            item["opa_excepted"] = False
        elif address in excepted_addresses:
            item["severity"] = "Info"
            item["opa_reason"] = "Violation suppressed by approved drift exception"
            item["action_required"] = "none"
            item["custodian_policy"] = None
            item["opa_evaluated"] = True
            item["opa_excepted"] = True
        elif address in compliant_addresses:
            item["severity"] = "Info"
            item["opa_reason"] = "Drift detected but within acceptable bounds"
            item["action_required"] = "none"
            item["custodian_policy"] = None
            item["opa_evaluated"] = True
            item["opa_excepted"] = False
        else:
            logger.warning("drift_item_not_evaluated_by_opa", address=address)
            item["severity"] = "Medium"
            item["opa_reason"] = "OPA evaluation missing"
            item["action_required"] = "manual_review"
            item["custodian_policy"] = None
            item["opa_evaluated"] = False
            item["opa_excepted"] = False

        enriched_items.append(item)

    logger.info(
        "enrichment_complete",
        total=len(enriched_items),
        actionable=len(
            [
                i
                for i in enriched_items
                if i.get("action_required") not in [None, "none", "monitor"]
            ]
        ),
        excepted=len([i for i in enriched_items if i.get("opa_excepted")]),
        compliant=len([i for i in enriched_items if i.get("severity") == "Info"]),
        opa_evaluated=len([i for i in enriched_items if i.get("opa_evaluated")]),
    )

    return enriched_items
