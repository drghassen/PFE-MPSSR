"""
Enrichissement des findings de drift avec les décisions OPA
"""
from __future__ import annotations

import structlog
from typing import Any

logger = structlog.get_logger(__name__)


def enrich_drift_items_with_opa(
    drift_items: list[dict[str, Any]],
    opa_decisions: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    Fusionne les drift items bruts avec les décisions OPA.
    
    Args:
        drift_items: Items originaux de json_normalizer.normalize_terraform_plan()
        opa_decisions: Décisions retournées par OPA {"violations": [...], "compliant": [...]}
    
    Returns:
        Items enrichis avec:
        - severity (remplace l'ancien classify_drift_severity)
        - opa_reason
        - action_required
        - custodian_policy
    """
    
    # Créer un index des violations OPA par resource address
    violations_by_address = {
        v["resource_id"]: v
        for v in opa_decisions.get("violations", [])
    }
    
    # Créer un set des ressources conformes
    compliant_addresses = {
        c["resource_id"]
        for c in opa_decisions.get("compliant", [])
    }
    
    enriched_items = []
    
    for item in drift_items:
        address = item.get("address")
        
        if address in violations_by_address:
            # Resource en violation
            opa_decision = violations_by_address[address]
            
            # Enrichir avec données OPA (remplace l'ancien severity hardcodé)
            item["severity"] = opa_decision["severity"]
            item["opa_reason"] = opa_decision["reason"]
            item["action_required"] = opa_decision["action_required"]
            item["custodian_policy"] = opa_decision.get("custodian_policy")
            item["opa_evaluated"] = True
            
        elif address in compliant_addresses:
            # Resource conforme
            item["severity"] = "Info"  # Compatible avec DefectDojo format
            item["opa_reason"] = "Drift detected but within acceptable bounds"
            item["action_required"] = "none"
            item["custodian_policy"] = None
            item["opa_evaluated"] = True
            
        else:
            # Resource non évaluée par OPA (ne devrait pas arriver)
            logger.warning(
                "drift_item_not_evaluated_by_opa",
                address=address
            )
            # Fallback sur l'ancien système (défensive)
            item["severity"] = "Medium"
            item["opa_reason"] = "OPA evaluation missing"
            item["action_required"] = "manual_review"
            item["custodian_policy"] = None
            item["opa_evaluated"] = False
        
        enriched_items.append(item)
    
    logger.info(
        "enrichment_complete",
        total=len(enriched_items),
        violations=len([i for i in enriched_items if i.get("severity") not in ["Info", "Low"]]),
        compliant=len([i for i in enriched_items if i.get("severity") == "Info"]),
        opa_evaluated=len([i for i in enriched_items if i.get("opa_evaluated")])
    )
    
    return enriched_items