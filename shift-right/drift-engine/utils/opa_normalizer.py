"""
Adaptateur Drift Findings → OPA Input Format
Transforme les drift items normalisés en format OPA-compatible
"""
from __future__ import annotations

import structlog
from typing import Any
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)


def normalize_drift_for_opa(drift_items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Transforme les drift items (produits par json_normalizer.normalize_terraform_plan)
    en format standardisé pour évaluation OPA.
    
    Args:
        drift_items: Liste des items de drift avec structure :
            {
                "address": "azurerm_storage_account.example",
                "mode": "managed",
                "type": "azurerm_storage_account",
                "name": "example",
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "actions": ["update"],
                "resource_id": "/subscriptions/.../",
                "changed_paths": ["min_tls_version"],
                "drifted": True
            }
        
    Returns:
        Format OPA : {"findings": [...]}
    """
    
    normalized = {
        "source": "drift-engine",
        "scan_type": "shift-right-drift",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": []
    }
    
    for item in drift_items:
        # Extraire uniquement les champs nécessaires pour OPA
        # (évite de passer des données sensibles inutiles)
        finding = {
            "address": item.get("address"),
            "type": item.get("type"),
            "mode": item.get("mode"),
            "name": item.get("name"),
            "provider_name": item.get("provider_name"),
            "actions": item.get("actions", []),
            "resource_id": item.get("resource_id"),
            "changed_paths": item.get("changed_paths", []),
        }
        
        normalized["findings"].append(finding)
    
    logger.info(
        "drift_normalized_for_opa",
        finding_count=len(normalized["findings"]),
        resource_types=list(set(f["type"] for f in normalized["findings"] if f.get("type")))
    )
    
    return normalized