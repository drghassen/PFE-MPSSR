"""
OPA HTTP Client pour Shift-Right Drift Evaluation
Utilise l'infrastructure OPA Server existante (docker-compose)
"""

from __future__ import annotations

import requests
import structlog
from typing import Any
from dataclasses import dataclass

logger = structlog.get_logger(__name__)


@dataclass
class OPAConfig:
    """Configuration OPA Server"""

    server_url: str = "http://localhost:8181"
    policy_path: str = "cloudsentinel.shiftright.drift"
    timeout: int = 30
    fallback_on_error: bool = True
    auth_token: str = ""


class OPAClient:
    """
    Client HTTP pour OPA Policy Decision Point.

    Zero Trust: All requests carry a Bearer token validated by OPA's
    system.authz policy. Without a valid token, OPA returns 403.

    Usage:
        config = OPAConfig(server_url="http://localhost:8182", auth_token="...")
        client = OPAClient(config)
        decisions = client.evaluate_drift(normalized_findings)
    """

    def __init__(self, config: OPAConfig) -> None:
        self.config = config
        self.session = requests.Session()
        # Inject Bearer token into all requests via session headers
        if self.config.auth_token:
            self.session.headers["Authorization"] = f"Bearer {self.config.auth_token}"
        self._health_check()

    def _health_check(self) -> bool:
        """Vérifie que OPA Server répond"""
        try:
            url = f"{self.config.server_url}/health"
            response = self.session.get(url, timeout=5)

            if response.status_code == 200:
                logger.info("opa_health_check_ok", server=self.config.server_url)
                return True
            else:
                logger.warning("opa_health_check_degraded", status=response.status_code)
                return False

        except requests.exceptions.RequestException as e:
            logger.error("opa_health_check_failed", error=str(e))
            if not self.config.fallback_on_error:
                raise
            return False

    def evaluate_drift(self, normalized_findings: dict[str, Any]) -> dict[str, Any]:
        """
        Envoie les drift findings à OPA pour évaluation.

        Args:
            normalized_findings: Format {"findings": [drift_items...]}

        Returns:
            {
              "violations": [...],
              "effective_violations": [...],
              "excepted_violations": [...],
              "compliant": [...],
              "drift_exception_summary": {...},
              "metadata": {...}
            }
        """
        # Construire l'URL de l'API OPA
        # Ex: /v1/data/cloudsentinel/shiftright/drift
        policy_path = self.config.policy_path.replace(".", "/")
        url = f"{self.config.server_url}/v1/data/{policy_path}"

        # Format attendu par OPA : {"input": {...}}
        payload = {"input": normalized_findings}

        try:
            logger.info(
                "opa_evaluate_request",
                url=url,
                finding_count=len(normalized_findings.get("findings", [])),
            )

            response = self.session.post(
                url,
                json=payload,
                timeout=self.config.timeout,
                headers={"Content-Type": "application/json"},
            )

            response.raise_for_status()
            result = response.json()

            # OPA retourne {"result": {violations: [...], effective_violations: [...], compliant: [...], ...}}
            opa_decision = result.get("result", {})
            raw_violations = opa_decision.get("violations", [])
            effective_violations = opa_decision.get("effective_violations")
            if not isinstance(effective_violations, list):
                # Backward compatibility: older policy versions may not expose
                # effective_violations; fall back to raw violations.
                effective_violations = raw_violations
            excepted_violations = opa_decision.get("excepted_violations")
            if not isinstance(excepted_violations, list):
                excepted_violations = []
            compliant = opa_decision.get("compliant", [])
            drift_exception_summary = opa_decision.get("drift_exception_summary", {})

            logger.info(
                "opa_evaluate_success",
                violations=len(raw_violations),
                effective_violations=len(effective_violations),
                excepted_violations=len(excepted_violations),
                compliant=len(compliant),
            )

            return {
                "violations": raw_violations,
                "effective_violations": effective_violations,
                "excepted_violations": excepted_violations,
                "compliant": compliant,
                "drift_exception_summary": drift_exception_summary,
                "metadata": {
                    "opa_server": self.config.server_url,
                    "policy_path": self.config.policy_path,
                    "fallback_mode": False,
                },
            }

        except requests.exceptions.RequestException as e:
            logger.error("opa_evaluate_failed", error=str(e), url=url)

            if self.config.fallback_on_error:
                logger.warning("opa_fallback_mode_activated")
                return self._fallback_decision(normalized_findings)
            else:
                raise

    def _fallback_decision(self, findings: dict[str, Any]) -> dict[str, Any]:
        """
        Mode dégradé si OPA est inaccessible.
        Stratégie conservatrice : tout marqué comme HIGH pour review manuel.
        """
        violations = [
            {
                "resource_id": f.get("address", "unknown"),
                "resource_type": f.get("type", "unknown"),
                "provider": f.get("provider_name"),
                "severity": "HIGH",
                "reason": "OPA server unavailable - conservative fallback applied",
                "action_required": "manual_review",
                "changed_paths": f.get("changed_paths", []),
                "custodian_policy": None,
                "original_actions": f.get("actions", []),
                "_fallback_item": f,
            }
            for f in findings.get("findings", [])
        ]

        return {
            "violations": violations,
            "effective_violations": violations,
            "excepted_violations": [],
            "compliant": [],
            "drift_exception_summary": {
                "total_exceptions_loaded": 0,
                "valid_exceptions": 0,
                "excepted_violations": 0,
            },
            "metadata": {
                "fallback_mode": True,
                "reason": "OPA server unreachable",
                "opa_server": self.config.server_url,
            },
        }
