# CloudSentinel normalizer — shared constants.
# DB_PORTS must stay in sync with db_ports in policies/opa/gate/gate_context.rego.

from __future__ import annotations

from typing import Dict

# DB_PORTS : ports associés aux moteurs de base de données courants.
# Utilisé par correlate_intent_vs_reality() pour détecter le pattern CS-INTENT-ROLE-SPOOFING.
# DevSecOps contract : constante immuable, jamais surchargeable via env vars.
DB_PORTS: frozenset = frozenset({3306, 5432, 27017, 1433, 6379, 5984, 9042, 2181})

DEFAULT_SEV_LUT: Dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "SEV5": "CRITICAL",
    "SEVERITY5": "CRITICAL",
    "VERY_HIGH": "CRITICAL",
    "HIGH": "HIGH",
    "SEV4": "HIGH",
    "SEVERITY4": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "SEV3": "MEDIUM",
    "SEVERITY3": "MEDIUM",
    "LOW": "LOW",
    "MINOR": "LOW",
    "SEV2": "LOW",
    "SEVERITY2": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "SEV1": "INFO",
    "SEVERITY1": "INFO",
    "UNKNOWN": "INFO",
}

DEFAULT_SLA: Dict[str, int] = {
    "CRITICAL": 24,
    "HIGH": 168,
    "MEDIUM": 720,
    "LOW": 2160,
    "INFO": 8760,
}

# Confidence map: deterministic, scanner-type-based.
# DevSecOps contract: confidence MUST be set here, NEVER recomputed downstream.
# Invariant: local == CI (no runtime dependency, no env var influence).
DEFAULT_CONFIDENCE_MAP: Dict[str, str] = {
    "gitleaks": "HIGH",
    "checkov": "MEDIUM",
    "trivy": "HIGH",
    # cloud-init scanner: static analysis of Terraform HCL + YAML cloud-init payloads.
    # Confidence is HIGH: patterns are deterministic (regex + YAML parse), not heuristic.
    "cloudinit": "HIGH",
}
