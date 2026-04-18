"""Terraform intent contract extraction and correlation with scanner findings."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from cs_norm_constants import DB_PORTS

logger = logging.getLogger("cloudsentinel.normalizer")


class NormalizerIntentMixin:
    def extract_intent_contract(self, terraform_plan_path: str) -> Dict[str, Any]:
        """Extrait le contrat d'intention depuis un fichier JSON issu de `terraform show -json`.

        Cherche la clé ``variables.resource_intent.value`` dans le plan Terraform.

        Retourne :
          - ``{"declared": <dict resource_intent>, "violation": None}`` si le contrat est présent
            et valide.
          - ``{"declared": None, "violation": "MISSING_INTENT_CONTRACT"}`` si le fichier est absent,
            non lisible, ou ne contient pas la clé ``resource_intent``. Ce cas déclenche
            ``CS-INTENT-CONTRACT-MISSING`` dans OPA (deny CRITICAL, non_waivable).

        Args:
            terraform_plan_path: Chemin vers le fichier JSON produit par
                ``terraform show -json <planfile>``.
        """
        logger.info("[intent] Lecture contrat : %s", terraform_plan_path)
        p = Path(terraform_plan_path)
        _missing: Dict[str, Any] = {"declared": None, "violation": "MISSING_INTENT_CONTRACT"}

        if not p.is_file():
            logger.error("[intent] \u274c tfplan.json introuvable : %s", terraform_plan_path)
            return _missing

        try:
            with p.open("r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            logger.error("[intent] \u274c JSON invalide : %s", e)
            return _missing

        if not isinstance(doc, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        variables = doc.get("variables")
        if not isinstance(variables, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        intent_raw = variables.get("resource_intent")
        if not isinstance(intent_raw, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        # `terraform show -json` encapsule la valeur dans {"value": {...}}
        value = intent_raw.get("value")
        if not isinstance(value, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        required_keys = {"service_type", "exposure_level", "owner", "approved_by"}
        if not required_keys.issubset(value.keys()):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        declared = {
            "service_type":   str(value.get("service_type", "")).strip(),
            "exposure_level": str(value.get("exposure_level", "")).strip(),
            "owner":          str(value.get("owner", "")).strip(),
            "approved_by":    str(value.get("approved_by", "")).strip(),
        }
        
        if not all(declared.values()):
            logger.error("[intent] \u274c champs vides dans intent_contract")
            return {"declared": None, "violation": "EMPTY_INTENT_CONTRACT_FIELDS"}

        logger.info(
            "[intent] \u2705 Contrat extrait \u2014 service_type=%s exposure=%s",
            declared["service_type"],
            declared["exposure_level"],
        )
        return {"declared": declared, "violation": None}

    def correlate_intent_vs_reality(self, intent: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Corrèle le contrat d'intention déclaré avec les findings normalisés des scanners.

        Détecte deux patterns de role spoofing :

        **Pattern 1 — CS-INTENT-ROLE-SPOOFING** (MITRE T1036 - Masquerading) :
          Une ressource déclarée ``web-server`` présente des ports de base de données
          dans les findings. Indique qu'une DB est déployée sous couvert d'un serveur web.

        **Pattern 2 — CS-INTENT-EXPOSURE-MISMATCH** (MITRE T1048 - Exfiltration Over Alternative Protocol) :
          Une ressource déclarée ``internal-only`` présente une IP publique ou une règle
          ``0.0.0.0/0`` dans les findings. Indique une exposition Internet non déclarée.

        Args:
            intent: Résultat de ``extract_intent_contract()`` (champ ``declared`` requis).
            findings: Liste des findings normalisés du Golden Report (post-``_dedup``).

        Returns:
            Liste d'objets ``intent_mismatch``. Vide si aucun écart n'est détecté.
        """
        logger.info("[correlate] Corrélation sur %d findings...", len(findings))
        declared = intent.get("declared") if isinstance(intent, dict) else None
        if not isinstance(declared, dict):
            return []

        service_type = str(declared.get("service_type", "")).strip().lower()
        exposure_level = str(declared.get("exposure_level", "")).strip().lower()
        mismatches: List[Dict[str, Any]] = []

        # Pré-calcul des champs textuels utiles pour la détection, une seule passe.
        def _finding_text(f: Dict[str, Any]) -> str:
            return " ".join([
                str(f.get("description", "")),
                str((f.get("source") or {}).get("id", "")),
                str((f.get("resource") or {}).get("name", "")),
                str((f.get("resource") or {}).get("path", "")),
            ])

        def _finding_fingerprint(f: Dict[str, Any]) -> str:
            return str((f.get("context") or {}).get("deduplication", {}).get("fingerprint", f.get("id", "")))

        # ── Pattern 1 : CS-INTENT-ROLE-SPOOFING ──────────────────────────────
        if service_type == "web-server":
            db_port_findings: List[Dict[str, Any]] = []
            detected_ports: set = set()

            for f in findings:
                if str(f.get("status", "FAILED")).upper() != "FAILED":
                    continue
                text = _finding_text(f)
                for m in re.finditer(r"\b(\d{2,5})\b", text):
                    port = int(m.group(1))
                    if port in DB_PORTS:
                        db_port_findings.append(f)
                        detected_ports.add(port)
                        break  # un port DB suffit pour qualifier ce finding

            if db_port_findings:
                _observed = f"db_ports_detected={{{', '.join(str(p) for p in sorted(detected_ports))}}}"
                logger.warning(
                    "[correlate] \u26a0\ufe0f  %s \u2014 déclaré: '%s' observé: '%s' MITRE: %s",
                    "CS-INTENT-ROLE-SPOOFING",
                    "service_type=web-server",
                    _observed,
                    "T1036 - Masquerading",
                )
                mismatches.append({
                    "rule":     "CS-INTENT-ROLE-SPOOFING",
                    "severity": "CRITICAL",
                    "declared": "service_type=web-server",
                    "observed": _observed,
                    "mitre":    "T1036 - Masquerading",
                    "source_findings": [_finding_fingerprint(f) for f in db_port_findings],
                })

        # ── Pattern 2 : CS-INTENT-EXPOSURE-MISMATCH ─────────────────────────
        if exposure_level == "internal-only":
            _PUBLIC_SIGNALS = re.compile(
                r"public[_\s]?ip|0\.0\.0\.0/0|0\.0\.0\.0",
                re.IGNORECASE,
            )
            exposure_findings: List[Dict[str, Any]] = []

            for f in findings:
                if str(f.get("status", "FAILED")).upper() != "FAILED":
                    continue
                text = _finding_text(f)
                if _PUBLIC_SIGNALS.search(text):
                    exposure_findings.append(f)

            if exposure_findings:
                logger.warning(
                    "[correlate] \u26a0\ufe0f  %s \u2014 déclaré: '%s' observé: '%s' MITRE: %s",
                    "CS-INTENT-EXPOSURE-MISMATCH",
                    "exposure_level=internal-only",
                    "public_ip_or_open_cidr_detected",
                    "T1048 - Exfiltration Over Alternative Protocol",
                )
                mismatches.append({
                    "rule":     "CS-INTENT-EXPOSURE-MISMATCH",
                    "severity": "HIGH",
                    "declared": "exposure_level=internal-only",
                    "observed": "public_ip_or_open_cidr_detected",
                    "mitre":    "T1048 - Exfiltration Over Alternative Protocol",
                    "source_findings": [_finding_fingerprint(f) for f in exposure_findings],
                })

        if mismatches:
            logger.info("[correlate] %d mismatch(es) détecté(s)", len(mismatches))
        else:
            logger.info("[correlate] \u2705 Aucun mismatch")
        return mismatches
