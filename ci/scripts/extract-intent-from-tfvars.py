#!/usr/bin/env python3
"""
CloudSentinel CI — Intent Contract Extractor from .tfvars

Extrait le bloc ``resource_intent`` depuis un fichier terraform.ci.tfvars
et produit un stub JSON structuré compatible avec normalize.py
(``extract_intent_contract()``).

Utilisé par le job ``terraform-plan`` pour éviter toute dépendance au
backend azurerm ou aux credentials Azure dans le stage scan.
"""
import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional


def log(message: str) -> None:
    """Affiche un message structuré préfixé [intent-extract]."""
    print(f"[intent-extract] {message}", flush=True)


def parse_resource_intent(tfvars_path: str) -> Optional[Dict[str, str]]:
    """Parse le bloc resource_intent depuis un fichier .tfvars HCL.

    Supporte la syntaxe d'objet HCL utilisée dans terraform.ci.tfvars :

    .. code-block:: hcl

        resource_intent = {
          service_type   = "web-server"
          exposure_level = "internet-facing"
          owner          = "team-devops"
          approved_by    = "team-security"
        }

    Args:
        tfvars_path: Chemin vers le fichier ``terraform.ci.tfvars``.

    Returns:
        Dict avec les clés ``service_type``, ``exposure_level``, ``owner``,
        ``approved_by``. Retourne ``None`` si le bloc est absent ou incomplet
        (normalize.py générera alors ``MISSING_INTENT_CONTRACT``).
    """
    log(f"tfvars={tfvars_path}")
    path = Path(tfvars_path)

    if not path.is_file():
        log(f"ERROR fichier introuvable : {tfvars_path}")
        return None

    content = path.read_text(encoding="utf-8")

    # Cherche le bloc resource_intent = { ... }
    block_match = re.search(
        r"resource_intent\s*=\s*\{([^}]*)\}",
        content,
        re.DOTALL,
    )
    if not block_match:
        log("resource_intent absent du fichier tfvars")
        return None

    block_body = block_match.group(1)

    # Extrait les paires clé = "valeur" dans le bloc
    kv_pattern = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
    fields: Dict[str, str] = {
        m.group(1): m.group(2) for m in kv_pattern.finditer(block_body)
    }

    required = {"service_type", "exposure_level", "owner", "approved_by"}
    missing = required - fields.keys()
    if missing:
        log(f"WARNING champs manquants dans resource_intent : {sorted(missing)}")
        return None

    log(f"service_type={fields['service_type']}")
    log(f"exposure_level={fields['exposure_level']}")
    log(f"owner={fields['owner']}")
    log(f"approved_by={fields['approved_by']}")

    return {
        "service_type":   fields["service_type"],
        "exposure_level": fields["exposure_level"],
        "owner":          fields["owner"],
        "approved_by":    fields["approved_by"],
    }


def build_tfplan_stub(intent: Optional[Dict[str, str]], is_invalid: bool = False) -> Dict[str, Any]:
    stub: Dict[str, Any] = {
        "variables": {
            "resource_intent": {
                "value": intent,
            }
        }
    }
    if is_invalid:
        stub["_cloudsentinel_validation"] = {
            "validated_by": "extract-intent-from-tfvars.py",
            "violation": "INVALID_INTENT_CONTRACT"
        }
    return stub


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CloudSentinel \u2014 Extrait resource_intent depuis .tfvars vers un stub JSON"
    )
    parser.add_argument(
        "--tfvars",
        required=True,
        help="Chemin vers le fichier terraform.ci.tfvars",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Chemin de sortie pour le stub tfplan.json",
    )
    args = parser.parse_args()

    intent = parse_resource_intent(args.tfvars)
    is_invalid = False

    if intent is None:
        log("resource_intent absent \u2014 MISSING_INTENT_CONTRACT sera lev\u00e9 par normalize.py")
    else:
        violations = []
        st = intent.get("service_type", "").strip()
        el = intent.get("exposure_level", "").strip()
        ow = intent.get("owner", "").strip().lower()
        ab = intent.get("approved_by", "").strip().lower()

        if st not in {"web-server", "database", "cache", "worker", "gateway"}:
            violations.append(f"service_type invalide: {st}")
        if el not in {"internet-facing", "internal-only", "isolated"}:
            violations.append(f"exposure_level invalide: {el}")
        if st == "database" and el == "internet-facing":
            violations.append("database + internet-facing interdit")
        if ow == ab:
            violations.append("owner != approved_by requis (four-eyes)")

        if violations:
            log("Validation tfvars \u00e9chou\u00e9e:")
            for v in violations:
                log(f"  - {v}")
            intent = None
            is_invalid = True
        else:
            log("resource_intent extrait avec succ\u00e8s")

    stub = build_tfplan_stub(intent, is_invalid)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(stub, f, indent=2)

    log(f"output={args.output}")


if __name__ == "__main__":
    main()
