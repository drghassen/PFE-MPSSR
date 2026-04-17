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
import sys
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


def build_tfplan_stub(intent: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """Construit un stub JSON minimal compatible avec normalize.py.

    ``extract_intent_contract()`` dans normalize.py attend la structure :

    .. code-block:: json

        {
          "variables": {
            "resource_intent": {
              "value": { "service_type": "...", ... }
            }
          }
        }

    Si ``intent`` est ``None``, ``value`` est ``null`` — ce qui déclenche
    ``MISSING_INTENT_CONTRACT`` dans normalize.py puis deny OPA CRITICAL.

    Args:
        intent: Dict des champs resource_intent, ou ``None`` si absent.

    Returns:
        Dict structuré comme un ``terraform show -json`` partiel.
    """
    return {
        "variables": {
            "resource_intent": {
                "value": intent,
            }
        }
    }


def main() -> None:
    """Point d'entrée : parse les arguments, extrait le contrat, écrit le JSON."""
    parser = argparse.ArgumentParser(
        description="CloudSentinel — Extrait resource_intent depuis .tfvars vers un stub JSON"
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

    if intent is None:
        log("resource_intent absent — MISSING_INTENT_CONTRACT sera levé par normalize.py")
    else:
        log("resource_intent extrait avec succès")

    stub = build_tfplan_stub(intent)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(stub, f, indent=2)

    log(f"output={args.output}")


if __name__ == "__main__":
    main()
