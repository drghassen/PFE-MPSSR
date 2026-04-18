#!/usr/bin/env python3
"""
CloudSentinel CI — Intent Contract Validator
Valide la présence, la cohérence et l'intégrité du contrat d'intention
avant l'évaluation OPA. Bloquant (exit 1) sur toute violation.
"""
import argparse
import json
import sys

# ── Couleurs ANSI pour GitLab CI logs ────────────────────────────────────────
_CRITICAL = "\033[31m"   # Rouge
_HIGH     = "\033[33m"   # Jaune
_OK       = "\033[32m"   # Vert
_INFO     = "\033[34m"   # Bleu
_RESET    = "\033[0m"


def log(level: str, message: str) -> None:
    """Affiche un message préfixé [intent-contract][LEVEL] avec couleur ANSI."""
    color_map = {
        "CRITICAL": _CRITICAL,
        "HIGH":     _HIGH,
        "OK":       _OK,
        "INFO":     _INFO,
    }
    color = color_map.get(level.upper(), _RESET)
    print(f"{color}[intent-contract][{level.upper()}]{_RESET} {message}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CloudSentinel — Intent Contract Validator (CI job, blocking)"
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Chemin vers le Golden Report JSON produit par normalize.py",
    )
    args = parser.parse_args()

    # 1. Charger le Golden Report
    try:
        with open(args.report, encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        log("CRITICAL", f"Golden Report introuvable : {args.report}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log("CRITICAL", f"Golden Report JSON invalide : {e}")
        sys.exit(1)

    # 2. Afficher le header avec pipeline_id et commit_sha
    metadata = report.get("metadata", {})
    git_meta = metadata.get("git", {})
    pipeline_id = git_meta.get("pipeline_id", "local")
    commit_sha = git_meta.get("commit", "unknown")[:8]
    print("", flush=True)
    print("━" * 60, flush=True)
    log("INFO", f"Pipeline: {pipeline_id} | Commit: {commit_sha}")
    log("INFO", "Validation du contrat d'intention CloudSentinel...")
    print("━" * 60, flush=True)

    intent = report.get("intent_contract") or {}
    mismatches = report.get("intent_mismatches") or []

    # 3. Vérifier violation MISSING_INTENT_CONTRACT
    if intent.get("violation") == "MISSING_INTENT_CONTRACT":
        log("CRITICAL", "Intent contract ABSENT — aucun fichier intent.tf déployé ou tfplan.json manquant.")
        log("CRITICAL", "Tout déploiement sans déclaration d'intention est bloqué (MISSING_INTENT_CONTRACT).")
        log("CRITICAL", "→ Ajoutez resource_intent dans infra/azure/student-secure/intent.tf et re-lancez le pipeline.")
        sys.exit(1)

    # 4. Afficher les champs du contrat déclaré
    declared = intent.get("declared") or {}
    log("OK",   f"Contrat présent ✓")
    log("INFO",  f"  service_type   : {declared.get('service_type', 'N/A')}")
    log("INFO",  f"  exposure_level : {declared.get('exposure_level', 'N/A')}")
    log("INFO",  f"  owner          : {declared.get('owner', 'N/A')}")
    log("INFO",  f"  approved_by    : {declared.get('approved_by', 'N/A')}")

    # 5. Vérifier four-eyes : owner != approved_by
    owner       = (declared.get("owner") or "").strip().lower()
    approved_by = (declared.get("approved_by") or "").strip().lower()
    if owner and approved_by and owner == approved_by:
        log("CRITICAL", f"Four-eyes violation — owner et approved_by sont identiques : '{owner}'")
        log("CRITICAL", "Le propriétaire et l'approbateur DOIVENT être deux personnes distinctes.")
        sys.exit(1)

    # 6. Four-eyes validé
    log("OK", "Four-eyes validé ✓ (owner ≠ approved_by)")

    # 7. Aucun mismatch → pipeline OK
    if not mismatches:
        log("OK", "Aucun mismatch intention/réalité ✓")
        print("━" * 60, flush=True)
        sys.exit(0)

    # 8. Mismatches présents → afficher le détail et bloquer
    log("CRITICAL", f"{len(mismatches)} mismatch(es) détecté(s) — divergence intention/réalité :")
    print("", flush=True)
    for i, m in enumerate(mismatches, start=1):
        print(f"  [{i}] Rule           : {m.get('rule', 'N/A')}", flush=True)
        print(f"       Declared       : {m.get('declared', 'N/A')}", flush=True)
        print(f"       Observed       : {m.get('observed', 'N/A')}", flush=True)
        print(f"       MITRE          : {m.get('mitre', 'N/A')}", flush=True)
        findings = m.get("source_findings") or []
        if findings:
            fps = ", ".join(fp[:16] + "..." for fp in findings[:3])
            print(f"       Source findings: {fps}", flush=True)
        print("", flush=True)

    log("CRITICAL", "Divergence intention/réalité — pipeline bloqué avant évaluation OPA.")
    log("CRITICAL", "→ Corrigez la configuration IaC ou mettez à jour le contrat d'intention.")
    print("━" * 60, flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONNEMENT DU SYSTÈME INTENT CONTRACT
#
# Ce script est la 3ème ligne de défense de CloudSentinel contre le role spoofing :
#
# LIGNE 1 — Terraform validate (intent.tf)
#   Refuse dès terraform plan si database + internet-facing, ou owner == approved_by.
#   Aucun artifact généré, aucun CI déclenché.
#
# LIGNE 2 — normalize.py (extract_intent_contract + correlate_intent_vs_reality)
#   Extrait le contrat du tfplan.json, le confronte aux findings réels des scanners.
#   Génère des mismatches si divergence : service déclaré ≠ comportement réseau observé.
#   Exemple : web-server déclaré + port 5432 ouvert = CS-INTENT-ROLE-SPOOFING.
#
# LIGNE 3 — Ce script (contract-test-intent CI job)
#   Lit le Golden Report enrichi, vérifie la présence et la cohérence du contrat,
#   et bloque le pipeline avant qu'OPA soit même invoqué si violation détectée.
#
# LIGNE 4 — OPA policies/opa/gate (cloudsentinel.gate)
#   Règles multi-signaux non-waivable sur input.findings brut (pas effective_failed_findings).
#   Même avec une exception DefectDojo valide four-eyes, le deny persiste.
#   CS-INTENT-CONTRACT-MISSING et CS-MULTI-SIGNAL-ROLE-SPOOFING ne peuvent pas être exemptées.
#
# POURQUOI 4 LIGNES ET PAS UNE SEULE ?
#   Un attaquant interne peut contourner une couche isolée.
#   Contourner les 4 simultanément nécessite : modifier l'IaC ET bypasser Terraform
#   ET tromper les 3 scanners indépendants ET créer une exception valide four-eyes.
#   Chaque couche est indépendante — si l'une échoue, les autres tiennent.
#
# POURQUOI NON-WAIVABLE DANS OPA ?
#   Les règles normales OPA opèrent sur effective_failed_findings (findings après exceptions).
#   Les règles non_waivable lisent input.findings brut — jamais filtré par les exceptions.
#   Un attaquant qui crée une exception pour son finding Checkov CRITICAL ne bypasse pas
#   le Signal 3 de CS-MULTI-SIGNAL-ROLE-SPOOFING qui lit directement input.findings.
#
# MITRE ATT&CK MAPPING
#   CS-INTENT-ROLE-SPOOFING     → T1036 Masquerading
#   CS-INTENT-EXPOSURE-MISMATCH → T1048 Exfiltration Over Alternative Protocol
#   CS-INTENT-CONTRACT-MISSING  → T1562 Impair Defenses (absence délibérée de déclaration)
# ─────────────────────────────────────────────────────────────────────────────
