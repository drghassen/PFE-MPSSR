# 📜 Policies — Policy as Code (Le Cœur Décisionnel)

> **Gouvernance Automatisée** : Des décisions logiques déclaratives déconnectées de l'exécution.

Ce répertoire centralise toutes les règles de sécurité, de conformité et de gouvernance utilisées par la plateforme CloudSentinel (Shift-Left & Shift-Right).

---

## 📁 Architecture des Policies

Le projet distingue explicitement deux phases d'évaluation :

```text
policies/
├── opa/                            # Phase 1 : Shift-Left (Pré-déploiement)
│   ├── README.md                   # Documentation OPA détaillée
│   ├── pipeline_decision.rego      # Le Policy Decision Point (PDP) principal
│   ├── test_pipeline_decision.rego # Suite de tests unitaires OPA
│   ├── exceptions.json             # Fichier de gouvernance (Exemptions auditées)
│   └── examples/                   # Cas d'usage et inputs factices pour tests
│
└── custodian/                      # Phase 2 : Shift-Right (Post-déploiement)
    ├── README.md                   # Documentation Cloud Custodian
    ├── azure/                      # Modules de remédiation Runtime (Azure)
    │   ├── compute-security.yml    # Règles ciblant les VMs
    │   ├── network-security.yml    # Règles ciblant les NSGs et VNETs
    │   └── storage-security.yml    # Règles ciblant les Storage Accounts
    └── aws/                        # Modules futurs pour multicloud
```

---

## 🎯 1. Open Policy Agent (OPA) — Shift-Left

**Rôle** : Reçoit le "Golden Report" généré par le Normalizer, applique **exclusivement** les règles métier, traite les `exceptions.json`, et retourne une décision `ALLOW` ou `DENY` stricte.

### Flux de Décision (PDP)
La logique `pipeline_decision.rego` ingère un compte-rendu consolidé (Gitleaks, Checkov, Trivy) et détermine :
- Les quotas de tolérance (ex: `critical_max: 0`, `high_max: 2`).
- Les exemptions conditionnées (environnement de dev, approbateurs distincts, limites temporelles).
- Un refus total et non négociable sur un scan échoué (binaire introuvable, json mal-formé).

### Évaluation Locale (Advisory vs Enforce)
*   **Advisory** : Évalue et prévient (Code source `allow == false` avec avertissement). Toujours l'état sur le poste du développeur.
*   **Enforcement** : Coupe la pipeline CI/CD en cas de violation ou si aucune politique d'exception valide et en cours d’exécution ne matche les findings.

---

## ☁️ 2. Cloud Custodian — Shift-Right

**Rôle** : Exécute de la remédiation réactive et déclarative directement sur l'infrastructure cloud cible. Garantit l'alignement sur ce qui a passé la phase Shift-Left.

### Concept (Azure Policies)
Custodian interagit directement avec l'API Azure Resource Manager pour identifier les "drifts" (décalages entre le modèle Infra-as-Code et l'état déployé).

Exemple (Storage) :
*   Si un storage est créé avec le flag `publicNetworkAccess: Enabled`.
*   Action: Custodian applique le webhook et écrase dynamiquement le tag/paramètre à `Disabled`.

---

## 🔑 Règles de Gouvernance (Conformité PFE)

1.  **Immuabilité** : Le code de politique doit être traité avec la même rigueur que le code de production (`test_*.rego` obligatoire pour tout ajout sur Pipeline Decision).
2.  **Four-Eyes Principle** : Le `exceptions.json` exige qu'un "requested_by" soit systématiquement différent du "approved_by" sous peine d'invalider explicitement l'exemption.
3.  **Maturité d'Exceptions** : Toute politique d'exigence (`enabled: true`) doit porter un `expires_at` (format ISO8601).
4.  **Tests Unitaires** : Tester localement via la pipeline `make test-opa` après la moindre retouche.

---

## 📚 Liens Complémentaires

*   **Détails OPA** : [opa/README.md](opa/README.md)
*   **Détails Custodian** : [custodian/README.md](custodian/README.md)
*   Documentation Principale : [../docs/POLICIES_GUIDE.md](../docs/POLICIES_GUIDE.md)
