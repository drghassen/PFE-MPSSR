# 🧠 OPA (Open Policy Agent) — Le Moteur de Décision (PDP)

Ce répertoire héberge le **Policy Decision Point** (PDP) de CloudSentinel. Il orchestre l'évaluation algorithmique du `golden_report.json` produit par le Normalizer. L'absence de code impératif (Bash, Python) ici est volontaire ; la gouvernance de sécurité est **purement déclarative via Rego**.

---

## 🎯 Architecture et Rôle

Dans le pipeline CI, le script externe `../shift-left/opa/run-opa.sh` joue le rôle du PEP (Policy Enforcement Point). Il appelle **ce référentiel** et ses artefacts pour déterminer l'état d'un pipeline (`ALLOW` / `DENY`).

```text
  [ Golden Report JSON ]  ---------+
                                   | (Input OPA)
                                   v
             [ pipeline_decision.rego ] <-- Évalue les règles métier et les seuils
                                   ^
                                   | (Data OPA)
  [ exceptions.json ]  ------------+
```

## 📁 Contenu du Répertoire

*   `pipeline_decision.rego` : Core-logic. Définit les méthodes d'autorisation strictes, les règles de calcul de criticité `effective` (après déduction des exemptions) et la vérification des métadonnées CI.
*   `exceptions.json` : Fichier Data d'exemption. La **Gouvernance as Code**. Stocke les waivers de sécurité approuvés par l'équipe.
*   `test_pipeline_decision.rego` : La suite complète de tests de la Policy OPA simulant des centaines de cas (exemptions expirées, faux environment, etc.).

## 🛡️ Règles de blocage standards (`deny[]`)

La pipeline CI est bloquée (`allow == false`) par OPA si l'une des conditions suivantes est remplie :
1.  **`effective_critical > critical_max`** : (Ex: 0 Critical admis)
2.  **`effective_high > high_max`** : (Ex: 2 Highs admis)
3.  **Scanner manquant / Fausse exécution** : (`NOT_RUN`) Si un scanner plante ou si l'export normalisé le marque erroné.
4.  **Exemption mal-formée** : Si une exception dans `exceptions.json` est "enabled: true" mais ne respecte pas le Four-Eyes Principle (Demandeur = Approbateur), est manquante d'un `commit_hash`, ou si elle est autorisée avec l'état `CRITICAL` dans un contexte d'environnement `prod`.

---

## ✍️ Gestion des Exceptions (`exceptions.json`)

Le système d'exception PFE-CloudSentinel v5 intègre une architecture avancée de gestion des dettes techniques.

### Schéma d'une Exemption Valide :
```json
{
  "id": "EXC-2026-001",
  "enabled": true,                  // Doit être "true" pour être évaluée
  "tool": "checkov",                // Outil source du finding
  "rule_id": "CKV2_CS_AZ_003",      // ID de la règle déclenchée
  "resource_path": "/main.tf",      // Fichier ciblé (supporte "canonical_path")
  "environments": ["dev"],          // Environnement concerné UNIQUEMENT
  "max_severity": "HIGH",           // Ne pas laisser passer si ça s'aggrave
  "reason": "Emergency unblock",
  "ticket": "SEC-0001",
  "requested_by": "dev@example.com",
  "approved_by": "sec@example.com", // DIFFÉRENT du requested_by
  "commit_hash": "a1b2c3d4",
  "expires_at": "2026-02-24T10:00:00Z" // Temps maximal accordé (RFC3339)
}
```

> [!CAUTION]
> Une exemption pour la production (`"environments": ["prod"]`) ne peut JAMAIS accepter un `max_severity: "CRITICAL"`. OPA refusera la policy par sécurité.

---

## 🧪 Tests Unitaires OPA

L'assurance qualité de l'engine OPA est critique. Les tests tournent sans réseau ni dépendance et valident ~50 scénarios de bord.

```bash
# Lancer les tests
opa test policies/opa/ -v

# Vérification du coverage (couverture)
opa test policies/opa/ --coverage --format json | jq .
```
