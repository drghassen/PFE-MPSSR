# 🏛️ Checkov — Scanner d'Infrastructure as Code (IaC)

> **Cloud Infrastructure Security** : Scanne les modules Terraform (et Kubernetes/ARM) à la recherche de misconfigurations, avant leur application.

Checkov est le composant de Tier-2 du pipeline Shift-Left. Il analyse les définitions `.tf` pour s'assurer de leur conformité avec les standards de sécurité (CIS Benchmarks, CloudSentinel Rules).

---

## 📐 Architecture du Wrapper (V5.0)

La philosophie de CloudSentinel interdit aux scanners de configurer des "soft-fails" ou des exceptions locales (`#checkov:skip`). Le wrapper `run-checkov.sh` impose un cadre d'exécution strict :

1.  **Délégation OPA** : Convertit le rapport Checkov en format Golden Report pré-normalisé (`checkov_opa.json`). Gère les "Checks Failed" sans crasher le job (Exit 0 métier).
2.  **Mapping Standardisé** : Le fichier externe `mapping.json` assigne un niveau de sévérité OPA (`CRITICAL`, `HIGH`, `MEDIUM`, etc.) aux identifiants obscurs de Checkov (ex: `CKV_AZURE_35`).
3.  **Filtrage Intelligent** : Seuls les identifiants préfixés par des patterns reconnus par le projet (`CKV2_CS_AZ_`, `CKV_AZURE_`, `CKV_K8S_`) sont conservés pour éviter le bruit.
4.  **Supply Chain Protection** : En CI, le binaire Checkov `wheel` est vérifié par SHA256 avant d'être injecté dans l'environnement Python.

---

## 🛠️ Configuration (`.checkov.yml`)

Checkov dispose de beaucoup d'options globales, forcées via notre `.checkov.yml` :
*   `skip-check` : Les règles ignorées de base par l'entreprise (non gérées via OPA car non pertinentes au contexte).
*   `framework` : Restreint à Terraform et Kubernetes.
*   `output` : JSON strict + Compact output pour les logs CI.

---

## 🚀 Utilisation

**Pipeline Manuelle (Admin) :**
```bash
# Nécessite SCAN_TARGET défini (Chemin vers l'IaC Terraform)
bash shift-left/checkov/run-checkov.sh "infra/azure/dev"
```

## 🚫 Rappel sur les Exemptions
**N'utilisez jamais `#checkov:skip` dans le code Terraform.**
Toutes les exceptions d'infrastructure doivent être auditées et justifiées dans le registre centralisé `policies/opa/exceptions.json` (Four-Eyes Principle). Le Checkov d'origine remontera l'erreur, et c'est le PDP OPA qui la contournera légalement.
