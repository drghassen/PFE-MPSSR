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

## 🛠️ Configuration

La configuration est volontairement séparée :

*   `.checkov.yml` : paramètres d'exécution uniquement (`framework`, `output`, `quiet`, `compact`, `soft-fail`).
*   `config/checkov-suppressions.yml` : suppressions scanner organisées par catégorie de gouvernance.
*   `.cloudsentinel/checkov.effective.yml` : fichier généré par le wrapper avant exécution de Checkov.

Les suppressions Checkov doivent rester limitées aux frontières de scope scanner, faux positifs et contraintes lab documentées. Les exceptions de risque métier passent par DefectDojo/OPA.

---

## 🚀 Utilisation

**Pipeline Manuelle (Admin) :**
```bash
# Scan complet du repository (tous les modules IaC découverts)
bash shift-left/checkov/run-checkov.sh "."
```

## 🚫 Rappel sur les Exemptions
**N'utilisez jamais `#checkov:skip` dans le code Terraform.**
Toutes les exceptions d'infrastructure doivent être auditées et justifiées dans DefectDojo, puis synchronisées dans `.cloudsentinel/exceptions.json` (Four-Eyes Principle). Le Checkov d'origine remontera l'erreur, et c'est le PDP OPA qui la contournera légalement.
