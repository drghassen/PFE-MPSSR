# SHIFT-LEFT — CloudSentinel

## Objectif
Détecter tôt, corriger vite. En local on informe (advisory), en CI/CD on bloque (enforce).

## Schéma Global (ASCII)

```
LOCAL (Pre-commit / Advisory)
┌───────────────────────────────────────────────────────────────────────┐
│ Dev machine                                                           │
│                                                                       │
│  git commit                                                           │
│     │                                                                 │
│     ▼                                                                 │
│  gitleaks (staged)                                                    │
│     │  -> .cloudsentinel/gitleaks_opa.json                            │
│     ▼                                                                 │
│  normalizer (local-fast)                                              │
│     │  -> .cloudsentinel/golden_report.json                           │
│     ▼                                                                 │
│  OPA (server preferred, CLI fallback, advisory)                       │
│     │  -> .cloudsentinel/opa_decision_precommit.json                  │
│     ▼                                                                 │
│  commit continues                                                     │
└───────────────────────────────────────────────────────────────────────┘

CI/CD (Enforce)
┌───────────────────────────────────────────────────────────────────────┐
│ GitLab CI                                                             │
│                                                                       │
│  gitleaks + checkov + trivy                                            │
│     │  -> reports OPA-ready                                            │
│     ▼                                                                 │
│  normalizer (mode=ci)                                                 │
│     │  -> .cloudsentinel/golden_report.json                           │
│     ▼                                                                 │
│  OPA Server (PDP)                                                     │
│     │  -> .cloudsentinel/opa_decision.json                            │
│     ▼                                                                 │
│  ALLOW -> deploy  |  DENY -> pipeline blocked                          │
└───────────────────────────────────────────────────────────────────────┘
```

## Chaîne Locale (Advisory)
- Script: `shift-left/pre-commit/pre-commit.sh`
- Gitleaks scanne uniquement les fichiers staged.
- Normalizer ignore Checkov/Trivy en local (local-fast).
- OPA advisory (server préféré, CLI fallback) affiche la décision mais ne bloque pas.

## Chaîne CI/CD (Enforce)
- `shift-left/gitleaks/run-gitleaks.sh`
- `shift-left/checkov/run-checkov.sh`
- `shift-left/trivy/scripts/run-trivy.sh`
- `ci/scripts/*.sh` wrappers (orchestration GitLab)
- `ci/libs/cloudsentinel_contracts.py` (merge Trivy + validations de contrat/schéma)
- `shift-left/normalizer/normalize.py` (mode=ci)
- `CLOUDSENTINEL_SCHEMA_STRICT=true` en CI (validation schema obligatoire)
- `shift-left/opa/run-opa.sh --enforce` (via OPA Server)

## Artifacts Générés
- `.cloudsentinel/gitleaks_opa.json`
- `.cloudsentinel/checkov_opa.json`
- `.cloudsentinel/trivy_opa.json`
- `.cloudsentinel/golden_report.json`
- `.cloudsentinel/opa_decision.json` (CI)
- `.cloudsentinel/opa_decision_precommit.json` (local)

## Gouvernance & rôles (RACI résumé)
- **Qui écrit les policies ?** Équipe SecOps / AppSec (owner) ; revue par Cloud/Platform (consulted).
- **Qui valide les exceptions ?** AppSec + Risk Owner du produit ; approbation obligatoire (champ `approved_by`) et ticket de suivi.
- **Qui accepte le risque ?** Product / Engineering Manager responsable de l’environnement ciblé (dev/test/prod).
- **Qui déclenche la remédiation automatique ?** Platform/DevOps via pipelines (`deploy-infrastructure`) lorsque OPA renvoie ALLOW ; en cas de DENY, l’équipe projet corrige ou demande exception.
- **Qui peut bypass ?** Personne côté scanners (exit 0). Seule OPA peut autoriser/denier ; les bypass passent par une exception OPA signée et datée, jamais par `|| true` ou désactivation de job.

## Matrice environnements / branches
- **dev / feature branches** : OPA enforce avec seuils `CRITICAL_MAX=0` / `HIGH_MAX=2`, exceptions possibles et limitées dans le temps.
- **staging** : mêmes seuils, exceptions plus restreintes (max_severity ≠ CRITICAL recommandé).
- **prod / main** : tolérance minimale, exceptions CRITICAL refusées par policy, audit obligatoire. Bypass uniquement via exception formelle OPA.

## Traçabilité
- `quality_gate.thresholds` dans `golden_report.json` rend visibles les seuils utilisés pour la décision.
- `opa_decision.json` contient l’empreinte de la policy, les exceptions appliquées, l’horodatage et l’engine (server/cli) pour audit.
