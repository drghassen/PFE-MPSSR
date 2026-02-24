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
│  OPA (CLI, advisory)                                                  │
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
- OPA CLI affiche la décision mais ne bloque pas.

## Chaîne CI/CD (Enforce)
- `shift-left/gitleaks/run-gitleaks.sh`
- `shift-left/checkov/run-checkov.sh`
- `shift-left/trivy/scripts/run-trivy.sh`
- `shift-left/normalizer/normalize.sh` (mode=ci)
- `shift-left/opa/run-opa.sh --enforce` (via OPA Server)

## Artifacts Générés
- `.cloudsentinel/gitleaks_opa.json`
- `.cloudsentinel/checkov_opa.json`
- `shift-left/trivy/reports/opa/trivy_opa.json`
- `.cloudsentinel/golden_report.json`
- `.cloudsentinel/opa_decision.json` (CI)
- `.cloudsentinel/opa_decision_precommit.json` (local)
