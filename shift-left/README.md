# 🔒 Shift-Left — Sécurité Pré-Déploiement

> **Phase 1** : Détection des vulnérabilités AVANT le déploiement dans le pipeline CI/CD

## 📐 Architecture

```
Poste Développeur            Pipeline CI/CD GitLab
     │                              │
     │                    ┌─────────┴─────────┐
     ▼                    │                   │
┌─────────┐          ┌────▼────┐  ┌───────┐  ┌──────┐
│Gitleaks │          │Gitleaks │  │Checkov│  │Trivy │
│Pre-Commit│         │         │  │ (IaC) │  │(Image)│
└─────────┘          └────┬────┘  └───┬───┘  └──┬───┘
                          │           │         │
                          └───────────┴─────────┘
                                   │
                          ┌────────▼─────────┐
                          │  Normalisation   │
                          │ & Enrichissement │
                          └────────┬─────────┘
                                   │
                          ┌────────▼─────────┐
                          │   Moteur OPA     │
                          │ Policies CIS/NSI │
                          └────────┬─────────┘
                                   │
                          ┌────────▼─────────┐
                          │  Quality Gate    │
                          │  ALLOW / DENY    │
                          └────────┬─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                 BLOCK          DEPLOY      DefectDojo
                                           (Findings)
```

## 🛠️ Composants

### 1. Pre-Commit Hook (Gitleaks)
- **Emplacement** : `shift-left/gitleaks/`
- **Fonction** : Détection locale des secrets avant le commit
- **Configuration** : `gitleaks.toml`

### 2. Scanners CI/CD (Parallèles)

#### Gitleaks - Secrets Detection
- **Détecte** : API keys, tokens, credentials, mots de passe
- **Format sortie** : JSON
- **Configuration** : `shift-left/gitleaks/gitleaks.toml`

#### Checkov - IaC Security
- **Détecte** : Misconfigurations Terraform, CloudFormation, Kubernetes
- **Framework** : CIS Benchmarks, NSI
- **Configuration** : `shift-left/checkov/.checkov.yml` (checks CloudSentinel uniquement)

#### Trivy - Vulnerability Scanner
- **Détecte** :
  - Vulnerabilités dans les images Docker
  - Dépendances vulnérables (CVE)
  - Misconfigurations IaC
- **Configuration** : `shift-left/trivy/configs/trivy.yaml`

### 3. Normalizer
- **Emplacement** : `shift-left/normalizer/`
- **Fonction** : Fusion des 3 rapports JSON en un format unifié
- **Enrichissement** :
  - Contexte (environnement, branche)
  - Exposition (publique/privée)
  - Métadonnées CI/CD
- **Script** : `normalize.sh`

### 4. Moteur OPA (Open Policy Agent)
- **Emplacement** : `policies/opa/`
- **Fonction** : Évaluation des policies et décision ALLOW/DENY
- **Policy** : `pipeline_decision.rego`
- **Règles** :
  - Blocage si secrets détectés (sauf whitelisted)
  - Blocage si CRITICAL ou HIGH > seuil
  - Contexte géographique et environnement
  - Exceptions par équipe (risk acceptance)

### 5. Quality Gate
- **Intégration** : GitLab CI/CD
- **Décision** :
  - `ALLOW` → Déploiement autorisé
  - `DENY` → Pipeline échoue, commentaire MR avec détails
- **Artifacts** : Export findings vers DefectDojo

## 📁 Structure

```
shift-left/
├── gitleaks/
│   ├── README.md
│   ├── gitleaks.toml           # Configuration Gitleaks
│   ├── .gitleaksignore         # Exceptions
│   └── pre-commit-hook.sh      # Hook Git (gitleaks seul)
│
├── pre-commit/
│   └── pre-commit.sh           # Hook Git (gitleaks + OPA advisory)
│
├── checkov/
│   ├── README.md
│   └── .checkov.yml            # Configuration Checkov
│
├── trivy/
│   ├── README.md
│   └── configs/
│       └── trivy.yaml          # Configuration Trivy
│
└── normalizer/
    ├── README.md
    ├── normalize.sh            # Script de normalisation
    └── schema/
        └── cloudsentinel_report.schema.json # Schéma JSON unifié
```

## 🚀 Mise en route locale

### Pre-commit unifiÃ© (Gitleaks + OPA advisory)
```bash
ln -sf ../../shift-left/pre-commit/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```
Par dÃ©faut, le mode local-fast ignore Checkov/Trivy pour Ã©viter le bruit.

### Formatage des configurations (TOML)
Pour garder un code propre et professionnel :
```bash
# Installation (Simple via npm)
npm install -g @taplo/cli

# OU via Cargo (si présent)
cargo install taplo-cli --locked

# Utilisation : Formater tous les fichiers .toml
taplo fmt
```

## 🚀 Utilisation

### Localement (Pre-Commit)
```bash
bash shift-left/pre-commit/pre-commit.sh
```

### Pipeline CI/CD
Exécution automatique dans `.gitlab-ci.yml` via le job `shift-left-scan` :
```yaml
shift-left-scan:
  stage: scan
  script:
    - bash shift-left/gitleaks/run-gitleaks.sh
    - bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET}"
    - bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "${TRIVY_SCAN_TYPE}"
```

### Test Manuel
```bash
# Depuis la racine du projet
make scan

# Orchestration complÃ¨te (scanners + normalisation + OPA advisory)
bash scripts/cloudsentinel-scan.sh
```

## 📊 Outputs

- **Rapport brut Gitleaks** : `.cloudsentinel/gitleaks_raw.json`
- **Rapport brut Checkov** : `.cloudsentinel/checkov_raw.json`
- **Rapport brut Trivy** : `shift-left/trivy/reports/raw/`
- **Rapport OPA-ready Gitleaks** : `.cloudsentinel/gitleaks_opa.json`
- **Rapport OPA-ready Checkov** : `.cloudsentinel/checkov_opa.json`
- **Rapport OPA-ready Trivy** : `.cloudsentinel/trivy_opa.json`
- **Rapport unifié** : `.cloudsentinel/golden_report.json`
- **Décision OPA (CI)** : `.cloudsentinel/opa_decision.json`
- **Décision OPA (local)** : `.cloudsentinel/opa_decision_precommit.json`
- **DefectDojo** : Findings importés automatiquement (CI)

## 🔑 Points Clés

✅ Détection **AVANT** déploiement  
✅ Scanners **parallèles** pour rapidité  
✅ **Normalisation** pour cohérence  
✅ **Policy-as-Code** pour décision automatisée  
✅ **Traçabilité** via DefectDojo  

## 📚 Documentation Associée

- [../docs/SHIFT_LEFT.md](../docs/SHIFT_LEFT.md) - Guide complet
- [../docs/POLICIES_GUIDE.md](../docs/POLICIES_GUIDE.md) - Création de policies
- [../policies/opa/README.md](../policies/opa/README.md) - Policies OPA
