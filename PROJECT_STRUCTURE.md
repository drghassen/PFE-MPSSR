# 📂 CloudSentinel - Structure Complète du Projet

> Vue d'ensemble de l'organisation du workspace professionnel

## 🌳 Arborescence Complète

```
pfe-cloud-sentinel/
│
├── 📄 README.md                    # Documentation principale
├── 🔧 Makefile                     # Commandes pratiques
├── 🌍 .env.template                # Template variables d'environnement
├── 🚫 .gitignore                   # Exclusions Git (sécurité)
├── 🔄 .gitlab-ci.yml               # Pipeline GitLab CI/CD
│
├── 📖 docs/                        # DOCUMENTATION
│   ├── README.md
│   ├── ARCHITECTURE.md             # (À créer) Architecture détaillée
│   ├── INSTALLATION.md             # (À créer) Guide installation
│   ├── SHIFT_LEFT.md               # (À créer) Doc Shift-Left
│   ├── SHIFT_RIGHT.md              # (À créer) Doc Shift-Right
│   ├── GOVERNANCE.md               # (À créer) DefectDojo & Dashboard
│   ├── POLICIES_GUIDE.md           # (À créer) Guide policies
│   └── TOOLS_REFERENCE.md          # (À créer) Référence outils
│
├── 🔒 shift-left/                  # PHASE 1: Pré-Déploiement
│   ├── README.md                   # ✅ Créé
│   ├── gitleaks/
│   │   ├── README.md               # ✅ Créé
│   │   ├── gitleaks.toml           # ✅ Config Gitleaks
│   │   ├── .gitleaksignore         # ✅ Exceptions
│   │   └── pre-commit-hook.sh      # Hook Git (gitleaks seul)
│   ├── pre-commit/
│   │   └── pre-commit.sh           # ✅ Hook Git (gitleaks + OPA advisory)
│   ├── checkov/
│   │   ├── README.md               # ✅ Créé
│   │   └── .checkov.yml            # ✅ Config Checkov
│   ├── trivy/
│   │   ├── README.md               # ✅ Créé
│   │   └── configs/
│   │       └── trivy.yaml          # ✅ Config Trivy
│   └── normalizer/
│       ├── README.md               # ✅ Créé
│       ├── normalize.sh            # ✅ Script normalisation
│       └── schema/
│           └── cloudsentinel_report.schema.json # ✅ Schéma JSON
│
├── 🔍 shift-right/                 # PHASE 2: Runtime Monitoring
│   ├── README.md                   # ✅ Créé
│   ├── prowler/
│   │   ├── README.md               # (À créer)
│   │   ├── config-azure.yaml       # (À créer) Config Prowler
│   │   └── run-prowler.sh          # (À créer) Script exécution
│   ├── event-collection/
│   │   ├── README.md               # (À créer)
│   │   ├── azure-eventgrid-setup.md # (À créer) Guide Event Grid
│   │   └── event-processor.py      # (À créer) Processeur events
│   └── drift-engine/
│       ├── README.md               # (À créer)
│       ├── detect-drift.py         # (À créer) Détection drift
│       ├── compare-state.py        # (À créer) Comparateur
│       └── requirements.txt        # (À créer)
│
├── 📜 policies/                    # POLICIES AS CODE
│   ├── README.md                   # ✅ Créé
│   ├── opa/
│   │   ├── README.md               # ✅ Créé
│   │   ├── pipeline_decision.rego  # ✅ Existe
│   │   ├── test_pipeline_decision.rego # ✅ Créé
│   │   └── exceptions.json         # ✅ Créé
│   └── custodian/
│       ├── README.md               # (À créer)
│       ├── azure/
│       │   ├── README.md           # (À créer)
│       │   ├── storage-security.yml # (À créer)
│       │   ├── network-security.yml # (À créer)
│       │   └── compute-security.yml # (À créer)
│       └── aws/
│           └── README.md           # (À créer - Future)
│
├── 🏗️ infra/                       # INFRASTRUCTURE AS CODE
│   ├── README.md                   # ✅ Créé
│   ├── azure/
│   │   ├── README.md               # (À créer)
│   │   ├── dev/
│   │   │   ├── main.tf             # ✅ Existe
│   │   │   ├── variables.tf        # (À créer)
│   │   │   ├── outputs.tf          # (À créer)
│   │   │   ├── providers.tf        # (À créer)
│   │   │   └── terraform.tfvars.template # (À créer)
│   │   └── modules/
│   │       ├── README.md           # (À créer)
│   │       ├── resource-group/     # (À créer)
│   │       ├── storage/            # (À créer)
│   │       ├── network/            # (À créer)
│   │       └── compute/            # (À créer)
│   └── aws/
│       └── README.md               # (À créer - Future)
│
├── 🔄 ci/                          # CI/CD SCRIPTS
│   ├── README.md                   # ✅ Créé
│   └── scripts/
│       ├── run-scanners.sh         # (À créer)
│       └── upload-to-defectdojo.sh # (À créer)
│
├── 📊 defectdojo/                  # GOUVERNANCE
│   ├── README.md                   # ✅ Créé
│   ├── docker-compose.yml          # (À créer)
│   ├── setup-engagements.py        # (À créer)
│   ├── import-findings.py          # (À créer)
│   └── requirements.txt            # (À créer)
│
├── 📈 monitoring/                  # DASHBOARD
│   ├── README.md                   # ✅ Créé
│   ├── docker-compose.yml          # (À créer)
│   ├── grafana/
│   │   ├── dashboards/
│   │   │   ├── overview.json       # (À créer)
│   │   │   ├── shift-left.json     # (À créer)
│   │   │   └── shift-right.json    # (À créer)
│   │   ├── datasources/
│   │   │   └── prometheus.yml      # (À créer)
│   │   └── provisioning/           # (À créer)
│   └── prometheus/
│       ├── prometheus.yml          # (À créer)
│       └── alerts/
│           └── security-alerts.yml # (À créer)
│
├── 🧪 tests/                       # TESTS & VALIDATION
│   ├── README.md                   # ✅ Créé
│   ├── vulnerable-samples/
│   │   ├── README.md               # (À créer)
│   │   ├── secrets.tf              # (À créer)
│   │   ├── insecure-storage.tf     # (À créer)
│   │   ├── open-ports.tf           # (À créer)
│   │   └── Dockerfile.vulnerable   # (À créer)
│   ├── opa-tests/
│   │   ├── README.md               # (À créer)
│   │   └── test-cases/             # (À créer)
│   └── e2e/
│       ├── README.md               # (À créer)
│       └── test-full-pipeline.sh   # (À créer)
│
└── 🛠️ scripts/                     # SCRIPTS UTILITAIRES
    ├── run_prod_pipeline.sh        # ✅ Existe
    ├── cloudsentinel-scan.sh        # ✅ Orchestrateur scan local
    ├── setup-dev-env.sh            # (À créer - Important)
    ├── cleanup.sh                  # (À créer)
    ├── gitleaks.json               # ⚠️ À supprimer (gitignored)
    └── opa_input.json              # ⚠️ À supprimer (gitignored)
```

---

## 📊 État d'Avancement

### ✅ Terminé
- [x] Structure de répertoires complète
- [x] README.md principal
- [x] .gitignore (sécurité)
- [x] .env.template
- [x] .gitlab-ci.yml (Pipeline CI/CD complet)
- [x] Makefile (40+ commandes)
- [x] README de chaque section majeure:
  - docs/
  - shift-left/
  - shift-right/
  - policies/
  - infra/
  - defectdojo/
  - monitoring/
  - tests/
  - ci/

### 🔨 À Implémenter (Phase 2)

#### Configuration Files
- [x] shift-left/checkov/.checkov.yml
- [ ] policies/custodian/azure/*.yml
- [ ] infra/azure/dev/*.tf (compléter)
- [ ] defectdojo/docker-compose.yml
- [ ] monitoring/docker-compose.yml

#### Scripts
- [ ] shift-right/prowler/run-prowler.sh
- [ ] shift-right/drift-engine/detect-drift.py
- [ ] ci/scripts/run-scanners.sh
- [ ] ci/scripts/upload-to-defectdojo.sh
- [ ] defectdojo/setup-engagements.py
- [ ] scripts/setup-dev-env.sh (prioritaire)
- [ ] scripts/cleanup.sh

#### Documentation Détaillée
- [ ] docs/ARCHITECTURE.md
- [ ] docs/INSTALLATION.md
- [ ] docs/SHIFT_LEFT.md
- [ ] docs/SHIFT_RIGHT.md
- [ ] docs/GOVERNANCE.md
- [ ] docs/POLICIES_GUIDE.md

#### Tests & Samples
- [ ] tests/vulnerable-samples/*.tf
- [ ] tests/opa-tests/test-cases/
- [ ] tests/e2e/test-full-pipeline.sh

---

## 🎯 Priorités Recommandées

### 1️⃣ Priorité HAUTE (Démarrage)
1. `scripts/setup-dev-env.sh` - Setup automatisé
2. `docs/INSTALLATION.md` - Guide installation
3. Configuration tools shift-left (`.checkov.yml`)

### 2️⃣ Priorité MOYENNE (Implémentation)
1. Normalizer Python script
2. Terraform modules (infra/azure/)
3. Policies Cloud Custodian
4. DefectDojo setup

### 3️⃣ Priorité BASSE (Finitions)
1. Dashboard Grafana
2. Tests E2E
3. Documentation approfondie

---

## 🔑 Commandes Clés

### Démarrage
```bash
make setup          # Installation complète
make config         # Créer .env
```

### Développement
```bash
make scan           # Exécuter shift-left
make test           # Tests
make validate       # Validation config
```

### Opérations
```bash
make defectdojo-start    # Démarrer DefectDojo
make dashboard-start     # Démarrer Dashboards
make status              # État des services
```

---

## 📚 Documentation

Voir [`README.md`](../README.md) pour l'aperçu général.  
Voir [`docs/README.md`](../docs/README.md) pour l'index de documentation.

---

**Structure créée le** : 09 Février 2026  
**Projet** : CloudSentinel PFE - M2MPSSR ISI Hammam Sousse
