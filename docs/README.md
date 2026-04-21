# CloudSentinel 🛡️

> **Gouvernance Sécurité Cloud Enterprise — Shift-Left & Shift-Right (v5.0)**

Plateforme DevSecOps automatisée implémentant une séparation stricte des responsabilités (PEP/PDP), combinant prévention pré-déploiement (CI/CD) et surveillance continue post-déploiement.

---

## 📐 Architecture Globale

Le projet implémente une architecture Zero-Trust en deux phases :

### **Phase 1 — SHIFT-LEFT (Pré-déploiement)**
Pipeline CI/CD avec exécution parallèle des scanners, normalisation stricte, et décision centralisée.
- **Scanners** : Gitleaks (Secrets), Checkov (IaC), Trivy (Conteneurs/Vulnérabilités)
- **Normalizer** : Unifie 100% des rapports JSON (Format Golden Report)
- **Open Policy Agent (OPA)** : Souveraineté totale sur la décision (ALLOW/DENY) via policies Rego.

### **Phase 2 — SHIFT-RIGHT (Runtime & Drift)**
Infrastructure live → Collecte d'événements → Détection de drift → Remédiation via Cloud Custodian.

### **Gouvernance & Observabilité**
- **DefectDojo** : Traçabilité des findings (ASPM)
- **Grafana + Prometheus** : Visualisation de la compliance en temps réel

---

## ✅ Standard Entreprise (Mode Local vs CI)

L'architecture supporte un mode d'exécution dual :

- **Pré-commit (local, advisory)** : Gitleaks (staged) → Normalisation (mode local-fast) → OPA en mode advisory (CLI). Retour immédiat au développeur sans friction.
- **CI/CD (enforcement)** : Full Scanners → Normalisation complète → OPA Server (enforce). Bloque impérativement le déploiement en cas de non-conformité.

---

## 📁 Structure du Projet

L'arborescence est conçue pour séparer le code applicatif, les policies, et l'infrastructure :

```text
pfe-cloud-sentinel/
├── 📋 .gitlab-ci.yml          # Pipeline CI/CD GitLab (6 stages complets)
├── 🔧 Makefile                # Commandes pratiques d'orchestration
├── 🌍 .env.template           # Variables d'environnement standardisées
├── 🚫 .gitignore              # Exclusions Git
│
├── 🔒 shift-left/             # Phase 1: Moteurs de détection et normalisation
│   ├── gitleaks/              # Wrapper et configuration (Secrets)
│   ├── checkov/               # Wrapper et configuration (IaC)
│   ├── trivy/                 # Wrapper et configuration (Vulns)
│   └── normalizer/            # Engine de normalisation JSON (Golden Report)
│
├── 📜 policies/               # Policy as Code (Le cœur décisionnel)
│   ├── opa/                   # Règles Rego (Pipeline Decision) et exceptions
│   └── custodian/             # Règles YAML (Remédiation Runtime Azure)
│
├── 🔄 ci/                     # Images Docker immutables et scripts CI
├── 🏗️  infra/                 # Infrastructure as Code (OpenTofu/Terraform)
├── 📊 defectdojo/             # Gouvernance & intégration outil ASPM
├── 📈 monitoring/             # Stack Grafana + Prometheus
├── 🧪 tests/                  # Fixtures et tests d'intégration (E2E)
├── 📖 docs/                   # Documentation de conception détaillée
└── 🛠️  scripts/               # Scripts utilitaires globaux
```

---

## 🚀 Démarrage Rapide

### 1️⃣ Configuration Initiale
```bash
cp .env.template .env
# Renseignez vos accès (Azure, GitLab, DefectDojo) dans le fichier .env
```

### 2️⃣ Installation des dépendances locales
```bash
make setup
```

### 3️⃣ Exécution d'un scan complet (Simulation CI en local)
```bash
make scan
```

---

## 📚 Documentation Détaillée

Chaque dossier contient son propre `README.md` détaillé pour ses composants spécifiques :
- **[Shift-Left (Scanners & Normalizer)](shift-left/README.md)**
- **[Policies (OPA & Custodian)](policies/README.md)**
- **[CI/CD & Images](ci/README.md)**

Guides de conception globaux (dans `docs/`):
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture détaillée et diagrammes
- **[SHIFT_LEFT.md](docs/SHIFT_LEFT.md)** - Conception approfondie du Shift-Left
- **[GOVERNANCE.md](docs/GOVERNANCE.md)** - Gestion des exceptions et métriques

---

## 👨‍🎓 Projet de Fin d'Études

Projet développé avec des standards de production avancés (Immuabilité CI, PEP/PDP, Supply Chain Security).

**Étudiant** : Ghassen DRIDI
**Encadrant** : Mr Moez HACHEM
**Formation** : Master 2MPSSR — ISICOM Hammam Sousse
**Année** : 2025-2026

**CloudSentinel** — *De la prévention à la gouvernance continue* 🛡️

---

## Fetch Exceptions Refactor (Modular)

The entrypoint remains unchanged:

```bash
python3 shift-left/opa/fetch-exceptions.py
```

Implementation was split into internal modules under:

```text
shift-left/opa/fetch_exceptions/
├── __init__.py
├── fetch_utils.py
├── fetch_defectdojo.py
├── fetch_validation.py
├── fetch_mapping.py
└── main.py
```

Compatibility guarantees:
- `shift-left/opa/fetch-exceptions.py` is still the public CLI/script path used by CI.
- Existing unit tests that import `fetch-exceptions.py` continue to work unchanged.
- Output contracts are preserved:
  - `.cloudsentinel/exceptions.json`
  - `.cloudsentinel/dropped_exceptions.json`
  - `.cloudsentinel/audit_events.jsonl`

CI script consolidation:
- Canonical guard implementations are in `shift-left/ci/`.
- `.gitlab-ci.yml` guard paths remain unchanged.
