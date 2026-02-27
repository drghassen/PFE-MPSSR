# CloudSentinel 🛡️

> **Gouvernance Sécurité Cloud — Shift-Left & Shift-Right**

Plateforme de sécurité cloud automatisée combinant prévention pré-déploiement et surveillance continue post-déploiement.

---

## 📐 Architecture

Le projet implémente une architecture en deux phases :

### **Phase 1 — SHIFT-LEFT (Pré-déploiement)**
Pipeline CI/CD avec scanners parallèles → Normalisation → Décision OPA → Quality Gate

### **Phase 2 — SHIFT-RIGHT (Runtime & Drift)**
Infrastructure live → Collecte d'événements → Détection de drift → Remédiation Cloud Custodian

### **Gouvernance Centralisée**
DefectDojo pour traçabilité des findings et gestion des risques

### **Dashboard Temps Réel**
Grafana + Prometheus pour visualisation de la compliance et incidents

---

## ✅ Standard entreprise (Local vs CI)

- **Pré-commit (local, advisory)** : Gitleaks (staged) → Normalisation (local-fast) → OPA en mode advisory (CLI)
- **CI/CD (enforcement)** : Gitleaks + Checkov + Trivy → Normalisation (mode CI) → OPA Server (enforce)

Objectif : feedback rapide en local, gouvernance stricte en CI, sans bruit ni faux positifs locaux.

---

## 📁 Structure du Projet

```
pfe-cloud-sentinel/
├── 📋 .gitlab-ci.yml          # Pipeline CI/CD GitLab
├── 🔧 Makefile                # Commandes pratiques
├── 🌍 .env.template           # Variables d'environnement
├── 🚫 .gitignore              # Exclusions Git
│
├── 📖 docs/                   # Documentation complète
├── 🔒 shift-left/             # Phase 1: Pré-déploiement
├── 🔍 shift-right/            # Phase 2: Runtime monitoring
├── 📜 policies/               # Policies as Code (OPA + Custodian)
├── 🏗️  infra/                 # Infrastructure as Code (Terraform)
├── 🔄 ci/                     # Scripts CI/CD
├── 📊 defectdojo/             # Gouvernance & traçabilité
├── 📈 monitoring/             # Grafana + Prometheus
├── 🧪 tests/                  # Tests et échantillons vulnérables
└── 🛠️  scripts/               # Scripts utilitaires
```

Voir la documentation complète dans [`docs/`](docs/)

---

## 🚀 Démarrage Rapide

### 1️⃣ Configuration
```bash
cp .env.template .env
# Éditer .env avec vos credentials
```

### 2️⃣ Installation
```bash
make setup
```

### 3️⃣ Vérification
```bash
make test
```

---

## 📚 Documentation

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture détaillée
- **[INSTALLATION.md](docs/INSTALLATION.md)** - Guide d'installation
- **[SHIFT_LEFT.md](docs/SHIFT_LEFT.md)** - Pipeline Shift-Left
- **[SHIFT_RIGHT.md](docs/SHIFT_RIGHT.md)** - Monitoring Shift-Right
- **[GOVERNANCE.md](docs/GOVERNANCE.md)** - DefectDojo & Dashboard

---

## 👨‍🎓 Projet de Fin d'Études

**Étudiant** : Ghassen DRIDI  
**Encadrant** : Mr Moez HACHEM  
**Formation** : Master 2MPSSR — ISICOM Hammam Sousse  
**Année** : 2025-2026

---

**CloudSentinel** — *De la prévention à la gouvernance* 🛡️
