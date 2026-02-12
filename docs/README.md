# 📖 Documentation CloudSentinel

Ce répertoire contient la documentation complète du projet CloudSentinel.

## 📑 Table des Matières

### Architecture & Conception
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Architecture complète Shift-Left & Shift-Right
  - Diagrammes détaillés
  - Flux de données
  - Composants et interactions

### Installation & Configuration
- **[INSTALLATION.md](INSTALLATION.md)** - Guide d'installation pas à pas
  - Prérequis système
  - Installation des outils
  - Configuration Azure/AWS
  - Setup DefectDojo local

### Implémentation

#### Phase 1 - Shift-Left
- **[SHIFT_LEFT.md](SHIFT_LEFT.md)** - Pipeline de sécurité pré-déploiement
  - Configuration des scanners (Gitleaks, Checkov, Trivy)
  - Normalisation et enrichissement des données
  - Policies OPA et décision automatisée
  - Quality Gate GitLab CI/CD

#### Phase 2 - Shift-Right
- **[SHIFT_RIGHT.md](SHIFT_RIGHT.md)** - Monitoring et drift detection
  - Event Collection (EventBridge/Azure Event Grid)
  - Prowler - Audit continu
  - Drift Engine - Détection IaC vs État réel
  - Cloud Custodian - Remédiation graduée

### Gouvernance & Monitoring
- **[GOVERNANCE.md](GOVERNANCE.md)** - Traçabilité et dashboard
  - Setup DefectDojo
  - Gestion des findings
  - Workflow d'acceptation de risque
  - Dashboard Grafana + Prometheus

### Référence
- **[TOOLS_REFERENCE.md](TOOLS_REFERENCE.md)** - Documentation des outils utilisés
- **[POLICIES_GUIDE.md](POLICIES_GUIDE.md)** - Guide de création de policies
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Résolution de problèmes courants

## 🎯 Par Où Commencer ?

1. **Comprendre l'architecture** → [ARCHITECTURE.md](ARCHITECTURE.md)
2. **Installer l'environnement** → [INSTALLATION.md](INSTALLATION.md)
3. **Implémenter Shift-Left** → [SHIFT_LEFT.md](SHIFT_LEFT.md)
4. **Implémenter Shift-Right** → [SHIFT_RIGHT.md](SHIFT_RIGHT.md)
5. **Configurer la gouvernance** → [GOVERNANCE.md](GOVERNANCE.md)

## 📝 Notes

Cette documentation suit la structure du cahier des charges du PFE et correspond au diagramme d'architecture fourni.

**Dernière mise à jour** : Février 2026
