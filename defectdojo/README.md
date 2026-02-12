# 📊 DefectDojo - Gouvernance & Traçabilité

> **Centralisation** des findings, gestion des risques, audit trail

DefectDojo est le système centralisé de gestion de toutes les vulnérabilités et incidents détectés par CloudSentinel.

---

## 🎯 Rôle dans l'Architecture

```
Shift-Left (CI/CD)          Shift-Right (Runtime)
       │                            │
       │ Findings                   │ Incidents
       ▼                            ▼
   ┌────────────────────────────────────┐
   │           DEFECTDOJO               │
   │  ┌──────────────────────────────┐  │
   │  │ Products & Engagements       │  │
   │  ├──────────────────────────────┤  │
   │  │ Findings (Vulnerabilities)   │  │
   │  ├──────────────────────────────┤  │
   │  │ Risk Acceptance              │  │
   │  ├──────────────────────────────┤  │
   │  │ Metrics & Dashboard          │  │
   │  └──────────────────────────────┘  │
   └────────────────────────────────────┘
                   │
                   ▼
         Grafana (Visualisation)
```

---

## 📁 Structure

```
defectdojo/
├── README.md
├── docker-compose.yml          # Déploiement local
├── setup-engagements.py        # Script de configuration
├── import-findings.py          # Import automatisé
└── requirements.txt            # Dépendances Python
```

---

## 🚀 Installation (Local)

### 1. Démarrage via Docker Compose
```bash
cd defectdojo
docker-compose up -d
```

### 2. Accès Web UI
- **URL** : http://localhost:8080
- **User** : admin
- **Pass** : (voir console logs lors du premier démarrage)

### 3. Configuration Initiale
```bash
# Créer products et engagements
python setup-engagements.py
```

---

## 🔧 Configuration

### Products
- **CloudSentinel-Dev** : Environnement développement
- **CloudSentinel-Staging** : Environnement staging (future)
- **CloudSentinel-Prod** : Environnement production (future)

### Engagements
- Un engagement par cycle de déploiement
- Durée : Sprint ou Release
- Association automatique via API

### Scan Types Supportés
- ✅ Gitleaks Scan
- ✅ Checkov Scan
- ✅ Trivy Scan
- ✅ Generic Findings (pour Cloud Custodian)

---

## 📤 Import de Findings

### Automatique (CI/CD)
```bash
# Dans .gitlab-ci.yml
curl -X POST "http://defectdojo:8080/api/v2/import-scan/" \
  -H "Authorization: Token $DOJO_API_KEY" \
  -F "file=@gitleaks.json" \
  -F "scan_type=Gitleaks Scan" \
  -F "engagement=$ENGAGEMENT_ID"
```

### Script Python
```bash
python import-findings.py \
  --file gitleaks.json \
  --type "Gitleaks Scan" \
  --engagement 1
```

---

## 📊 Workflow

### 1. Findings (Découverte)
- Import automatique depuis scanners
- Déduplication automatique
- Sévérité et priorité assignées

### 2. Triage (Analyse)
- Review par Security Team
- Assignation à un owner
- Statut : Active / False Positive / Risk Accepted

### 3. Risk Acceptance (Décision)
- Justification requise
- Expiration date
- Approbation manager

### 4. Remediation (Correction)
- Plan de remédiation
- Tracking via Jira/GitLab Issues
- Validation post-fix

### 5. Closed (Résolu)
- Vérification finale
- Archivage avec audit trail

---

## 🔗 Intégrations

### GitLab CI/CD
- Import automatique des scans
- Comments sur Merge Requests
- Quality Gate based on findings

### Cloud Custodian
- Import des incidents runtime
- Actions de remédiation trackées

### Grafana
- Dashboards depuis DefectDojo API
- Métriques temps réel

### Slack/Email
- Notifications sur nouveaux findings critiques
- Alertes sur dépassement SLA

---

## 📈 Métriques Disponibles

- **Finding Trends** : Évolution dans le temps
- **Mean Time To Remediate (MTTR)**
- **SLA Compliance** : % findings résolus dans les délais
- **Top Vulnerabilities** : Types les plus fréquents
- **Product Health** : Score de sécurité par product

---

## 🔑 API Key Management

### Génération
1. Se connecter à DefectDojo UI
2. User → API Key → Generate
3. Copier dans `.env` :
   ```bash
   DOJO_API_KEY=your_generated_api_key
   ```

### Permissions
- **Read** : Lecture findings
- **Write** : Import scans
- **Admin** : Gestion products/engagements

---

## 📚 Documentation

- **DefectDojo Official** : https://documentation.defectdojo.com/
- **API Reference** : http://localhost:8080/api/v2/doc/
- **Setup Guide** : [../docs/DEFECTDOJO.md](../docs/DEFECTDOJO.md)
- **Dashboard Guide** : [../docs/GOVERNANCE.md](../docs/GOVERNANCE.md)
