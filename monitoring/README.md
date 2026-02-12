# 📈 Monitoring - Dashboard Temps Réel

> **Grafana + Prometheus** pour visualisation de la compliance et incidents

## 🎯 Objectif

Tableau de bord centralisé affichant :
- **Vue Drift** : Compliance vs état réel
- **Vue Compliance** : Conformité CIS/NSI
- **Vue Incidents** : Findings DefectDojo en temps réel

---

## 📁 Structure

```
monitoring/
├── README.md
├── docker-compose.yml      # Stack Grafana + Prometheus
├── grafana/
│   ├── dashboards/
│   │   ├── overview.json           # Dashboard principal
│   │   ├── shift-left.json         # Métriques CI/CD
│   │   └── shift-right.json        # Métriques runtime
│   ├── datasources/
│   │   └── prometheus.yml          # Configuration Prometheus
│   └── provisioning/
│
└── prometheus/
    ├── prometheus.yml              # Configuration Prometheus
    └── alerts/
        └── security-alerts.yml     # Alertes sécurité
```

---

## 🚀 Démarrage

### Via Makefile
```bash
make dashboard-start
# Grafana: http://localhost:3000
# Prometheus: http://localhost:9090
```

### Manuel
```bash
cd monitoring
docker-compose up -d
```

---

## 📊 Dashboards Disponibles

### 1. Overview Dashboard
- **Findings total** (par criticité)
- **Trend** (évolution temporelle)
- **MTTR** (Mean Time To Remediate)
- **Top 10 vulnérabilités**

### 2. Shift-Left Dashboard
- **Pipelines status** (success/fail rate)
- **Scanners performance**
- **OPA decisions** (allow/deny ratio)
- **Blocages par type**

### 3. Shift-Right Dashboard
- **Drift count** par environnement
- **Prowler score CIS**
- **Cloud Custodian actions**
- **Compliance trend**

---

## 🔧 Configuration

### Datasources
- **Prometheus** : Métriques temps réel
- **DefectDojo API** : Findings via JSON API
- **Azure Monitor** (optionnel)
- **AWS CloudWatch** (optionnel)

### Alertes
- Slack webhook pour incidents critiques
- Email pour rapports quotidiens
- PagerDuty pour on-call (optionnel)

---

## 📚 Accès

- **Grafana** : http://localhost:3000
  - User : `admin`
  - Pass : `admin` (à changer au premier login)
  
- **Prometheus** : http://localhost:9090

---

## 📖 Documentation

- [../docs/GOVERNANCE.md](../docs/GOVERNANCE.md) - Guide complet
- Grafana Official : https://grafana.com/docs/
