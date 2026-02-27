# 📉 Monitoring & Drift Detection (Shift-Right)

> **Continuous Observability** : La sécurité ne s'arrête pas au déploiement.

Ce composant (Monitoring/Observability) surveille l'activité métier et sécuritaire de l'infrastructure en production.

---

## 🎯 Périmètre (Grafana + Prometheus)

1.  **Surveillance de Conformité** : Dashboard temps réel affichant les taux de succès des pipelines, et la part de "Findings" temporairement ignorés par les exceptions OPA actives (Technical Debt).
2.  **Alerting sur Drift** :
    *   Si l'infrastructure As Code déployée (Terraform) est modifiée manuellement en production ("ClickOps"), des drifts d'état seront remontés ici.
3.  **Logs Remédiation Custodian** : Suivi des actions automatisées de Cloud Custodian (ex: "Storage Account Public Access désactivé").

## 🚀 Mise en Oeuvre

(Futur: Ajouter le `docker-compose.yml` de la stack Observabilité)
