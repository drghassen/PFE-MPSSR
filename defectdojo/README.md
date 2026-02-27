# 📊 Gouvernance ASPM (DefectDojo)

> **Application Security Posture Management** : Agrégation en continu, traçabilité et déduplication des incidents de sécurité (Findings) CloudSentinel.

Ce composant (dossier ou script) s'assure que le bruit (logs JSON abstraits) remonté par Gitleaks, Checkov, Trivy et OPA se métamorphose en véritables tickets de remédiation auditables par une équipe SOC/Sécurité.

---

## 🎯 Stratégie d'Ingestion (Data-Flow)

DefectDojo se place non pas sur le poste développeur, mais en CI, une fois la **Normalisation** effectuée :

```text
  [ Golden Report JSON ]
             |
             v
 [ upload-to-defectdojo ] (Pipeline Stage)
             |
             v
   [ 📈 DefectDojo API ] --> Métriques, SLA, Tickets JIRA
```

### Bénéfices Architecturaux
1.  **Single Source of Truth** : Stockage du contexte entier pour la sécurité.
2.  **Mesure des Exemptions** : Si OPA laisse passer une vulnérabilité reconnue (Exception active), DefectDojo trace que cette faille figure tout de même en production, assurant un suivi temporel et sa fermeture une fois la date `expires_at` dépassée.
3.  **Déduplication Intelligente** : Via les fingerprints SHA/Base64 consolidés par le `Normalizer`, DefectDojo empile les alertes continues sur un seul finding (au lieu de milliers d'identiques via chaque MR).

---

## 🚀 Fonctionnement en CI

L'intégration peut exploiter l'API REST v2 de DefectDojo. Notre Normalizer formatant les données spécifiquement (`golden_report.json`), l'outil qui importe la donnée n'a plus qu'à translater ce schéma unique vers la nomenclature de l'API DefectDojo (pas besoin de x3 importateurs différents).

### En CLI ou Webhook :
```bash
# (Exemple abstrait de payload)
curl -X POST "$DEFECTDOJO_URL/api/v2/findings/" \
     -H "Authorization: Token $DEFECTDOJO_API_TOKEN" \
     ...
```
