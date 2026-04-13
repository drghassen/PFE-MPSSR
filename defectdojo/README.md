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

---

## CloudSentinel Risk Acceptance Template (Once-For-All)

Pour eviter de remplir les memes champs a chaque exception, utilisez:
- template versionne: `defectdojo/risk_acceptance_template.json`
- generateur payload/API: `scripts/cloudsentinel_ra_template.py`

Le script produit un payload DefectDojo compatible `fetch-exceptions.py` (champs CloudSentinel dans `custom_fields` + fallback top-level).

### Champs a modifier a chaque exception
- `resource_id`
- `repo`
- `branch_scope`
- `justification`
- `expires_at`

### Generation d'un payload JSON
```bash
python3 scripts/cloudsentinel_ra_template.py \
  --resource-id azurerm_network_security_rule.rdp_any_allow \
  --repo mygroup/myproject \
  --branch-scope main \
  --justification "Temporary exception with compensating controls" \
  --expires-at 2026-03-20T00:00:00Z \
  --output .cloudsentinel/dojo_ra_payload.json
```

### Creation directe dans DefectDojo (API POST)
```bash
export DOJO_URL="https://dojo.example.com"
export DOJO_API_KEY="xxxxxxxx"

python3 scripts/cloudsentinel_ra_template.py \
  --resource-id azurerm_network_security_rule.rdp_any_allow \
  --repo mygroup/myproject \
  --branch-scope main \
  --justification "Temporary exception with compensating controls" \
  --expires-at 2026-03-20T00:00:00Z \
  --post
```

### Notes importantes
- Le script cherche d'abord un fingerprint exact dans:
  - `.cloudsentinel/checkov_opa.json`
  - `.cloudsentinel/golden_report.json`
- Si introuvable, il genere un fingerprint deterministe `sha256(rule_id:resource_id)`:
  - utile pour creer la RA
  - peut ne pas matcher OPA en mode `fingerprint_exact`

### Mapping UX DefectDojo -> CloudSentinel (mode standard)
- `Name` -> `rule_id` (format conseille: `CKV2_CS_AZ_021`)
- `Accepted findings` -> source de traceabilite + resolution `resource_id` via `component_name` du finding
- `Security Recommendation Details` -> `fingerprint` / `resource_hash` (mettre uniquement la valeur base64)
- `Accepted By` -> `approved_by` (email)
- `Owner` -> `requested_by` (fallback system si owner non-email)
- `Expiration date` -> `expires_at`
- `Decision details` -> `justification`

Template de saisie UX recommande:
- `Name`: `CKV2_CS_AZ_021`
- `Security Recommendation`: `Accept`
- `Security Recommendation Details`: fingerprint exact (base64)
- `Decision`: `Accept`
- `Decision details`: justification metier/technique
- `Accepted By`: email AppSec
- `Owner`: owner DefectDojo
- `Expiration date`: date future

### One-time setup recommande dans DefectDojo
Creez ces `custom_fields` (modele Risk Acceptance) une seule fois:
- `rule_id`, `check_id`
- `scanner`, `tool`
- `resource_id`, `resource_name`
- `fingerprint`, `resource_hash`
- `scope_type`, `branch_scope`, `repo`
- `severity`
- `requested_by`, `approved_by`, `approved_by_role`
- `justification`, `expires_at`
- `break_glass`, `incident_id`
