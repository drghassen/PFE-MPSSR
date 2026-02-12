# 🔍 Shift-Right — Runtime & Drift Detection

> **Phase 2** : Surveillance continue et remédiation en production

## 📐 Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   LIVE INFRASTRUCTURE                      │
│                    (AWS / Azure)                           │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       │ Events (Resource changes,
                       │         config updates, etc.)
                       ▼
           ┌───────────────────────┐
           │      SENSORS          │
           │  EventBridge (AWS)    │
           │  Event Grid (Azure)   │
           │  + Prowler (Audit)    │
           └───────────┬───────────┘
                       │
                       │ Filtered events
                       ▼
           ┌───────────────────────┐
           │    DRIFT ENGINE       │
           │  IaC vs État Réel     │
           │  Terraform State      │
           └───────────┬───────────┘
                       │
                       │ Drift detected
                       ▼
      ┌────────────────────────────────┐
      │     CLOUD CUSTODIAN            │
      │  Gouvernance & Remédiation     │
      │  Décision + Actions graduées   │
      └────────────┬───────────────────┘
                   │
                   │
      ┌────────────┼─────────────┐
      │            │             │
      ▼            ▼             ▼
  ┌──────┐   ┌──────────┐  ┌─────────┐
  │Notify│   │Isolation │  │Auto-Fix │
  │Slack │   │Tag/Stop  │  │Correct  │
  └──────┘   └──────────┘  └─────────┘
      │            │             │
      └────────────┴─────────────┘
                   │
                   ▼
           ┌──────────────┐
           │ DefectDojo   │
           │ (Incidents)  │
           └──────────────┘
```

## 🛠️ Composants

### 1. Event Collection
- **AWS** : EventBridge
- **Azure** : Event Grid
- **Fonction** : Collecte des événements cloud en temps réel
- **Events surveillés** :
  - Création/modification/suppression de ressources
  - Changements de configuration
  - Violations de policies
- **Emplacement** : `shift-right/event-collection/`

### 2. Sensors - Prowler
- **Type** : Audit de compliance CIS
- **Cloud** : Azure + AWS
- **Fonction** : Scan périodique de la posture de sécurité
- **Output** : Rapport de compliance JSON
- **Emplacement** : `shift-right/prowler/`
- **Configuration** : `config-azure.yaml`

### 3. Drift Engine
- **Fonction** : Détection des écarts entre IaC et état réel
- **Comparaison** :
  - État Terraform (`terraform.tfstate`)
  - État cloud réel (API Azure/AWS)
- **Détecte** :
  - Modifications manuelles (Console, CLI)
  - Ressources créées hors Terraform
  - Changements de configuration non trackés
- **Emplacement** : `shift-right/drift-engine/`

### 4. Cloud Custodian
- **Type** : Policy Engine + Remediation
- **Policies** : `policies/custodian/azure/` et `policies/custodian/aws/`
- **Actions graduées** :
  1. **Notify** : Slack, Email
  2. **Tag** : Marquage des ressources non conformes
  3. **Isolate** : Restriction réseau, arrêt temporaire
  4. **Auto-remediate** : Correction automatique contrôlée
- **Mode** :
  - `--dryrun` : Simulation
  - `--region` : Régions spécifiques
  - Cron job pour exécution périodique

## 📁 Structure

```
shift-right/
├── prowler/
│   ├── README.md
│   ├── config-azure.yaml       # Config Prowler Azure
│   ├── config-aws.yaml         # Config Prowler AWS (future)
│   └── run-prowler.sh          # Script d'exécution
│
├── event-collection/
│   ├── README.md
│   ├── azure-eventgrid-setup.md    # Guide setup Event Grid
│   ├── aws-eventbridge-setup.md    # Guide setup EventBridge
│   └── event-processor.py          # Processeur d'événements
│
└── drift-engine/
    ├── README.md
    ├── detect-drift.py         # Script de détection
    ├── compare-state.py        # Comparateur IaC/Cloud
    └── requirements.txt        # Dépendances
```

## 🚀 Utilisation

### Event Collection Setup (Azure)
```bash
# Voir guide complet
cat shift-right/event-collection/azure-eventgrid-setup.md
```

### Prowler - Audit CIS
```bash
cd shift-right/prowler
./run-prowler.sh
```

### Drift Detection
```bash
cd shift-right/drift-engine
python detect-drift.py --env dev
```

### Cloud Custodian Execution
```bash
# Dry-run
custodian run -s output/ \
  policies/custodian/azure/storage-security.yml \
  --dryrun

# Exécution réelle
custodian run -s output/ \
  policies/custodian/azure/storage-security.yml
```

### Mode Automatisé (Cron)
```bash
# Exécution toutes les heures
0 * * * * /path/to/run-custodian.sh
```

## 📊 Outputs

- **Prowler** : `prowler-output-YYYY-MM-DD.json`
- **Drift** : `drift-report.json`
- **Custodian** : `custodian-run-YYYY-MM-DD/`
  - `metadata.json`
  - `resources.json`
  - `policy.yml`
- **DefectDojo** : Incidents importés avec contexte

## 🎯 Cas d'Usage

### Scenario 1 : Storage Account Publique
1. Event Grid détecte changement sur Storage Account
2. Prowler confirme configuration non-CIS
3. Custodian détecte `public_access = true`
4. Action : **Isolation** (Firewall + Tag "NON-COMPLIANT")
5. Notification Slack Security Team
6. Finding dans DefectDojo

### Scenario 2 : VM modifiée manuellement
1. Drift Engine détecte écart Terraform ↔ Cloud
2. Custodian vérifie NSG rules
3. Port 22 ouvert (non dans Terraform)
4. Action : **Notify** + **Tag**
5. Incident DefectDojo avec recommandation

### Scenario 3 : Compliance Continue
1. Prowler scan quotidien (Cron)
2. Génération rapport CIS
3. Non-conformités détectées
4. Custodian applique policies
5. Auto-remediation où possible
6. Dashboard Grafana mis à jour

## 🔑 Points Clés

✅ Surveillance **continue** 24/7  
✅ Détection **drift** vs IaC  
✅ **Remédiation graduée** (notify → isolate → fix)  
✅ Audit **CIS Benchmarks** automatisé  
✅ **Zero Trust** : vérification permanente  

## 📚 Documentation Associée

- [../docs/SHIFT_RIGHT.md](../docs/SHIFT_RIGHT.md) - Guide complet
- [../docs/GOVERNANCE.md](../docs/GOVERNANCE.md) - Dashboard et DefectDojo
- [../policies/custodian/README.md](../policies/custodian/README.md) - Policies Custodian
