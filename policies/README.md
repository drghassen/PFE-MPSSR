# 📜 Policies - Policy as Code

> **Décisions automatisées** via policies déclaratives

Ce répertoire contient toutes les policies de sécurité utilisées dans CloudSentinel :
- **OPA (Open Policy Agent)** : Décisions Shift-Left (Quality Gate CI/CD)
- **Cloud Custodian** : Remédiation Shift-Right (Runtime)

---

## 📁 Structure

```
policies/
├── opa/
│   ├── README.md
│   ├── pipeline_decision.rego      # Policy principale
│   ├── test_pipeline_decision.rego # Tests unitaires
│   └── examples/
│       └── sample-inputs/          # Exemples de données
│
└── custodian/
    ├── README.md
    ├── azure/
    │   ├── README.md
    │   ├── storage-security.yml    # Policies storage
    │   ├── network-security.yml    # Policies réseau
    │   └── compute-security.yml    # Policies VMs
    │
    └── aws/
        ├── README.md
        └── (future policies AWS)
```

---

## 🎯 OPA - Open Policy Agent

**Usage** : Phase Shift-Left  
**Objectif** : Décider si le pipeline peut déployer (ALLOW/DENY)

### Input
Données normalisées depuis :
- Gitleaks (secrets)
- Checkov (IaC misconfigurations)
- Trivy (vulnérabilités)

### Policy Rules
```rego
# Exemples de règles
deny[msg] {
    scanner_not_run[name]
    msg := sprintf("Scanner %s did not run or report is invalid", [name])
}

deny[msg] {
    effective_critical > critical_max
    msg := sprintf("CRITICAL findings (%d) exceed threshold (%d)", [effective_critical, critical_max])
}

allow {
    count(deny) == 0
}
```

### Commande
```bash
opa eval -i opa_input.json \
  -d policies/opa/pipeline_decision.rego \
  "data.cloudsentinel.gate.decision"
```

---

## ☁️ Cloud Custodian

**Usage** : Phase Shift-Right  
**Objectif** : Remédiation automatisée en production

### Azure Policies

#### Storage Security
```yaml
policies:
  - name: storage-block-public-access
    resource: azure.storage
    filters:
      - type: value
        key: properties.publicNetworkAccess
        value: Enabled
    actions:
      - type: set-properties
        properties:
          publicNetworkAccess: Disabled
```

#### Network Security
```yaml
policies:
  - name: nsg-block-ssh-world
    resource: azure.networksecuritygroup
    filters:
      - type: ingress
        FromPort: 22
        ToPort: 22
        Cidr: "0.0.0.0/0"
    actions:
      - type: notify
        to: [security@example.com]
```

### Commande
```bash
# Dry-run
custodian run -s output/ policies/custodian/azure/ --dryrun

# Exécution
custodian run -s output/ policies/custodian/azure/
```

---

## 🔑 Bonnes Pratiques

### OPA
✅ Toujours définir des tests (`test_*.rego`)  
✅ Utiliser des seuils configurables (pas hardcodés)  
✅ Messages d'erreur clairs et actionnables  
✅ Versionner les policies avec Git  

### Cloud Custodian
✅ Toujours tester en `--dryrun` d'abord  
✅ Actions graduées (notify → tag → isolate → fix)  
✅ Slack/Email pour actions critiques  
✅ Logs dans DefectDojo  

---

## 📚 Documentation

- **OPA** : [opa/README.md](opa/README.md)
- **Custodian Azure** : [custodian/azure/README.md](custodian/azure/README.md)
- **Guide Policies** : [../docs/POLICIES_GUIDE.md](../docs/POLICIES_GUIDE.md)
