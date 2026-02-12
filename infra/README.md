# 🏗️ Infrastructure as Code (IaC)

> **Terraform** pour Azure et AWS

Ce répertoire contient l'infrastructure cloud définie en code.

---

## 📁 Structure

```
infra/
├── azure/
│   ├── README.md
│   ├── dev/
│   │   ├── main.tf              # Configuration principale
│   │   ├── variables.tf         # Variables
│   │   ├── outputs.tf           # Outputs
│   │   ├── terraform.tfvars.template
│   │   └── providers.tf         # Azure provider
│   │
│   └── modules/
│       ├── resource-group/
│       ├── storage/
│       ├── network/
│       └── compute/
│
└── aws/
    ├── README.md
    └── (future - structure similaire)
```

---

## 🎯 Environnements

### Dev
- **Objectif** : Développement et tests
- **Ressources** : Limitées et non-redondantes
- **Localisation** : `infra/azure/dev/`

### Staging (Future)
- **Objectif** : Tests pré-production
- **Localisation** : `infra/azure/staging/`

### Production (Future)
- **Objectif** : Production
- **Localisation** : `infra/azure/prod/`

---

## 🚀 Utilisation

### Azure Dev Environment

```bash
cd infra/azure/dev

# 1. Copier le template de variables
cp terraform.tfvars.template terraform.tfvars
# Éditer avec vos valeurs

# 2. Initialiser Terraform
terraform init

# 3. Plan (preview des changements)
terraform plan

# 4. Apply (déployer)
terraform apply

# 5. Outputs (récupérer les infos)
terraform output
```

---

## 📦 Ressources Créées (Dev)

- **Resource Group** : Conteneur logique
- **Storage Account** : Stockage - **intentionnellement mal configuré pour tests**
- **Virtual Network** : Réseau isolé
- **Network Security Group** : Firewall règles
- **Virtual Machine** : Instance de calcul

⚠️ **Note** : Certaines ressources sont volontairement mal configurées pour tester les scanners et policies.

---

## 🔐 Sécurité

### Secrets Management
- ❌ **JAMAIS** committer `terraform.tfvars`
- ✅ Utiliser `.tfvars.template` comme documentation
- ✅ Stocker secrets dans Azure Key Vault ou AWS Secrets Manager
- ✅ Utiliser variables d'environnement pour CI/CD

### State Management
- 🔒 State stocké dans Azure Storage Account (backend remote)
- 🔒 Locking activé pour éviter conflits
- 🔒 Chiffrement au repos

---

## 🧪 Tests

### Checkov (IaC Scan)
```bash
checkov -d infra/azure/dev/
```

### Terraform Validate
```bash
terraform validate
```

### Terraform Plan (Dry-run)
```bash
terraform plan -out=tfplan
```

---

## 📚 Documentation

- **Azure Terraform** : [azure/README.md](azure/README.md)
- **Modules** : [azure/modules/README.md](azure/modules/README.md)
- **Best Practices** : [../docs/IAC_BEST_PRACTICES.md](../docs/IAC_BEST_PRACTICES.md)
