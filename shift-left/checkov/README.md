# Checkov Security Component

## Overview
Checkov detecte les mauvaises configurations IaC (Terraform, CloudFormation, Kubernetes).

## Usage
```bash
# Scan d'un dossier IaC
bash shift-left/checkov/run-checkov.sh infra/azure/dev
```

## Configuration
- Fichier de configuration: `shift-left/checkov/.checkov.yml`
- Policies locales: `shift-left/checkov/policies/`
- Le fichier `.checkov.yml` force l'exécution **uniquement** des checks `CKV2_CS_AZ_###`.
