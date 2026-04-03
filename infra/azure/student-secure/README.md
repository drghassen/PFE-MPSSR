# CloudSentinel - Azure Student Secure Stack

Stack Terraform sécurisé et modulaire pour Azure Student, avec intégration CI/CD fail-closed.

## Architecture

- `Resource Group` dédié au stack.
- `Virtual Network` segmenté:
  - subnet `public` pour la VM bastion/jump-host logique (VM sans IP publique directe).
  - subnet `private` pour services internes et private endpoints.
  - subnet `db` délégué MySQL.
- `Network Security Groups`:
  - deny-all inbound explicite.
  - ouverture minimale uniquement des flux nécessaires.
- `Storage Account` sécurisé:
  - TLS1.2, HTTPS-only, public access désactivé, CMK Key Vault, private endpoint Blob.
- `MySQL Flexible Server` privé:
  - subnet délégué + private endpoint + private DNS.
- `Key Vault Premium`:
  - RBAC, purge protection, clé HSM pour chiffrement.
  - secrets DB stockés dans Key Vault (username/password).
- `Monitoring`:
  - Network Watcher flow logs, Log Analytics, diagnostic settings.

## Design Sécurité

- Pas d’exposition publique directe de la base de données.
- Chiffrement data-plane et contrôle réseau strict sur Storage et Key Vault.
- Outputs Terraform limités aux informations non sensibles (IDs, endpoints, IP privée VM).
- Contrat scanner strict:
  - `status = OK | NOT_RUN`
  - en cas d’erreur technique, propagation `NOT_RUN` jusqu’à OPA.
- Décision centralisée OPA:
  - séparation stricte `Detection -> Normalization -> Decision -> Enforcement`.

## Gestion des Secrets

- Secrets applicatifs DB créés dans Key Vault:
  - `mysql-admin-username-<suffix>`
  - `mysql-admin-password-<suffix>`
- Aucun secret en output Terraform.
- Les rapports scanners sont redacted/sanitized avant normalisation et artifacts OPA.
- Le backend Terraform est `azurerm` (state distant Azure Blob), à configurer via CI vars.

Important:
- Terraform garde des attributs sensibles dans le state (comportement Terraform standard).
- La protection repose sur backend distant Azure chiffré + RBAC strict + stockage privé.

## Déploiement Local

```bash
cd infra/azure/student-secure
cp terraform.tfvars.example terraform.tfvars
# renseigner admin_ssh_public_key et cidr admin

terraform init \
  -backend-config="resource_group_name=<tfstate-rg>" \
  -backend-config="storage_account_name=<tfstate-storage>" \
  -backend-config="container_name=<tfstate-container>" \
  -backend-config="key=student-secure-dev.tfstate" \
  -backend-config="use_azuread_auth=true"

terraform plan -out=tfplan
terraform apply tfplan
```

## CI/CD (Git Push -> Scan -> OPA -> Deploy)

Le pipeline GitLab est déclenché sur `push` et exécute:

1. Garde immutabilité/policies.
2. Scanners Shift-Left (`gitleaks`, `checkov`, `trivy fs/config/image`).
3. Normalizer -> `golden_report.json` (schema strict).
4. OPA `--enforce`.
5. Gate de déploiement stricte (`0 finding` + aucun scanner `NOT_RUN`).
6. `terraform init/plan/apply` sur `infra/azure/student-secure`.
7. Vérification post-déploiement automatisée.

Variables CI requises pour deploy:

- `ARM_CLIENT_ID`
- `ARM_CLIENT_SECRET`
- `ARM_TENANT_ID`
- `ARM_SUBSCRIPTION_ID`
- `TFSTATE_RESOURCE_GROUP`
- `TFSTATE_STORAGE_ACCOUNT`
- `TFSTATE_CONTAINER`
- optionnel: `TFSTATE_KEY`

## Vérification Automatique (Fail-Closed)

Depuis la racine du repo:

```bash
bash scripts/verify-student-secure.sh infra/azure/student-secure alpine:3.21
bash scripts/ci/enforce-zero-findings.sh .cloudsentinel/golden_report.json
```

Post-deploy CI:

```bash
bash scripts/post-deploy-verify-student-secure.sh infra/azure/student-secure alpine:3.21
```

Le flux échoue immédiatement si:

- scanner non exécuté (`NOT_RUN`)
- JSON invalide
- secret non redacted
- violation OPA
- findings restants (`FAILED > 0`)

## Outputs Disponibles

- IDs: RG, VNet, subnets, NSGs, Storage, VM, MySQL, Key Vault.
- Endpoints privés: Key Vault, Storage Blob, MySQL.
- VM: IP privée uniquement (pas d’exposition publique directe).
- FQDN DB privé + IDs des secrets Key Vault (pas les valeurs).
