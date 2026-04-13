# CloudSentinel - Azure Student Secure Stack

Stack OpenTofu sécurisé et modulaire pour Azure Student, avec intégration CI/CD fail-closed.

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
  - TLS1.2, HTTPS-only, public access désactivé, CMK Key Vault réellement appliquée, private endpoint Blob.
- `MySQL Flexible Server` privé:
  - subnet délégué + private endpoint + private DNS.
- `Key Vault Premium`:
  - RBAC, purge protection, clé CMK (créée par Terraform ou référencée via `key_vault_existing_cmk_key_id`) pour chiffrement Storage.
  - secrets DB stockés dans Key Vault (username/password).
- `Monitoring`:
  - Network Watcher flow logs, Log Analytics, diagnostic settings.

## Design Sécurité

- Pas d’exposition publique directe de la base de données.
- Chiffrement data-plane et contrôle réseau strict sur Storage et Key Vault.
- Outputs OpenTofu limités aux informations non sensibles (IDs, endpoints, IP privée VM).
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
- Le backend OpenTofu est `azurerm` (state distant Azure Blob), à configurer via CI vars.

Important:
- OpenTofu garde des attributs sensibles dans le state (comportement standard IaC).
- La protection repose sur backend distant Azure chiffré + RBAC strict + stockage privé.

## Déploiement Local

```bash
cd infra/azure/student-secure
cp terraform.tfvars.example terraform.tfvars
# renseigner admin_ssh_public_key et cidr admin
# important: Azure VM attend une clé RSA (pas ed25519) pour cette configuration
# exemple:
# ssh-keygen -t rsa -b 4096 -C "student-secure" -f ~/.ssh/student_secure_rsa
# puis utiliser le contenu de ~/.ssh/student_secure_rsa.pub

tofu init \
  -backend-config="resource_group_name=<tfstate-rg>" \
  -backend-config="storage_account_name=<tfstate-storage>" \
  -backend-config="container_name=<tfstate-container>" \
  -backend-config="key=student-secure-dev.tfstate" \
  -backend-config="use_azuread_auth=true"

tofu plan -out=tfplan
tofu apply tfplan
```

## CI/CD (Git Push -> Scan -> OPA -> Deploy)

Le pipeline GitLab est déclenché sur `push` et exécute:

1. Garde immutabilité/policies.
2. Scanners Shift-Left (`gitleaks`, `checkov`, `trivy fs/config/image`).
3. Normalizer -> `golden_report.json` (schema strict).
4. OPA `--enforce`.
5. `tofu init/plan/apply` sur `infra/azure/student-secure` (seulement si OPA = ALLOW).

Variables CI requises pour deploy:

- `ARM_CLIENT_ID`
- `ARM_CLIENT_SECRET`
- `ARM_TENANT_ID`
- `ARM_SUBSCRIPTION_ID`
- `TFSTATE_RESOURCE_GROUP`
- `TFSTATE_STORAGE_ACCOUNT`
- `TFSTATE_CONTAINER`
- optionnel: `TFSTATE_KEY`
- optionnel: `TF_VAR_enable_vm_encryption_at_host` (mettre `false` sur Azure Student sauf feature explicitement activée)

Variables Terraform CMK:

- `key_vault_cmk_expiration_date`
- `key_vault_existing_cmk_key_id` (laisser vide pour création IaC, renseigner pour réutiliser une clé existante)

## Vérification Automatique (Fail-Closed)

Depuis la racine du repo:

```bash
bash scripts/verify-student-secure.sh infra/azure/student-secure alpine:3.21
```

Le flux échoue immédiatement si:

- scanner non exécuté (`NOT_RUN`)
- JSON invalide
- secret non redacted
- violation OPA

## Outputs Disponibles

- IDs: RG, VNet, subnets, NSGs, Storage, VM, MySQL, Key Vault.
- Endpoints privés: Key Vault, Storage Blob, MySQL.
- VM: IP privée uniquement (pas d’exposition publique directe).
- FQDN DB privé + IDs des secrets Key Vault (pas les valeurs).
