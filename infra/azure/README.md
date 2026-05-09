# CloudSentinel Azure Lab (OpenTofu)

Infrastructure modulaire pour `envs/dev`, orientée tests Shift-Left + Shift-Right, sans `Activity Logs`.

## Déploiement

```bash
cd infra/azure/envs/dev
cp terraform.tfvars.example terraform.tfvars
# renseigner subscription_id, tenant_id, vm_admin_ssh_public_key

# backend local (test)
tofu init -backend=false

# backend azurerm (CI/prod)
# tofu init -backend-config="resource_group_name=..." -backend-config="storage_account_name=..." -backend-config="container_name=..." -backend-config="key=..."

tofu plan

tofu apply
```

## Modules

- `resource-group`
- `network` (VNet, subnets, NSG, Public IP)
- `identity` (User Assigned Managed Identity)
- `compute` (1-2 Linux VMs)
- `container-instance` (ACI privé dans subnet délégué)
- `storage` (Storage Account sécurisé)
- `key-vault`
- `rbac` (assignations least privilege)
- `recovery` (Recovery Services Vault + backup policy)
- `database-cosmos` (optionnel via `enable_cosmosdb`)

## Notes

- `vm_count` supporte `1` ou `2`.
- `enable_cosmosdb` est désactivé par défaut pour limiter risque quota/coût Azure Student.
- Le module `key_vault` expose `azurerm_private_dns_zone.vault` pour compatibilité pipeline existant.
- Le module `network` expose `azurerm_subnet.private_endpoints` pour compatibilité pipeline existant.
