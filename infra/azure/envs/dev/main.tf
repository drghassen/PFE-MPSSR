module "resource_group" {
  source = "../../modules/resource-group"

  name     = local.resource_group_name
  location = var.location
  tags     = local.common_tags
}

resource "time_sleep" "after_resource_group" {
  create_duration = "20s"
  depends_on      = [module.resource_group]
}

module "network" {
  source = "../../modules/network"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location

  vnet_name = local.vnet_name
  vnet_cidr = var.vnet_cidr

  vm_subnet_name                = "snet-vm"
  vm_subnet_cidr                = var.vm_subnet_cidr
  aci_subnet_name               = "snet-aci"
  aci_subnet_cidr               = var.aci_subnet_cidr
  private_endpoints_subnet_name = "snet-pe"
  private_endpoints_subnet_cidr = var.private_endpoints_subnet_cidr

  vm_nsg_name  = "nsg-vm-${local.normalized_prefix}-${local.normalized_env}"
  aci_nsg_name = "nsg-aci-${local.normalized_prefix}-${local.normalized_env}"
  pe_nsg_name  = "nsg-pe-${local.normalized_prefix}-${local.normalized_env}"

  public_ip_name = "pip-${local.normalized_prefix}-${local.normalized_env}"
  tags           = local.common_tags
  depends_on     = [time_sleep.after_resource_group]
}

module "identity" {
  source = "../../modules/identity"

  name                = local.identity_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  tags                = local.common_tags
  depends_on          = [time_sleep.after_resource_group]
}

module "storage" {
  source = "../../modules/storage"

  name                = local.storage_account_name
  resource_group_name = module.resource_group.name
  location            = module.resource_group.location

  allowed_subnet_ids = [
    module.network.vm_subnet_id,
    module.network.aci_subnet_id,
  ]
  allowed_ip_rules = var.storage_allowed_ip_rules
  tags             = local.common_tags
  depends_on       = [module.network]
}

module "key_vault" {
  source = "../../modules/key-vault"

  name                = local.key_vault_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  tenant_id           = var.tenant_id
  vnet_id             = module.network.vnet_id
  tags                = local.common_tags
  depends_on          = [module.network]
}

resource "time_sleep" "after_key_vault" {
  create_duration = "30s"
  depends_on      = [module.key_vault]
}

module "compute" {
  source = "../../modules/compute"

  name_prefix                  = "${local.normalized_prefix}-${local.normalized_env}"
  location                     = module.resource_group.location
  resource_group_name          = module.resource_group.name
  subnet_id                    = module.network.vm_subnet_id
  public_ip_id                 = module.network.public_ip_id
  assign_public_ip             = var.assign_public_ip
  vm_count                     = var.vm_count
  vm_size                      = var.vm_size
  admin_username               = var.vm_admin_username
  admin_ssh_public_key         = var.vm_admin_ssh_public_key
  user_assigned_identity_id    = module.identity.id
  boot_diagnostics_storage_uri = module.storage.primary_blob_endpoint
  encryption_at_host_enabled   = var.vm_encryption_at_host_enabled
  enable_trusted_launch        = var.vm_enable_trusted_launch
  tags                         = local.common_tags
  depends_on                   = [module.network, module.identity, module.storage]
}

module "container_instance" {
  source = "../../modules/container-instance"

  name                      = local.aci_name
  location                  = module.resource_group.location
  resource_group_name       = module.resource_group.name
  subnet_id                 = module.network.aci_subnet_id
  user_assigned_identity_id = module.identity.id
  image                     = var.aci_image
  cpu                       = var.aci_cpu
  memory                    = var.aci_memory
  tags                      = local.common_tags
  depends_on                = [module.network, module.identity]
}

module "database" {
  source = "../../modules/database-cosmos"

  enabled             = var.enable_cosmosdb
  account_name        = local.cosmos_name
  database_name       = var.cosmosdb_database_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  allowed_subnet_ids  = [module.network.vm_subnet_id, module.network.aci_subnet_id]
  tags                = local.common_tags
  depends_on          = [module.network]
}

module "rbac" {
  source = "../../modules/rbac"

  principal_id        = module.identity.principal_id
  resource_group_id   = module.resource_group.id
  storage_account_id  = module.storage.id
  key_vault_id        = module.key_vault.id
  cosmosdb_account_id = module.database.account_id
  grant_rg_reader     = var.vm_grant_rg_reader
  depends_on          = [time_sleep.after_key_vault]
}

resource "azurerm_role_assignment" "current_principal_key_vault_admin" {
  scope                = module.key_vault.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
  depends_on           = [time_sleep.after_key_vault]
}

resource "azurerm_role_assignment" "app_principal_key_vault_secrets_user" {
  count = var.key_vault_grant_app_secrets_user_role && var.app_principal_object_id != null ? 1 : 0

  scope                = module.key_vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.app_principal_object_id
  depends_on           = [time_sleep.after_key_vault]
}

module "sql" {
  source = "../../modules/database-sql"

  enabled             = var.enable_sql
  server_name         = local.sql_server_name
  database_name       = var.sql_database_name
  sku_name            = var.sql_sku_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name

  vnet_id                    = module.network.vnet_id
  private_endpoint_subnet_id = module.network.private_endpoints_subnet_id

  audit_storage_endpoint  = module.storage.primary_blob_endpoint
  azuread_admin_login     = data.azurerm_client_config.current.client_id
  azuread_admin_object_id = data.azurerm_client_config.current.object_id

  tags       = local.common_tags
  depends_on = [module.network, module.storage]
}

module "recovery" {
  source = "../../modules/recovery"

  name                     = local.recovery_vault_name
  location                 = module.resource_group.location
  resource_group_name      = module.resource_group.name
  vm_ids                   = module.compute.vm_ids
  vm_count                 = var.vm_count
  enable_backup_protection = var.enable_backup_protection
  tags                     = local.common_tags
  depends_on               = [module.compute]
}
