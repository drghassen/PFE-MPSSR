locals {
  base_name = "${var.project_name}-${var.environment}"
  tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    Module      = "student-secure"
  })
}

module "resource_group" {
  source = "./modules/resource_group"

  name     = "rg-${local.base_name}-${var.location}"
  location = var.location
  tags     = local.tags
}

module "network" {
  source = "./modules/network"

  base_name           = local.base_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  vnet_cidr           = var.vnet_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  db_subnet_cidr      = var.db_subnet_cidr
  admin_allowed_cidr  = var.admin_allowed_cidr
  tags                = local.tags
}

module "key_vault" {
  source = "./modules/key_vault"

  base_name           = local.base_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  tenant_id           = module.resource_group.tenant_id
  private_subnet_id   = module.network.private_subnet_id
  virtual_network_id  = module.network.vnet_id
  key_expiration_date = var.key_vault_cmk_expiration_date
  cmk_key_name        = "storage-cmk-${var.environment}"
  existing_cmk_key_id = var.key_vault_existing_cmk_key_id
  tags                = local.tags
}

module "storage" {
  source = "./modules/storage"

  base_name                  = local.base_name
  location                   = module.resource_group.location
  resource_group_name        = module.resource_group.name
  key_vault_id               = module.key_vault.id
  key_vault_key_id           = module.key_vault.cmk_key_id
  virtual_network_id         = module.network.vnet_id
  private_subnet_id          = module.network.private_subnet_id
  storage_allowed_subnet_ids = [module.network.public_subnet_id, module.network.private_subnet_id, module.network.db_subnet_id]
  tags                       = local.tags
}

module "monitoring" {
  source = "./modules/monitoring"

  base_name                           = local.base_name
  location                            = module.resource_group.location
  resource_group_name                 = module.resource_group.name
  network_watcher_name                = "NetworkWatcher_${lower(module.resource_group.location)}"
  network_watcher_resource_group_name = "NetworkWatcherRG"
  subscription_id                     = var.subscription_id
  storage_account_id                  = module.storage.id
  key_vault_id                        = module.key_vault.id
  network_security_ids                = module.network.nsg_ids
  tags                                = local.tags
}

module "database" {
  source = "./modules/database"

  enabled                  = var.enable_database
  manage_key_vault_secrets = var.manage_database_secrets_in_key_vault
  base_name                = local.base_name
  location                 = module.resource_group.location
  resource_group_name      = module.resource_group.name
  delegated_subnet_id      = module.network.db_subnet_id
  private_subnet_id        = module.network.private_subnet_id
  virtual_network_id       = module.network.vnet_id
  mysql_sku_name           = var.mysql_sku_name
  mysql_admin_username     = var.mysql_admin_username
  key_vault_id             = module.key_vault.id
  secret_expiration_date   = var.db_secret_expiration_date
  tags                     = local.tags

  depends_on = [module.key_vault]
}

module "compute" {
  source = "./modules/compute"

  base_name              = local.base_name
  location               = module.resource_group.location
  resource_group_name    = module.resource_group.name
  subnet_id              = module.network.public_subnet_id
  vm_size                = var.vm_size
  admin_username         = var.admin_username
  admin_ssh_public_key   = var.admin_ssh_public_key
  tags                   = local.tags
  encryption_at_host_enabled = var.enable_vm_encryption_at_host
  # CKV2_CS_AZ_010 — CMK disk encryption via Disk Encryption Set.
  # The key_vault module provisions the DES when CMK is configured.
  disk_encryption_set_id = module.key_vault.disk_encryption_set_id
}
