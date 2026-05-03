locals {
  base_tags = {
    environment = var.environment
    owner       = var.owner
    cost_center = var.cost_center
    managed_by  = "terraform"
    project     = "cloudsentinel"
    data_class  = "sensitive"
  }

  tags = merge(local.base_tags, var.tags)

  names = {
    resource_group = "rg-${var.name_prefix}-${var.environment}"
    vnet           = "vnet-${var.name_prefix}-${var.environment}"
    workspace      = "law-${var.name_prefix}-${var.environment}"
    vm             = "vm-${var.name_prefix}-app"
    bastion        = "bas-${var.name_prefix}-${var.environment}"
    key_vault      = "kv-${var.name_prefix}-${var.environment}"
    postgres       = "pg-${var.name_prefix}-${var.environment}"
    backup_vault    = "rsv-${var.name_prefix}-${var.environment}"
    # Azure Compute Gallery names: only alphanumeric, dots, underscores (no hyphens).
    compute_gallery = "acg.${var.name_prefix}.${var.environment}"
  }
}

module "resource_group" {
  source   = "../../modules/resource_group"
  name     = local.names.resource_group
  location = var.location
  tags     = local.tags
}

module "network" {
  source = "../../modules/network"

  resource_group_name           = module.resource_group.name
  location                      = module.resource_group.location
  name_prefix                   = var.name_prefix
  vnet_name                     = local.names.vnet
  vnet_cidr                     = var.vnet_cidr
  app_subnet_cidr               = var.app_subnet_cidr
  private_endpoints_subnet_cidr = var.private_endpoints_subnet_cidr
  data_subnet_cidr              = var.data_subnet_cidr
  bastion_subnet_cidr           = var.bastion_subnet_cidr
  tags                          = local.tags
}

module "monitoring" {
  source = "../../modules/monitoring"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  workspace_name      = local.names.workspace
  retention_in_days   = var.log_analytics_retention_days
  tags                = local.tags
}

module "compute_gallery" {
  source = "../../modules/compute_gallery"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  gallery_name        = local.names.compute_gallery
  tags                = local.tags
}

module "compute" {
  source = "../../modules/compute"

  resource_group_name        = module.resource_group.name
  resource_group_id          = module.resource_group.id
  location                   = module.resource_group.location
  vm_name                    = local.names.vm
  subnet_id                  = module.network.app_subnet_id
  admin_username             = var.vm_admin_username
  admin_ssh_public_key       = var.vm_admin_ssh_public_key
  vm_size                    = var.vm_size
  os_disk_size_gb            = var.vm_os_disk_size_gb
  encryption_at_host_enabled = var.vm_encryption_at_host_enabled
  grant_rg_reader            = var.vm_grant_rg_reader
  cloud_init                 = var.cloud_init
  disk_encryption_set_id     = module.disk_encryption.disk_encryption_set_id
  log_analytics_workspace_id = module.monitoring.workspace_id
  tags                       = local.tags
}

module "key_vault" {
  source = "../../modules/key_vault"

  resource_group_name            = module.resource_group.name
  location                       = module.resource_group.location
  key_vault_name                 = local.names.key_vault
  tenant_id                      = var.tenant_id
  private_endpoints_subnet_id    = module.network.private_endpoints_subnet_id
  virtual_network_id             = module.network.vnet_id
  app_principal_id               = module.compute.principal_id
  grant_app_kv_secrets_user_role = var.key_vault_grant_app_secrets_user_role
  log_analytics_workspace_id     = module.monitoring.workspace_id
  tags                           = local.tags
}

module "disk_encryption" {
  source = "../../modules/disk_encryption"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  name_prefix         = var.name_prefix
  environment         = var.environment
  key_vault_id        = module.key_vault.id
  tags                = local.tags

  depends_on = [module.key_vault]
}

module "postgresql" {
  source = "../../modules/postgresql"

  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  server_name                = local.names.postgres
  database_name              = var.postgres_db_name
  administrator_login        = var.postgres_admin_username
  administrator_password     = var.postgres_admin_password
  delegated_subnet_id        = module.network.data_subnet_id
  virtual_network_id         = module.network.vnet_id
  postgresql_version         = var.postgres_version
  sku_name                   = var.postgres_sku_name
  storage_mb                 = var.postgres_storage_mb
  log_analytics_workspace_id = module.monitoring.workspace_id
  tags                       = local.tags
}

module "bastion" {
  source = "../../modules/bastion"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  bastion_name        = local.names.bastion
  bastion_subnet_id   = module.network.bastion_subnet_id
  tags                = local.tags
}

module "backup" {
  source = "../../modules/backup"

  resource_group_name   = module.resource_group.name
  location              = module.resource_group.location
  vault_name            = local.names.backup_vault
  vm_id                 = module.compute.id
  backup_retention_days = var.vm_backup_retention_days
  tags                  = local.tags
}

module "network_watcher" {
  source = "../../modules/network_watcher"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  name_prefix         = var.name_prefix
  environment         = var.environment

  network_watcher_name = var.network_watcher_name
  network_watcher_rg   = var.network_watcher_rg

  log_analytics_workspace_name = local.names.workspace
  log_analytics_workspace_rg   = module.resource_group.name

  # Pass all four NSGs so every network boundary gets flow-logged.
  nsgs = {
    app               = module.network.nsg_app_id
    private-endpoints = module.network.nsg_private_endpoints_id
    data              = module.network.nsg_data_id
    bastion           = module.network.nsg_bastion_id
  }

  flow_log_retention_days            = var.flow_log_retention_days
  traffic_analytics_interval_minutes = var.traffic_analytics_interval_minutes
  tags                               = local.tags

  depends_on = [module.monitoring]
}
