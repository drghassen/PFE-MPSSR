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
