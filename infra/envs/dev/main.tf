locals {
  mandatory_tags = {
    project             = "cloudsentinel"
    environment         = "dev"
    managed_by          = "opentofu"
    owner               = "platform-security"
    data_classification = "internal"
  }

  common_tags = merge(local.mandatory_tags, var.tags)
}

resource "azurerm_resource_group" "this" {
  name     = "${var.name_prefix}-rg"
  location = var.location
  tags     = local.common_tags
}

module "vpc" {
  source = "../../modules/vpc"

  name_prefix         = var.name_prefix
  resource_group_name = azurerm_resource_group.this.name
  location            = var.location
  vnet_cidr           = var.vnet_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  create_nat_gateway  = var.create_nat_gateway
  tags                = local.common_tags
}

module "security" {
  source = "../../modules/security"

  name_prefix         = var.name_prefix
  resource_group_name = azurerm_resource_group.this.name
  location            = var.location
  ssh_allowed_cidr    = var.ssh_allowed_cidr
  allow_http_inbound  = var.allow_http_inbound
  log_retention_days  = var.log_retention_days
  tags                = local.common_tags
}

module "iam" {
  source = "../../modules/iam"

  name_prefix         = var.name_prefix
  resource_group_name = azurerm_resource_group.this.name
  resource_group_id   = azurerm_resource_group.this.id
  location            = var.location
  create_ci_identity  = var.create_ci_identity
  tags                = local.common_tags
}

module "compute" {
  source = "../../modules/compute"

  name_prefix                = var.name_prefix
  resource_group_name        = azurerm_resource_group.this.name
  location                   = var.location
  subnet_id                  = module.vpc.public_subnet_id
  nsg_id                     = module.security.nsg_id
  admin_username             = var.admin_username
  admin_ssh_public_key       = var.admin_ssh_public_key
  vm_size                    = var.vm_size
  assign_public_ip           = var.assign_public_ip
  user_assigned_identity_id  = module.iam.vm_identity_id
  log_analytics_workspace_id = module.security.log_analytics_workspace_id
  tags                       = local.common_tags
}

module "database" {
  source = "../../modules/database"

  name_prefix         = var.name_prefix
  resource_group_name = azurerm_resource_group.this.name
  location            = var.location
  admin_login         = var.db_admin_login
  admin_password      = var.db_admin_password
  sku_name            = var.db_sku_name
  db_name             = var.db_name
  allowed_ips         = var.db_allowed_ips
  tags                = local.common_tags
}
