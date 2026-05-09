locals {
  normalized_prefix = lower(replace(var.name_prefix, "/[^a-zA-Z0-9-]/", ""))
  normalized_env    = lower(replace(var.environment, "/[^a-zA-Z0-9-]/", ""))

  compact_prefix = lower(replace("${local.normalized_prefix}${local.normalized_env}", "/[^a-zA-Z0-9]/", ""))

  resource_group_name = "rg-${local.normalized_prefix}-${local.normalized_env}"
  vnet_name           = "vnet-${local.normalized_prefix}-${local.normalized_env}"

  storage_account_name = substr("st${local.compact_prefix}", 0, 24)
  key_vault_name       = substr("kv-${local.normalized_prefix}-${local.normalized_env}", 0, 24)
  recovery_vault_name  = substr("rsv-${local.normalized_prefix}-${local.normalized_env}", 0, 50)
  aci_name             = substr("aci-${local.normalized_prefix}-${local.normalized_env}", 0, 63)
  identity_name        = substr("uami-${local.normalized_prefix}-${local.normalized_env}", 0, 64)
  cosmos_name          = substr("cosmos-${local.compact_prefix}", 0, 44)
  common_tags = {
    project     = "cloudsentinel"
    environment = local.normalized_env
    owner       = "devsecops"
    managed_by  = "opentofu"
    cost_center = "student-lab"
  }
}
