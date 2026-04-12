output "resource_group_id" {
  description = "Resource Group ID"
  value       = module.resource_group.id
}

output "virtual_network_id" {
  description = "Virtual network ID"
  value       = module.network.vnet_id
}

output "subnet_ids" {
  description = "Subnet IDs"
  value = {
    public  = module.network.public_subnet_id
    private = module.network.private_subnet_id
    db      = module.network.db_subnet_id
  }
}

output "network_security_group_ids" {
  description = "NSG IDs"
  value       = module.network.nsg_ids
}

output "storage_account_id" {
  description = "Storage account ID"
  value       = module.storage.id
}

output "storage_private_endpoints" {
  description = "Storage private endpoints (DNS endpoint + subnet scope)"
  sensitive   = true
  value = {
    blob_endpoint = module.storage.primary_blob_endpoint
    endpoint_id   = module.storage.private_endpoint_id
    subnet_ids    = module.storage.allowed_subnet_ids
    cmk_key_id    = module.storage.cmk_key_id
  }
}

output "storage_customer_managed_key_id" {
  description = "Storage customer-managed key association resource ID"
  sensitive   = true
  value       = module.storage.customer_managed_key_id
}

output "virtual_machine_id" {
  description = "VM ID"
  value       = module.compute.id
}

output "virtual_machine_public_ip" {
  description = "VM public IP (null by default; no direct internet exposure)"
  value       = module.compute.public_ip_address
}

output "virtual_machine_private_ip" {
  description = "VM private IP"
  value       = module.compute.private_ip_address
}

output "mysql_server_id" {
  description = "MySQL Flexible Server ID"
  value       = module.database.server_id
}

output "mysql_private_endpoint" {
  sensitive   = true
  description = "MySQL private endpoint details"
  value = {
    fqdn             = module.database.server_fqdn
    endpoint_id      = module.database.private_endpoint_id
    delegated_subnet = module.network.db_subnet_id
    private_dns_zone = module.database.private_dns_zone_id
  }
}

output "mysql_secret_ids" {
  description = "Key Vault secret IDs for MySQL credentials"
  sensitive   = true
  value = {
    username_secret_id = module.database.mysql_admin_username_secret_id
    password_secret_id = module.database.mysql_admin_password_secret_id
  }
}

output "key_vault_id" {
  description = "Key Vault ID"
  sensitive   = true
  value       = module.key_vault.id
}

output "key_vault_private_endpoint_id" {
  description = "Key Vault private endpoint ID"
  sensitive   = true
  value       = module.key_vault.private_endpoint_id
}

output "key_vault_cmk_key_id" {
  description = "Key Vault CMK key ID used by Storage encryption"
  sensitive   = true
  value       = module.key_vault.cmk_key_id
}
