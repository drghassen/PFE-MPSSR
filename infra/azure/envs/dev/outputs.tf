output "resource_group_name" {
  value = module.resource_group.name
}

output "vnet_name" {
  value = module.network.vnet_name
}

output "vm_names" {
  value = module.compute.vm_names
}

output "vm_private_ips" {
  value = module.compute.vm_private_ips
}

output "public_ip" {
  value = module.network.public_ip_address
}

output "storage_account_name" {
  value = module.storage.name
}

output "key_vault_name" {
  value = module.key_vault.name
}

output "managed_identity_principal_id" {
  value = module.identity.principal_id
}

output "recovery_vault_name" {
  value = module.recovery.name
}

output "cosmosdb_account_name" {
  value = module.database.account_name
}
