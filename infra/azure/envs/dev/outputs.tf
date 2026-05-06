output "resource_group_name" {
  description = "Resource group name."
  value       = module.resource_group.name
}

output "vnet_name" {
  description = "VNet name."
  value       = module.network.vnet_name
}

output "vm_name" {
  description = "Application VM name."
  value       = module.compute.name
}

output "vm_private_ip" {
  description = "Application VM private IP."
  value       = module.compute.private_ip
}

output "key_vault_name" {
  description = "Key Vault name."
  value       = module.key_vault.name
}

output "key_vault_uri" {
  description = "Key Vault URI."
  value       = module.key_vault.vault_uri
}

output "postgres_server_name" {
  description = "PostgreSQL server name."
  value       = module.postgresql.name
}

output "postgres_fqdn" {
  description = "PostgreSQL server private FQDN."
  value       = module.postgresql.fqdn
}

output "bastion_name" {
  description = "Bastion host name."
  value       = module.bastion.name
}

output "bastion_public_ip" {
  description = "Bastion public IP (only public entrypoint)."
  value       = module.bastion.public_ip
}

output "nsg_deny_all_policy_definition_id" {
  description = "Custom Azure Policy definition ID enforcing NSG DenyAllInbound baseline."
  value       = try(azurerm_policy_definition.nsg_deny_all_inbound_baseline[0].id, null)
}

output "nsg_deny_all_policy_assignment_id" {
  description = "Azure Policy assignment ID for NSG DenyAllInbound baseline."
  value       = try(azurerm_resource_group_policy_assignment.nsg_deny_all_inbound_baseline[0].id, null)
}
