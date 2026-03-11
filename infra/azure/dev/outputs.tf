output "resource_group_name" {
  description = "The name of the resource group created"
  value       = azurerm_resource_group.app.name
}

output "resource_group_id" {
  description = "The ID of the resource group created"
  value       = azurerm_resource_group.app.id
}

output "vnet_id" {
  description = "Enterprise virtual network ID"
  value       = module.network.vnet_id
}

output "app_subnet_id" {
  description = "Application subnet ID"
  value       = module.network.app_subnet_id
}

output "storage_account_name" {
  description = "Main storage account name"
  value       = module.storage.storage_account_name
}

output "storage_public_container" {
  description = "Publicly readable container name"
  value       = module.storage.public_container_name
}

output "identity_principal_id" {
  description = "Principal ID of user-assigned identity"
  value       = module.iam.identity_principal_id
}

output "vm_id" {
  description = "Virtual machine ID"
  value       = module.compute.vm_id
}

output "vm_public_ip" {
  description = "Public IP of the VM"
  value       = module.compute.vm_public_ip
}
