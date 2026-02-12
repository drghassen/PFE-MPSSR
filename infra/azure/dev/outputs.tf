output "resource_group_name" {
  description = "The name of the resource group created"
  value       = azurerm_resource_group.app.name
}

output "resource_group_id" {
  description = "The ID of the resource group created"
  value       = azurerm_resource_group.app.id
}


