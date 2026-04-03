output "id" {
  value = azurerm_resource_group.this.id
}

output "name" {
  value = azurerm_resource_group.this.name
}

output "location" {
  value = azurerm_resource_group.this.location
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}
