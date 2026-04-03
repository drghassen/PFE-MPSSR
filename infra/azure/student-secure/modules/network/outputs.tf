output "vnet_id" {
  value = azurerm_virtual_network.this.id
}

output "public_subnet_id" {
  value = azurerm_subnet.public.id
}

output "private_subnet_id" {
  value = azurerm_subnet.private.id
}

output "db_subnet_id" {
  value = azurerm_subnet.db.id
}

output "nsg_ids" {
  value = {
    public  = azurerm_network_security_group.public.id
    private = azurerm_network_security_group.private.id
    db      = azurerm_network_security_group.db.id
  }
}
