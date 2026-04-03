output "id" {
  value = azurerm_linux_virtual_machine.this.id
}

output "public_ip_address" {
  value = null
}

output "private_ip_address" {
  value = azurerm_network_interface.this.private_ip_address
}
