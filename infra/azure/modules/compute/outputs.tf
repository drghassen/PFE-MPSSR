output "id" {
  description = "VM ID."
  value       = azurerm_linux_virtual_machine.this.id
}

output "name" {
  description = "VM name."
  value       = azurerm_linux_virtual_machine.this.name
}

output "private_ip" {
  description = "Private IP address of VM NIC."
  value       = azurerm_network_interface.this.private_ip_address
}

output "principal_id" {
  description = "Managed identity principal ID."
  value       = azurerm_linux_virtual_machine.this.identity[0].principal_id
}
