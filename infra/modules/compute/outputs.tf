output "vm_id" {
  description = "Virtual machine ID."
  value       = azurerm_linux_virtual_machine.this.id
}

output "vm_name" {
  description = "Virtual machine name."
  value       = azurerm_linux_virtual_machine.this.name
}

output "private_ip" {
  description = "Private IP address of the VM NIC."
  value       = azurerm_network_interface.this.private_ip_address
}

output "public_ip" {
  description = "Public IP address when enabled."
  value       = try(azurerm_public_ip.vm[0].ip_address, null)
}
