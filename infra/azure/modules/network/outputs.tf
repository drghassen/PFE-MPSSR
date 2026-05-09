output "vnet_id" {
  value = azurerm_virtual_network.this.id
}

output "vnet_name" {
  value = azurerm_virtual_network.this.name
}

output "vm_subnet_id" {
  value = azurerm_subnet.vm.id
}

output "aci_subnet_id" {
  value = azurerm_subnet.aci.id
}

output "private_endpoints_subnet_id" {
  value = azurerm_subnet.private_endpoints.id
}

output "vm_nsg_id" {
  value = azurerm_network_security_group.vm.id
}

output "aci_nsg_id" {
  value = azurerm_network_security_group.aci.id
}

output "public_ip_id" {
  value = azurerm_public_ip.vm.id
}

output "public_ip_address" {
  value = azurerm_public_ip.vm.ip_address
}
