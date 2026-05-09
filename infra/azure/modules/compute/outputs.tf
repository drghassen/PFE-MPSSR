output "vm_ids" {
  value = compact([
    azurerm_linux_virtual_machine.vm1.id,
    try(azurerm_linux_virtual_machine.vm2[0].id, null),
  ])
}

output "vm_names" {
  value = compact([
    azurerm_linux_virtual_machine.vm1.name,
    try(azurerm_linux_virtual_machine.vm2[0].name, null),
  ])
}

output "vm_private_ips" {
  value = compact([
    azurerm_network_interface.vm1.private_ip_address,
    try(azurerm_network_interface.vm2[0].private_ip_address, null),
  ])
}
