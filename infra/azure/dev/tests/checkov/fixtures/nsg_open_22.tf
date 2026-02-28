resource "azurerm_network_security_group" "open_ssh" {
  name                = "nsg-open-ssh"
  location            = "westeurope"
  resource_group_name = "rg-test"
}

resource "azurerm_network_security_rule" "ssh_any_allow" {
  name                        = "ssh-any-allow"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  destination_port_ranges     = ["22"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.open_ssh.name
}

# RDP aussi ouvert pour déclencher CKV2_CS_AZ_017
resource "azurerm_network_security_rule" "rdp_any_allow" {
  name                        = "rdp-any-allow"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.open_ssh.name
}
