resource "azurerm_network_security_group" "open_prefixes" {
  name                = "nsg-open-prefixes"
  location            = "westeurope"
  resource_group_name = "rg-test"
}

# SSH ouvert avec liste de prefixes internet (source_address_prefixes)
resource "azurerm_network_security_rule" "ssh_any_allow_prefixes" {
  name                        = "ssh-any-allow-prefixes"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = ["0.0.0.0/0"]
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.open_prefixes.name
}

# RDP ouvert avec liste de prefixes internet (source_address_prefixes)
resource "azurerm_network_security_rule" "rdp_any_allow_prefixes" {
  name                        = "rdp-any-allow-prefixes"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefixes     = ["Internet"]
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.open_prefixes.name
}
