variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "delegated_subnet_id" {
  type = string
}

variable "private_subnet_id" {
  type = string
}

variable "virtual_network_id" {
  type = string
}

variable "mysql_sku_name" {
  type = string
}

variable "mysql_admin_username" {
  type = string
}

variable "key_vault_id" {
  type = string
}

variable "secret_expiration_date" {
  type = string
}

variable "tags" {
  type = map(string)
}
