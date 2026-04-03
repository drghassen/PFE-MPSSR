variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "key_vault_id" {
  type = string
}

variable "key_vault_key_id" {
  type = string
}

variable "virtual_network_id" {
  type = string
}

variable "private_subnet_id" {
  type = string
}

variable "storage_allowed_subnet_ids" {
  type = list(string)
}

variable "tags" {
  type = map(string)
}
