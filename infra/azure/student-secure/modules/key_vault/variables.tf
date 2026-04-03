variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "private_subnet_id" {
  type = string
}

variable "virtual_network_id" {
  type = string
}

variable "key_expiration_date" {
  type = string
}

variable "tags" {
  type = map(string)
}
