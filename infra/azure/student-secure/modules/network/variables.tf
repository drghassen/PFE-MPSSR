variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "vnet_cidr" {
  type = string
}

variable "public_subnet_cidr" {
  type = string
}

variable "private_subnet_cidr" {
  type = string
}

variable "db_subnet_cidr" {
  type = string
}

variable "admin_allowed_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}
