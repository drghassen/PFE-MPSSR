variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "vnet_name" {
  type = string
}

variable "vnet_cidr" {
  type = string
}

variable "vm_subnet_name" {
  type = string
}

variable "vm_subnet_cidr" {
  type = string
}

variable "aci_subnet_name" {
  type = string
}

variable "aci_subnet_cidr" {
  type = string
}

variable "private_endpoints_subnet_name" {
  type = string
}

variable "private_endpoints_subnet_cidr" {
  type = string
}

variable "vm_nsg_name" {
  type = string
}

variable "aci_nsg_name" {
  type = string
}

variable "pe_nsg_name" {
  type = string
}

variable "public_ip_name" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
