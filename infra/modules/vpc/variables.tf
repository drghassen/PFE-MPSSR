variable "name_prefix" {
  description = "Prefix used to name networking resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where networking resources are deployed."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "vnet_cidr" {
  description = "CIDR block for the virtual network."
  type        = string
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private subnet."
  type        = string
}

variable "create_nat_gateway" {
  description = "Create a NAT gateway for private subnet outbound internet access."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
