variable "resource_group_name" {
  description = "Resource group name hosting networking resources."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "name_prefix" {
  description = "Naming prefix for resources."
  type        = string
}

variable "vnet_name" {
  description = "Virtual network name."
  type        = string
}

variable "vnet_cidr" {
  description = "VNet CIDR."
  type        = string
}

variable "app_subnet_name" {
  description = "Application subnet name."
  type        = string
  default     = "snet-app"
}

variable "app_subnet_cidr" {
  description = "Application subnet CIDR."
  type        = string
}

variable "private_endpoints_subnet_name" {
  description = "Private endpoint subnet name."
  type        = string
  default     = "snet-pe"
}

variable "private_endpoints_subnet_cidr" {
  description = "Private endpoints subnet CIDR."
  type        = string
}

variable "data_subnet_name" {
  description = "Data subnet name."
  type        = string
  default     = "snet-data"
}

variable "data_subnet_cidr" {
  description = "Data subnet CIDR."
  type        = string
}

variable "bastion_subnet_cidr" {
  description = "AzureBastionSubnet CIDR (must be /26 or larger)."
  type        = string
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
