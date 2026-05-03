variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "bastion_name" {
  description = "Azure Bastion name."
  type        = string
}

variable "bastion_subnet_id" {
  description = "Subnet ID for Azure Bastion (must be AzureBastionSubnet)."
  type        = string
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
