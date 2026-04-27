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

variable "public_subnet_nsg_id" {
  description = "Network Security Group ID to associate with the public subnet."
  type        = string
  default     = null
}

variable "private_subnet_nsg_id" {
  description = "Network Security Group ID to associate with the private subnet."
  type        = string
  default     = null
}

variable "associate_public_nsg" {
  description = "Whether to associate an NSG with the public subnet. Must be a static bool, not derived from a resource attribute."
  type        = bool
  default     = false
}

variable "associate_private_nsg" {
  description = "Whether to associate an NSG with the private subnet. Must be a static bool, not derived from a resource attribute."
  type        = bool
  default     = false
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
