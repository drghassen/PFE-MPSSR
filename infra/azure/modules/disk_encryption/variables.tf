variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "name_prefix" {
  description = "Global naming prefix."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "key_vault_id" {
  description = "ID of the Key Vault that holds the disk CMK."
  type        = string
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
