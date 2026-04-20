variable "name_prefix" {
  description = "Prefix used to name database resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where the database is deployed."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "admin_login" {
  description = "PostgreSQL administrator username."
  type        = string
}

variable "key_vault_id" {
  description = "Azure Key Vault ID that holds the DB administrator password secret."
  type        = string
}

variable "db_password_secret_name" {
  description = "Name of the Key Vault secret that contains the DB administrator password."
  type        = string
  default     = "db-admin-password"
}

variable "sku_name" {
  description = "PostgreSQL Flexible Server SKU (Burstable B1ms is cheapest)."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "cloudsentinel"
}

variable "allowed_ips" {
  description = "List of IPs allowed to connect to the DB (add VM public IP + your own IP)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
