variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "server_name" {
  description = "PostgreSQL flexible server name."
  type        = string
}

variable "database_name" {
  description = "Application database name."
  type        = string
}

variable "administrator_login" {
  description = "PostgreSQL admin username."
  type        = string
}

variable "administrator_password" {
  description = "PostgreSQL admin password."
  type        = string
  sensitive   = true
}

variable "delegated_subnet_id" {
  description = "Delegated subnet ID for PostgreSQL flexible server."
  type        = string
}

variable "virtual_network_id" {
  description = "Virtual network ID to link private DNS zone."
  type        = string
}

variable "private_dns_zone_name" {
  description = "Private DNS zone for PostgreSQL."
  type        = string
  default     = "privatelink.postgres.database.azure.com"
}

variable "postgresql_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "14"
}

variable "availability_zone" {
  description = "Availability zone for PostgreSQL server."
  type        = string
  default     = "1"
}

variable "storage_mb" {
  description = "Storage size in MB."
  type        = number
  default     = 32768
}

variable "sku_name" {
  description = "PostgreSQL flexible server SKU."
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "backup_retention_days" {
  description = "Backup retention period."
  type        = number
  default     = 14
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for diagnostics."
  type        = string
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
