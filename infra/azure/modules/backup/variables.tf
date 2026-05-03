variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "vault_name" {
  description = "Recovery Services Vault name."
  type        = string
}

variable "vm_id" {
  description = "ID of the VM to protect with Azure Backup."
  type        = string
}

variable "backup_retention_days" {
  description = "Number of daily recovery points to retain."
  type        = number
  default     = 30
}

variable "backup_time" {
  description = "UTC time for daily backup window (HH:MM)."
  type        = string
  default     = "02:00"
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
