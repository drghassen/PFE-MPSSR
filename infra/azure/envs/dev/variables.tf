variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "francecentral"
}

variable "name_prefix" {
  description = "Prefix for resource naming"
  type        = string
  default     = "cslab"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vnet_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "vm_subnet_cidr" {
  type    = string
  default = "10.40.1.0/24"
}

variable "aci_subnet_cidr" {
  type    = string
  default = "10.40.2.0/24"
}

variable "private_endpoints_subnet_cidr" {
  type    = string
  default = "10.40.3.0/24"
}

variable "vm_count" {
  description = "Number of VMs (1 or 2)"
  type        = number
  default     = 1

  validation {
    condition     = var.vm_count == 1 || var.vm_count == 2
    error_message = "vm_count must be 1 or 2."
  }
}

variable "assign_public_ip" {
  description = "Attach public IP to VM1"
  type        = bool
  default     = true
}

variable "vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "vm_admin_username" {
  type    = string
  default = "azureuser"
}

variable "vm_admin_ssh_public_key" {
  description = "SSH public key for VM admin"
  type        = string
  sensitive   = true
}

variable "vm_encryption_at_host_enabled" {
  description = "Enable encryption at host for VMs"
  type        = bool
  default     = true
}

variable "vm_enable_trusted_launch" {
  description = "Enable trusted launch (Secure Boot + vTPM) for VMs"
  type        = bool
  default     = false
}

variable "vm_grant_rg_reader" {
  description = "Grant Reader at resource-group scope to the managed identity"
  type        = bool
  default     = false
}

variable "storage_allowed_ip_rules" {
  description = "Optional public IP allowlist for storage data plane"
  type        = list(string)
  default     = []
}

variable "aci_image" {
  type    = string
  default = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
}

variable "aci_cpu" {
  type    = number
  default = 1
}

variable "aci_memory" {
  type    = number
  default = 1.5
}

variable "enable_backup_protection" {
  type    = bool
  default = true
}

variable "enable_cosmosdb" {
  description = "Enable optional Cosmos DB serverless for DB security testing"
  type        = bool
  default     = false
}

variable "cosmosdb_database_name" {
  type    = string
  default = "cloudsentinel"
}

variable "key_vault_grant_app_secrets_user_role" {
  description = "Grant Key Vault Secrets User role to app_principal_object_id"
  type        = bool
  default     = false
}

variable "app_principal_object_id" {
  description = "Object ID of app principal to grant Key Vault Secrets User"
  type        = string
  default     = null
}

variable "enable_sql" {
  description = "Enable Azure SQL Server + Database"
  type        = bool
  default     = true
}

variable "sql_database_name" {
  description = "Name of the SQL database"
  type        = string
  default     = "cloudsentinel"
}

variable "sql_sku_name" {
  description = "SQL DB SKU (Free or Basic recommended for Azure Student)"
  type        = string
  default     = "Free"
}
