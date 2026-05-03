variable "subscription_id" {
  description = "Azure subscription ID."
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "norwayeast"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "dev"
}

variable "name_prefix" {
  description = "Global naming prefix (short, lowercase, unique)."
  type        = string
  default     = "csdemo"
}

variable "owner" {
  description = "Resource owner tag."
  type        = string
  default     = "cloudsentinel"
}

variable "cost_center" {
  description = "Cost center tag."
  type        = string
  default     = "security"
}

variable "vnet_cidr" {
  description = "VNet CIDR block."
  type        = string
  default     = "10.40.0.0/16"
}

variable "app_subnet_cidr" {
  description = "CIDR for app subnet."
  type        = string
  default     = "10.40.1.0/24"
}

variable "private_endpoints_subnet_cidr" {
  description = "CIDR for private endpoint subnet."
  type        = string
  default     = "10.40.3.0/24"
}

variable "data_subnet_cidr" {
  description = "CIDR for data subnet."
  type        = string
  default     = "10.40.2.0/24"
}

variable "bastion_subnet_cidr" {
  description = "CIDR for Azure Bastion subnet (minimum /26)."
  type        = string
  default     = "10.40.4.0/26"
}

variable "vm_admin_username" {
  description = "Linux VM admin username."
  type        = string
  default     = "azureadmin"
}

variable "vm_admin_ssh_public_key" {
  description = "SSH public key for VM admin access."
  type        = string
}

variable "vm_size" {
  description = "Linux VM size."
  type        = string
  default     = "Standard_B2s"
}

variable "vm_os_disk_size_gb" {
  description = "Linux VM OS disk size in GB."
  type        = number
  default     = 64
}

variable "vm_encryption_at_host_enabled" {
  description = "Enable host encryption for VM (set true only if subscription feature is enabled)."
  type        = bool
  default     = false
}

variable "vm_grant_rg_reader" {
  description = "Grant Reader role on RG to VM managed identity (requires roleAssignments/write)."
  type        = bool
  default     = false
}

variable "cloud_init" {
  description = "Optional cloud-init content for VM bootstrap."
  type        = string
  default     = null
}

variable "postgres_admin_username" {
  description = "PostgreSQL admin username."
  type        = string
  default     = "pgadmincs"
}

variable "postgres_admin_password" {
  description = "PostgreSQL admin password."
  type        = string
  sensitive   = true
}

variable "postgres_db_name" {
  description = "Application database name."
  type        = string
  default     = "patient_finance_db"
}

variable "postgres_sku_name" {
  description = "PostgreSQL SKU."
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB."
  type        = number
  default     = 32768
}

variable "postgres_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "14"
}

variable "log_analytics_retention_days" {
  description = "Log Analytics retention days."
  type        = number
  default     = 90
}

variable "key_vault_grant_app_secrets_user_role" {
  description = "Grant Key Vault Secrets User role to VM identity (requires roleAssignments/write)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# VM Backup  (Prowler: vm_backup_enabled)
# ---------------------------------------------------------------------------

variable "vm_backup_retention_days" {
  description = "Number of daily VM recovery points to retain in Azure Backup."
  type        = number
  default     = 30
}

# ---------------------------------------------------------------------------
# Network Watcher + NSG Flow Logs  (Prowler: network_watcher_enabled)
# ---------------------------------------------------------------------------

variable "network_watcher_name" {
  description = "Name of the existing Network Watcher. Azure auto-creates NetworkWatcher_<region>."
  type        = string
  default     = "NetworkWatcher_norwayeast"
}

variable "network_watcher_rg" {
  description = "Resource group that contains the Network Watcher. Azure default is NetworkWatcherRG."
  type        = string
  default     = "NetworkWatcherRG"
}

variable "flow_log_retention_days" {
  description = "NSG flow log retention in days. CIS Azure 6.5 minimum is 90."
  type        = number
  default     = 90
}

variable "traffic_analytics_interval_minutes" {
  description = "Traffic Analytics processing interval: 10 (near-real-time) or 60 (hourly)."
  type        = number
  default     = 10
}
