variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "resource_group_id" {
  description = "Resource group ID used for RBAC scope."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "vm_name" {
  description = "VM name."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID where VM NIC is deployed."
  type        = string
}

variable "admin_username" {
  description = "Admin username for VM."
  type        = string
}

variable "admin_ssh_public_key" {
  description = "Admin SSH public key for VM login."
  type        = string
}

variable "vm_size" {
  description = "Azure VM size."
  type        = string
  default     = "Standard_B2s"
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB."
  type        = number
  default     = 64
}

variable "cloud_init" {
  description = "Optional cloud-init content."
  type        = string
  default     = null
}

variable "grant_rg_reader" {
  description = "Grant Reader role to VM managed identity at RG scope."
  type        = bool
  default     = true
}

variable "encryption_at_host_enabled" {
  description = "Enable host-based encryption for VM (requires Microsoft.Compute/EncryptionAtHost feature)."
  type        = bool
  default     = false
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
