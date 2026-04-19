variable "name_prefix" {
  description = "Prefix used to name compute resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where compute resources are deployed."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID where NIC and VM are deployed."
  type        = string
}

variable "nsg_id" {
  description = "Network Security Group ID to attach to NIC."
  type        = string
}

variable "admin_username" {
  description = "Admin username for VM login."
  type        = string
  default     = "cloudsentinel"
}

variable "admin_ssh_public_key" {
  description = "SSH public key used for VM access."
  type        = string
}

variable "vm_size" {
  description = "Azure VM SKU."
  type        = string
  default     = "Standard_B2s"
}

variable "assign_public_ip" {
  description = "Assign a public IP to the VM NIC (false by default)."
  type        = bool
  default     = false
}

variable "user_assigned_identity_id" {
  description = "User-assigned managed identity ID attached to the VM."
  type        = string
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for VM diagnostics."
  type        = string
}

variable "cloud_init_content" {
  description = "Base64-encoded cloud-init user-data. Scanned by CloudSentinel cloudinit-scanner — DB packages or security bypass patterns will trigger violations."
  type        = string
  default     = null
  sensitive   = false
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
