variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "vm_size" {
  type = string
}

variable "admin_username" {
  type = string
}

variable "admin_ssh_public_key" {
  type        = string
  description = "RSA public key for SSH access. Password authentication is disabled."

  validation {
    condition     = can(regex("^ssh-rsa\\s+[A-Za-z0-9+/=]+(?:\\s+.*)?$", trimspace(var.admin_ssh_public_key)))
    error_message = "admin_ssh_public_key must be an RSA public key in OpenSSH format (starts with 'ssh-rsa ')."
  }
}

variable "tags" {
  type = map(string)
}

# CKV2_CS_AZ_010 / CIS 7.1 — Disk Encryption Set ID for CMK disk encryption.
# When set, the OS disk is encrypted with a customer-managed key via an Azure
# Disk Encryption Set. Set to null to use platform-managed keys (PMK) only,
# which is acceptable in dev environments without the EncryptionAtHost feature.
variable "disk_encryption_set_id" {
  type        = string
  description = "Azure Disk Encryption Set resource ID for CMK OS disk encryption. Null = platform-managed key."
  default     = null
}

# Azure Student subscriptions often do not expose the
# Microsoft.Compute/EncryptionAtHost feature.
variable "encryption_at_host_enabled" {
  type        = bool
  description = "Enable EncryptionAtHost on the VM when the subscription supports it."
  default     = false
}
