variable "project_name" {
  description = "Project short name used in resource naming."
  type        = string
  default     = "csstudent"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.project_name))
    error_message = "project_name must match ^[a-z0-9-]{3,20}$"
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be one of: dev, test, prod."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "norwayeast"
}

variable "admin_username" {
  description = "Linux VM admin username."
  type        = string
  default     = "cloudadmin"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{2,30}$", var.admin_username))
    error_message = "admin_username is invalid for Linux VM user naming constraints."
  }
}

variable "admin_ssh_public_key" {
  description = "SSH public key for VM admin access."
  type        = string

  validation {
    condition     = can(regex("^ssh-rsa\\s+[A-Za-z0-9+/=]+(?:\\s+.*)?$", trimspace(var.admin_ssh_public_key)))
    error_message = "admin_ssh_public_key must be an RSA public key in OpenSSH format (starts with 'ssh-rsa ')."
  }
}

variable "admin_allowed_cidr" {
  description = "CIDR allowed to SSH to VM."
  type        = string
  default     = "203.0.113.10/32"
}

variable "vnet_cidr" {
  description = "CIDR for virtual network."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for public subnet."
  type        = string
  default     = "10.42.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR for private application subnet."
  type        = string
  default     = "10.42.2.0/24"
}

variable "db_subnet_cidr" {
  description = "CIDR for database delegated subnet."
  type        = string
  default     = "10.42.3.0/24"
}

variable "vm_size" {
  description = "VM SKU (cost-optimized for Student subscription)."
  type        = string
  default     = "Standard_B1s"
}

variable "mysql_sku_name" {
  description = "MySQL Flexible Server SKU (cost-optimized)."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "mysql_admin_username" {
  description = "MySQL administrator username."
  type        = string
  default     = "mysqladmin"
}

variable "enable_database" {
  description = "Enable managed MySQL deployment. Disable for Azure Student regions with capacity restrictions."
  type        = bool
  default     = false
}

variable "manage_database_secrets_in_key_vault" {
  description = "Write MySQL admin credentials to Key Vault from IaC. Disable when CI principal lacks Key Vault data-plane rights."
  type        = bool
  default     = false
}

variable "db_secret_expiration_date" {
  description = "Expiration date for database credentials stored in Key Vault (RFC3339)."
  type        = string
  default     = "2030-01-01T00:00:00Z"
}

variable "tags" {
  description = "Common tags for governance and traceability."
  type        = map(string)
  default = {
    ManagedBy   = "Terraform"
    Security    = "CloudSentinel"
    CostProfile = "Student-Minimal"
  }
}
