variable "subscription_id" {
  description = "Azure subscription ID where resources will be deployed."
  type        = string
  nullable    = false
}

variable "location" {
  description = "Azure region for deployment."
  type        = string
  default     = "westeurope"
}

variable "name_prefix" {
  description = "Prefix for all resources."
  type        = string
  default     = "cs-dev"
}

variable "vnet_cidr" {
  description = "CIDR block for VNet."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet."
  type        = string
  default     = "10.42.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet."
  type        = string
  default     = "10.42.2.0/24"
}

variable "create_nat_gateway" {
  description = "Enable NAT gateway for controlled private subnet egress."
  type        = bool
  default     = true
}

variable "ssh_allowed_cidr" {
  description = "Trusted source CIDR allowed for SSH. Must never be 0.0.0.0/0 in non-dev environments."
  type        = string
  default     = "10.0.0.0/24"
}

variable "admin_username" {
  description = "Admin username used for SSH access."
  type        = string
  default     = "cloudsentinel"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for VM access."
  type        = string
}

variable "vm_size" {
  description = "VM SKU for the workload node."
  type        = string
  default     = "Standard_B2s"
}

variable "assign_public_ip" {
  description = "Attach public IP to VM (false by default for secure posture)."
  type        = bool
  default     = false
}

variable "create_ci_identity" {
  description = "Create a dedicated CI/CD managed identity with read-only RBAC."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log Analytics retention period in days."
  type        = number
  default     = 30
}

variable "allow_http_inbound" {
  description = "Allow HTTP inbound on port 80 (enable for public-facing VM)."
  type        = bool
  default     = false
}

variable "db_admin_login" {
  description = "PostgreSQL administrator username."
  type        = string
  default     = "csadmin"
}

variable "db_admin_password" {
  description = "PostgreSQL administrator password (use CI/CD masked variable)."
  type        = string
  sensitive   = true
}

variable "db_sku_name" {
  description = "PostgreSQL Flexible Server SKU — B_Standard_B1ms is cheapest (~13$/month)."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "cloudsentinel"
}

variable "db_allowed_ips" {
  description = "IPs allowed through the DB firewall. Add VM public IP + your own IP after first apply."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Extra tags merged with the mandatory baseline tags."
  type        = map(string)
  default     = {}
}
