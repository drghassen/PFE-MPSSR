variable "location" {
  description = "Region Azure pour le deploiement"
  type        = string
}

variable "environment" {
  description = "Environnement cible"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "L'environnement doit etre l'un des suivants : dev, staging, prod."
  }
}

variable "project_name" {
  description = "Nom du projet"
  type        = string
}

variable "owner" {
  description = "Responsable de la ressource"
  type        = string
}

variable "common_tags" {
  description = "Metadonnees pour gouvernance"
  type        = map(string)
  default     = {}
}

variable "admin_username" {
  description = "Username administrateur pour la VM de test"
  type        = string
  default     = "cloudadmin"
}

# Risky by design for security testing: password auth is enabled and value is kept in tfvars.
variable "admin_password" {
  description = "Mot de passe administrateur pour la VM"
  type        = string
  sensitive   = true
}

variable "vm_size" {
  description = "SKU de VM pour l'environnement de test"
  type        = string
  default     = "Standard_B1s"
}
