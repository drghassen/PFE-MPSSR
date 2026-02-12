variable "location" {
  description = "Région Azure pour le déploiement"
  type        = string
}

variable "environment" {
  description = "Environnement cible"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "L'environnement doit être l'un des suivants : dev, staging, prod."
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
  description = "Métadonnées pour gouvernance"
  type        = map(string)
  default     = {}
}