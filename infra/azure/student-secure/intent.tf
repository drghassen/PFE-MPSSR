# intent.tf — Intent Contract pour CloudSentinel Shift-Left
#
# Ce fichier déclare l'INTENTION de déploiement de cette ressource.
# CloudSentinel utilise ce contrat pour détecter le role spoofing :
# un dev déclare "web-server" mais configure une base de données exposée publiquement.
#
# OBLIGATOIRE : toute modification nécessite l'approbation d'un reviewer distinct (four-eyes).

variable "resource_intent" {
  description = "Contrat d'intention — déclare CE QUE cette ressource EST et QUI en est responsable. Utilisé par CloudSentinel pour détecter le role spoofing avant déploiement."
  type = object({
    service_type   = string
    exposure_level = string
    owner          = string
    approved_by    = string
  })

  validation {
    condition     = contains(["web-server", "database", "cache", "worker", "gateway"], var.resource_intent.service_type)
    error_message = "service_type doit être l'un de : web-server, database, cache, worker, gateway."
  }

  validation {
    condition     = contains(["internet-facing", "internal-only", "isolated"], var.resource_intent.exposure_level)
    error_message = "exposure_level doit être l'un de : internet-facing, internal-only, isolated."
  }

  # Sécurité : une base de données ne peut JAMAIS être exposée sur Internet.
  # Une violation de cette règle signifie que la déclaration d'intention est incohérente
  # avec les bonnes pratiques Azure (CIS Azure 4.x, NIST SC-7).
  validation {
    condition     = !(var.resource_intent.service_type == "database" && var.resource_intent.exposure_level == "internet-facing")
    error_message = "Une ressource de type 'database' ne peut pas avoir exposure_level 'internet-facing'. Utilisez 'internal-only' ou 'isolated' (CIS Azure 4.x / NIST SC-7)."
  }

  # Four-eyes principle : le responsable et l'approbateur doivent être deux personnes distinctes.
  # Empêche l'auto-approbation d'un contrat d'intention.
  validation {
    condition     = var.resource_intent.owner != var.resource_intent.approved_by
    error_message = "owner et approved_by doivent être des personnes DIFFÉRENTES (violation du principe four-eyes). L'auto-approbation est interdite."
  }
}

# Exemple d'utilisation conforme
# resource_intent = {
#   service_type   = "web-server"
#   exposure_level = "internet-facing"
#   owner          = "dev@company.com"
#   approved_by    = "lead@company.com"
# }
