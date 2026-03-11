location     = "norwayeast"
environment  = "dev"
project_name = "cloud-sentinel"
owner        = "ghassendridi007@gmail.com"

common_tags = {
  Project     = "CloudSentinel"
  ManagedBy   = "Terraform"
  Environment = "dev"
  Security    = "High"
  CostCenter  = "PFE-SSR-2026"
  Compliance  = "AS-CODE"
}

admin_username = "cloudadmin"
# Intentionally weak and hardcoded to emulate credential hygiene issues in test scans.
admin_password = "Password123!"
vm_size        = "Standard_B1s"
