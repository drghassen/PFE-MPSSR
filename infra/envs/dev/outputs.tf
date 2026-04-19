output "resource_group_name" {
  description = "Resource group name."
  value       = azurerm_resource_group.this.name
}

output "vnet_id" {
  description = "Virtual network ID."
  value       = module.vpc.vnet_id
}

output "public_subnet_id" {
  description = "Public subnet ID."
  value       = module.vpc.public_subnet_id
}

output "private_subnet_id" {
  description = "Private subnet ID."
  value       = module.vpc.private_subnet_id
}

output "nsg_id" {
  description = "NSG ID attached to VM NIC."
  value       = module.security.nsg_id
}

output "vm_name" {
  description = "VM name."
  value       = module.compute.vm_name
}

output "vm_private_ip" {
  description = "VM private IP address."
  value       = module.compute.private_ip
}

output "vm_public_ip" {
  description = "VM public IP address when enabled."
  value       = module.compute.public_ip
}

output "vm_identity_principal_id" {
  description = "Managed identity principal ID attached to VM."
  value       = module.iam.vm_identity_principal_id
}

output "ci_identity_principal_id" {
  description = "CI/CD managed identity principal ID when enabled."
  value       = module.iam.ci_identity_principal_id
}

output "db_fqdn" {
  description = "PostgreSQL server FQDN — use in connection string."
  value       = module.database.db_fqdn
}

output "db_name" {
  description = "Database name."
  value       = module.database.db_name
}

output "db_admin_login" {
  description = "PostgreSQL admin login."
  value       = module.database.db_admin_login
}

output "db_port" {
  description = "PostgreSQL port."
  value       = module.database.db_port
}
