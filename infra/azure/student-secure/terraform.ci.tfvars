# CI-only variables file — committed to git, used by terraform-plan (tofu plan -backend=false).
# Purpose: static analysis and intent contract extraction only. No real deployment.
# Real deployment uses terraform.tfvars (gitignored, contains real SSH key and subscription).

subscription_id      = "00000000-0000-0000-0000-000000000000"
admin_ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholderciplanplaceholder ci-plan-placeholder"

resource_intent = {
  service_type   = "web-server"
  exposure_level = "internet-facing"
  owner          = "devops-team"
  approved_by    = "security-team"
}

