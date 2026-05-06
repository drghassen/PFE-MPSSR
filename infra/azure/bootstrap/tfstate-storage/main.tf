# =============================================================================
# CloudSentinel — Terraform State Backend Hardening
# Resource     : sttfstateghassen01  (rg-terraform-state)
# Purpose      : Manage the Terraform remote state storage account safely
#
# SECURITY FINDINGS ADDRESSED IN THIS FILE
# ─────────────────────────────────────────
# ✅ PHASE 1 (SAFE — applied here):
#    • TLS 1.2 enforcement               (CIS 3.15)
#    • HTTPS-only traffic                (CIS 3.1)
#    • Public blob access disabled
#    • Blob versioning enabled           (state recovery)
#    • Blob soft-delete 30 days          (state recovery)
#    • Formalized network_rules          (no behavioral change yet)
#    • Diagnostic logging
#
# ⚠  PHASE 2 (MEDIUM RISK — see section below, NOT applied automatically):
#    • Network firewall: default_action = "Deny" + allowed_ip_ranges
#    • Requires all GitLab runner IPs allowlisted BEFORE switching
#
# 🚫 PHASE 3 (ARCHITECTURAL CHANGE REQUIRED — DO NOT APPLY WITHOUT MIGRATION):
#    • Customer Managed Keys (CMK):
#      - Requires dedicated Key Vault in same region
#      - KV unavailability = Terraform state lock-out (CRITICAL blast radius)
#      - Requires state migration plan and tested rollback
#    • Private Endpoint:
#      - Requires GitLab runner on the same VNet (self-hosted) OR VPN/ExpressRoute
#      - SaaS GitLab runners cannot reach private endpoints
#      - Requires private DNS zone: privatelink.blob.core.windows.net
#    • Infrastructure Encryption (double encryption):
#      - azurerm 4.x: infrastructure_encryption_enabled = ForceNew
#      - Enabling it DESTROYS this resource in terraform plan → state gone
#      - Requires: create new SA → migrate blobs → update backend config → delete old SA
#
# NOT APPLICABLE:
#    • storage_smb_channel_encryption_with_secure_algorithm:
#      Terraform state uses Blob (HTTPS). Azure Files (SMB) is not used.
#      Suppressed in config/prowler/exclusions-azure-student.txt.
#
# IMPORT COMMAND (run once before first apply):
#   terraform import azurerm_storage_account.tfstate \
#     /subscriptions/<SUB_ID>/resourceGroups/rg-terraform-state/providers/Microsoft.Storage/storageAccounts/sttfstateghassen01
#
# =============================================================================

# ---------------------------------------------------------------------------
# DATA — existing Log Analytics Workspace (optional diagnostic target)
# Remove this block if no LAW exists in the subscription yet.
# ---------------------------------------------------------------------------
data "azurerm_log_analytics_workspace" "law" {
  count               = var.log_analytics_workspace_name != "" ? 1 : 0
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_workspace_rg
}

# ---------------------------------------------------------------------------
# PHASE 1 — Storage account in-place hardening
#
# IMPORT BEFORE APPLY (idempotency guard):
#   terraform import azurerm_storage_account.tfstate \
#     /subscriptions/<SUB_ID>/resourceGroups/rg-terraform-state/ \
#     providers/Microsoft.Storage/storageAccounts/sttfstateghassen01
#
# After import, `terraform plan` shows ONLY safe in-place diffs:
#   ~ min_tls_version                 = "TLS1_0" → "TLS1_2"
#   ~ https_traffic_only_enabled      = false    → true
#   ~ allow_nested_items_to_be_public = true     → false
#   ~ blob_properties.versioning_enabled         → true
#   ~ blob_properties.delete_retention_policy    → 30 days
#   (no ForceNew, no recreation, no connectivity loss)
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "tfstate" {
  # checkov:skip=CKV_AZURE_35: Phase 2 — default_action=Deny requires GitLab runner IPs allowlisted before switching
  # checkov:skip=CKV_AZURE_59: Phase 2 — public_network_access_enabled=false requires self-hosted runners on Azure VNet
  # checkov:skip=CKV2_AZURE_33: Phase 3 — private endpoint requires runner VNet migration (scaffold below)
  # checkov:skip=CKV2_AZURE_1: Phase 3 — CMK requires dedicated Key Vault setup (scaffold below)
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  # These must match the existing account's current values EXACTLY to avoid
  # recreation (ForceNew attributes). Verify with:
  #   az storage account show --name sttfstateghassen01 --rg rg-terraform-state \
  #     --query "{kind:kind, tier:sku.tier, replication:sku.name}"
  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  # ── Phase 1: safe in-place security hardening ────────────────────────────

  # CIS 3.15 — reject TLS < 1.2 at the Azure platform level
  min_tls_version = "TLS1_2"

  # CIS 3.1 — all traffic must use HTTPS (state backend always does, but enforce it)
  https_traffic_only_enabled = true

  # Prevent any blob from accidentally being made public
  allow_nested_items_to_be_public = false

  # Shared key access disabled — CI uses ARM_STORAGE_USE_AZUREAD=true for AAD-only auth.
  # CKV2_AZURE_40 / CIS 3.10: enforce Azure AD auth exclusively.
  shared_access_key_enabled = false

  # ── Infrastructure encryption (PHASE 3 — DO NOT ENABLE HERE) ────────────
  # infrastructure_encryption_enabled = true
  #
  # WHY NOT NOW:
  #   azurerm ~> 4.x treats this as ForceNew. If uncommented, Terraform will
  #   DESTROY sttfstateghassen01 and create a new empty account. All .tfstate
  #   blobs are gone. Recovery requires manual blob copy + backend reconfiguration.
  #
  #   PHASE 3 migration path:
  #     1. az storage account create --name sttfstateghassen01v2 --infrastructure-encryption true
  #     2. azcopy sync "https://sttfstateghassen01.blob.core.windows.net/tfstate" \
  #                    "https://sttfstateghassen01v2.blob.core.windows.net/tfstate"
  #     3. Update TFSTATE_STORAGE_ACCOUNT in GitLab CI/CD Variables
  #     4. tofu init -migrate-state
  #     5. Verify all pipelines pass, then delete old account
  # ────────────────────────────────────────────────────────────────────────

  blob_properties {
    # Blob versioning: keeps previous .tfstate versions on every write.
    # Enables point-in-time recovery if a bad plan corrupts state.
    versioning_enabled = true

    # 30-day soft-delete: blobs survive accidental deletion long enough
    # for investigation and recovery. Standard state files are small (< 1 MB),
    # so storage cost impact is negligible.
    delete_retention_policy {
      days = var.blob_soft_delete_retention_days
    }

    # Container soft-delete: protects the tfstate container itself
    container_delete_retention_policy {
      days = var.container_soft_delete_retention_days
    }
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 7
    }
  }

  sas_policy {
    expiration_period = "P7D"
    expiration_action = "Log"
  }

  # ── Network rules: Phase 1 (no behavioral change) ────────────────────────
  #
  # default_action = "Allow" preserves current connectivity for all clients
  # including GitLab SaaS runners (dynamic IPs, not allowlistable).
  #
  # AzureServices bypass: required for Azure Monitor, diagnostics, and any
  # trusted Microsoft service that needs to interact with this account.
  #
  # ⚠  PHASE 2 CHANGE (require explicit approval before applying):
  #   To restrict access to specific CI runner IPs, change to:
  #     default_action = "Deny"
  #     ip_rules       = var.allowed_ip_ranges
  #   And ensure ALL runner egress IPs are in allowed_ip_ranges BEFORE applying.
  #   GitLab SaaS runner IPs: https://docs.gitlab.com/ee/user/gitlab_com/
  #   For self-hosted runners: use the runner VM's private IP or subnet.
  #
  # ⚠  PHASE 3 CHANGE (private endpoint):
  #   When private endpoint is in place, switch to:
  #     default_action = "Deny"
  #     virtual_network_subnet_ids = [<runner-subnet-id>]
  #   And remove public IP rules entirely.
  # ────────────────────────────────────────────────────────────────────────
  network_rules {
    default_action = "Allow"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }

  lifecycle {
    # Guard against accidental destruction of the Terraform state backend.
    # This is the single most critical resource in the entire infrastructure.
    prevent_destroy = true

    # Ignore replication_type changes initiated outside Terraform (e.g. Azure portal).
    # Replication changes trigger data movement and possible brief unavailability.
    ignore_changes = [account_replication_type]
  }
}

# ---------------------------------------------------------------------------
# PHASE 1 — Diagnostic logging for state account
#
# Captures StorageRead/Write/Delete operations on the blob service.
# This directly addresses the audit trail requirement without touching
# any functional configuration.
#
# Conditional: only created if a Log Analytics Workspace is provided.
# ---------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "tfstate_blob" {
  count = var.log_analytics_workspace_name != "" ? 1 : 0

  name               = "${var.storage_account_name}-blob-diag"
  target_resource_id = "${azurerm_storage_account.tfstate.id}/blobServices/default"

  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.law[0].id

  # StorageRead/Write/Delete on blob service captures all state operations.
  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Transaction"
  }
}

# ---------------------------------------------------------------------------
# PHASE 3 SCAFFOLD — Customer Managed Keys
# (ALL resources commented out — DO NOT uncomment without a complete migration plan)
#
# RISK: If the Key Vault becomes unavailable (purged, access revoked, region outage),
# Terraform CANNOT read or write state. Every pipeline fails. Recovery requires
# restoring Key Vault access before any infrastructure change is possible.
#
# PREREQUISITE CHECKLIST before enabling CMK:
#   □ Dedicated Key Vault in norwayeast (same region as storage account)
#   □ Key Vault soft-delete and purge protection enabled (already true in this project)
#   □ Managed Identity assigned to storage account with Key Vault Crypto User role
#   □ Tested Key Vault unavailability scenario and recovery procedure
#   □ Terraform state migration executed and validated
#   □ Azure for Students quota check: CMK requires Key Vault Standard SKU minimum
#
# resource "azurerm_user_assigned_identity" "tfstate_cmk" {
#   name                = "${var.storage_account_name}-cmk-identity"
#   resource_group_name = var.resource_group_name
#   location            = var.location
# }
#
# resource "azurerm_key_vault_key" "tfstate_cmk" {
#   name         = "tfstate-cmk-key"
#   key_vault_id = "<KEY_VAULT_ID>"
#   key_type     = "RSA"
#   key_size     = 4096
#   key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
#   rotation_policy {
#     expire_after         = "P90D"
#     notify_before_expiry = "P7D"
#   }
# }
#
# resource "azurerm_storage_account_customer_managed_key" "tfstate" {
#   storage_account_id = azurerm_storage_account.tfstate.id
#   key_vault_id       = "<KEY_VAULT_ID>"
#   key_name           = azurerm_key_vault_key.tfstate_cmk.name
# }
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PHASE 3 SCAFFOLD — Private Endpoint
# (commented out — requires network redesign and GitLab runner migration)
#
# PREREQUISITE CHECKLIST before enabling private endpoint:
#   □ GitLab runner moved to self-hosted VM on Azure VNet (SaaS runners won't work)
#   □ Private DNS zone: privatelink.blob.core.windows.net linked to runner VNet
#   □ Private endpoint subnet provisioned with /28 or larger
#   □ End-to-end connectivity tested: runner → PE → storage account
#   □ network_rules.default_action switched to "Deny" AFTER PE is validated
#
# resource "azurerm_private_endpoint" "tfstate" {
#   name                = "${var.storage_account_name}-pe"
#   location            = var.location
#   resource_group_name = var.resource_group_name
#   subnet_id           = "<RUNNER_SUBNET_ID>"
#
#   private_service_connection {
#     name                           = "${var.storage_account_name}-psc"
#     private_connection_resource_id = azurerm_storage_account.tfstate.id
#     is_manual_connection           = false
#     subresource_names              = ["blob"]
#   }
#
#   private_dns_zone_group {
#     name                 = "default"
#     private_dns_zone_ids = ["<BLOB_PRIVATE_DNS_ZONE_ID>"]
#   }
# }
# ---------------------------------------------------------------------------
