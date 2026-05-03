# =============================================================================
# CloudSentinel — Network Watcher + VNet Flow Logs
# Finding  : network_watcher_enabled  (Prowler HIGH)
# CIS Azure : 6.4  Network Watcher enabled in each region
#             6.5  Flow log retention >= 90 days
#             6.6  Traffic Analytics enabled on flow logs
# =============================================================================
#
# DESIGN NOTES
#   • Never recreates the Network Watcher — it is referenced via data source.
#   • A dedicated storage account is created for flow-log blobs; it is the
#     ONLY new persistent resource besides the flow log objects themselves.
#   • One azurerm_network_watcher_flow_log is created per VNet via for_each.
#     Keys in var.vnets become part of the resource name; use stable, slug-safe
#     keys (e.g. "vnet", "spoke-vnet").
#   • NSG flow logs were retired by Azure on 2025-06-30; VNet flow logs are
#     the replacement and capture all traffic at the VNet scope.
#   • Flow log version 2 is required by Traffic Analytics.
#
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.40"
    }
  }
  required_version = ">= 1.6.0"
}

locals {
  # Storage account name constraints: 3-24 chars, lowercase alphanumeric only.
  # Pattern: "stnwfl" + name_prefix + environment  →  e.g. "stnwflcsdemodev" (15 chars)
  flowlogs_sa_name = substr(
    lower(replace("stnwfl${var.name_prefix}${var.environment}", "-", "")),
    0, 24
  )
}

# ---------------------------------------------------------------------------
# DATA — existing Network Watcher (read-only reference, never recreated)
#
# Azure auto-provisions NetworkWatcher_<region> inside NetworkWatcherRG when
# the subscription has Network Watcher enabled. If your watcher lives in a
# different RG, override var.network_watcher_rg.
# ---------------------------------------------------------------------------
data "azurerm_network_watcher" "this" {
  name                = var.network_watcher_name
  resource_group_name = var.network_watcher_rg
}

# ---------------------------------------------------------------------------
# DATA — existing Log Analytics Workspace (read-only reference)
# ---------------------------------------------------------------------------
data "azurerm_log_analytics_workspace" "law" {
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_workspace_rg
}

# ---------------------------------------------------------------------------
# STORAGE ACCOUNT — dedicated to VNet flow log blobs
#
# Network Watcher writes raw flow blobs here before Traffic Analytics reads
# them. The account must allow the AzureServices bypass so the platform can
# write without a public endpoint.
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "flowlogs" {
  # checkov:skip=CKV2_AZURE_33: Private endpoint for flow-log storage is not in scope for this module
  # checkov:skip=CKV2_AZURE_1: CMK for flow-log storage is not in scope for this module
  name                = local.flowlogs_sa_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = merge(var.tags, { purpose = "vnet-flow-logs" })

  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  # Security hardening (azurerm ~> 4.x attribute names)
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  shared_access_key_enabled       = false

  # Network Watcher (trusted Azure service) must be able to write flow blobs
  # even though public access is blocked.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }

  blob_properties {
    versioning_enabled = true

    # Soft-delete mirrors the flow log retention to keep blobs recoverable.
    delete_retention_policy {
      days = var.flow_log_retention_days
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = var.flow_log_retention_days
    }
  }

  sas_policy {
    expiration_period = "07.00:00:00"
    expiration_action = "Log"
  }
}

# ---------------------------------------------------------------------------
# VNET FLOW LOGS — one resource per VNet, keyed by var.vnets map
#
# VNet flow logs replace NSG flow logs (retired by Azure 2025-06-30).
# They capture all traffic flowing through the VNet (covering every subnet
# and NSG boundary) with the same Traffic Analytics enrichment.
#
# Version 2 enables the enriched schema required by Traffic Analytics.
# The resource_group_name must be the Network Watcher's RG (Azure constraint),
# NOT the application resource group.
# ---------------------------------------------------------------------------
resource "azurerm_network_watcher_flow_log" "vnet" {
  for_each = var.vnets

  # Name must be unique within the Network Watcher scope.
  name = "${replace(each.key, "_", "-")}-vnet-flowlog"

  # Must point to the Network Watcher's own resource group.
  resource_group_name  = data.azurerm_network_watcher.this.resource_group_name
  network_watcher_name = data.azurerm_network_watcher.this.name

  target_resource_id = each.value
  storage_account_id = azurerm_storage_account.flowlogs.id
  enabled            = true

  # Version 2 is required for Traffic Analytics enrichment.
  version = 2

  retention_policy {
    enabled = true
    days    = var.flow_log_retention_days
  }

  traffic_analytics {
    enabled = true

    # workspace_id  = GUID of the LAW (not the ARM resource ID)
    workspace_id          = data.azurerm_log_analytics_workspace.law.workspace_id
    workspace_region      = data.azurerm_log_analytics_workspace.law.location
    workspace_resource_id = data.azurerm_log_analytics_workspace.law.id

    interval_in_minutes = var.traffic_analytics_interval_minutes
  }

  tags = var.tags
}
