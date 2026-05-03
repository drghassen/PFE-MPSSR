# =============================================================================
# BOOTSTRAP BACKEND — local state
# =============================================================================
#
# This configuration manages the Terraform remote state storage account
# (sttfstateghassen01). It CANNOT use that account as its own backend —
# that is the classic chicken-and-egg problem.
#
# SOLUTION: local backend. The .tfstate file produced here is small (< 5 KB),
# contains no secrets, and should be:
#   1. Committed to a secure branch (it holds only storage account metadata), OR
#   2. Stored in a separate secured location outside this repository.
#
# DO NOT store this state file in sttfstateghassen01 itself.
#
# .gitignore entry recommendation:
#   infra/azure/bootstrap/tfstate-storage/.terraform/
#   # Keep terraform.tfstate committed (no secrets, just resource IDs)
#
# =============================================================================

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
