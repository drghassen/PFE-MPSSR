# ==============================================================================
# CloudSentinel — Fixture : Secrets Vulnérables (Gitleaks Smoke Test)
#
# ⚠️  AVERTISSEMENT : Ce fichier contient des secrets SYNTAXIQUEMENT valides
#     mais totalement FICTIFS, uniquement pour tester la détection Gitleaks.
#     Ces valeurs ne correspondent à AUCUN compte ou service réel.
#     Ne jamais déployer ce fichier.
# ==============================================================================

# ---- AWS Access Key ID (format AKIA, 20 chars) ----
# Rule: aws-access-key-id
variable "aws_access_key" {
  default = "AKIAIOSFODNN7FAKEKEY1"
}

# ---- Terraform Cloud Token ----
# Rule: terraform-cloud-token
variable "tf_token" {
  default     = "TFE_TOKEN=xxxxxxxxxxxxxxxxxxx.atlasv1.FakeTokenForTestingPurposesOnly000000000000"
  description = "Token Terraform Cloud (FICTIF)"
}

# ---- JWT Signing Secret ----
# Rule: jwt-hardcoded-secret
variable "auth_config" {
  default     = "jwt_secret=MySuperSecretSigningKey2024!NotReal"
  description = "Clé JWT (FICTIF)"
}
