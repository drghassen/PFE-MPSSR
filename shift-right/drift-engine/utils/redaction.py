from __future__ import annotations

import os
import re


def safe_env_snapshot() -> dict[str, str]:
    """Returns a safe subset of env vars — never includes secrets."""
    allow = {
        "ARM_SUBSCRIPTION_ID",
        "ARM_TENANT_ID",
        "ARM_CLIENT_ID",
        "ARM_USE_MSI",
        "TF_WORKING_DIR",
        "TF_WORKSPACE",
        "DRIFT_OUTPUT_PATH",
        "DRIFT_PUSH_TO_DEFECTDOJO",
    }
    return {key: os.environ[key] for key in sorted(allow) if key in os.environ}


def redact_sensitive(text: str) -> str:
    """Best-effort redaction of secrets in Terraform/OpenTofu stdout/stderr."""
    if not text:
        return ""

    redacted = text

    # Replace literal secret values if they appear verbatim in output.
    for key in (
        "ARM_CLIENT_SECRET",
        "DEFECTDOJO_API_KEY",
        "AZURE_CLIENT_SECRET",
        "ARM_ACCESS_KEY",
        "OPA_AUTH_TOKEN",
    ):
        value = os.getenv(key)
        if value:
            redacted = redacted.replace(value, "***REDACTED***")

    # Redact HCL-style assignment patterns.
    redacted = re.sub(
        r'(?im)^(\s*[\w\-.]*?(?:password|secret|token|api[_-]?key|access[_-]?key)[\w\-.]*\s*=\s*)"[^"]*"',
        r'\1"***REDACTED***"',
        redacted,
    )

    # Redact known token formats.
    redacted = re.sub(r"\bghp_[A-Za-z0-9_]{20,}\b", "***REDACTED***", redacted)
    redacted = re.sub(r"\bglpat-[A-Za-z0-9\-_]{20,}\b", "***REDACTED***", redacted)

    return redacted
