from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential, ManagedIdentityCredential
except Exception as exc:  # pragma: no cover
    ClientSecretCredential = None  # type: ignore[assignment]
    DefaultAzureCredential = None  # type: ignore[assignment]
    ManagedIdentityCredential = None  # type: ignore[assignment]
    _AZURE_IDENTITY_IMPORT_ERROR: Exception | None = exc
else:
    _AZURE_IDENTITY_IMPORT_ERROR = None

try:
    from azure.mgmt.resource import ResourceManagementClient
except Exception as exc:  # pragma: no cover
    ResourceManagementClient = None  # type: ignore[assignment]
    _AZURE_MGMT_RESOURCE_IMPORT_ERROR: Exception | None = exc
else:
    _AZURE_MGMT_RESOURCE_IMPORT_ERROR = None


@dataclass(frozen=True)
class AzureEnv:
    tenant_id: Optional[str]
    client_id: Optional[str]
    client_secret: Optional[str]
    subscription_id: Optional[str]


def _get_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def load_azure_env() -> AzureEnv:
    """
    Read Azure auth env vars.

    - Terraform azurerm provider: typically ARM_*.
    - Azure SDK: typically AZURE_*.
    """

    tenant_id = _get_env("AZURE_TENANT_ID") or _get_env("ARM_TENANT_ID")
    client_id = _get_env("AZURE_CLIENT_ID") or _get_env("ARM_CLIENT_ID")
    client_secret = _get_env("AZURE_CLIENT_SECRET") or _get_env("ARM_CLIENT_SECRET")
    subscription_id = _get_env("AZURE_SUBSCRIPTION_ID") or _get_env("ARM_SUBSCRIPTION_ID")
    return AzureEnv(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id,
    )


def get_credential() -> object:
    """
    Prefer Service Principal when present; otherwise fall back to Managed Identity.
    """

    if _AZURE_IDENTITY_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Missing dependency 'azure-identity'. Install it (and 'azure-mgmt-resource' if using enrichment) "
            "or run inside the drift-engine Docker image."
        ) from _AZURE_IDENTITY_IMPORT_ERROR

    env = load_azure_env()
    if env.tenant_id and env.client_id and env.client_secret:
        assert ClientSecretCredential is not None
        return ClientSecretCredential(
            tenant_id=env.tenant_id,
            client_id=env.client_id,
            client_secret=env.client_secret,
        )

    # Managed Identity fallback (user-assigned if AZURE_CLIENT_ID/ARM_CLIENT_ID is set).
    if env.client_id:
        assert ManagedIdentityCredential is not None
        return ManagedIdentityCredential(client_id=env.client_id)
    try:
        assert ManagedIdentityCredential is not None
        return ManagedIdentityCredential()
    except Exception:
        assert DefaultAzureCredential is not None
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)


class AzureResourceClient:
    def __init__(self, subscription_id: str) -> None:
        if _AZURE_MGMT_RESOURCE_IMPORT_ERROR is not None:
            raise RuntimeError(
                "Missing dependency 'azure-mgmt-resource'. Install it or disable azure.validate_access "
                "in drift_config.yaml."
            ) from _AZURE_MGMT_RESOURCE_IMPORT_ERROR

        self.subscription_id = subscription_id
        self.credential = get_credential()
        assert ResourceManagementClient is not None
        self.client: Any = ResourceManagementClient(self.credential, subscription_id)

    def count_resource_groups(self) -> int:
        return sum(1 for _ in self.client.resource_groups.list())
