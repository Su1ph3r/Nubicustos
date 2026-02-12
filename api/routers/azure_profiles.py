"""Azure Profiles API - Manage Azure credential profiles."""

import json
import logging
import os
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/azure-profiles", tags=["Azure Profiles"])

# Path to Azure profiles JSON file
AZURE_PROFILES_PATH = "/app/credentials/azure/profiles.json"


class AzureProfile(BaseModel):
    """Azure profile information."""

    name: str
    tenant_id: str | None = None
    client_id: str | None = None
    subscription_id: str | None = None
    identity: str | None = None
    subscription_names: list[str] = []
    created_at: datetime | None = None
    auth_method: str = "service_principal"
    username: str | None = None


class AzureProfileCredentials(BaseModel):
    """Azure profile credentials (for internal use)."""

    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    subscription_id: str | None = None
    auth_method: str = "service_principal"
    username: str | None = None
    password: str | None = None


class SaveAzureProfileRequest(BaseModel):
    """Request to save a new Azure profile."""

    profile_name: str
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    subscription_id: str | None = None
    auth_method: str = "service_principal"
    username: str | None = None
    password: str | None = None


class AzureProfileListResponse(BaseModel):
    """Response for listing Azure profiles."""

    profiles: list[AzureProfile]
    profiles_file_exists: bool
    profiles_path: str


def _read_profiles_file() -> dict:
    """Read Azure profiles from JSON file."""
    if os.path.exists(AZURE_PROFILES_PATH):
        try:
            with open(AZURE_PROFILES_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not read Azure profiles file: {e}")
    return {"profiles": {}}


def _write_profiles_file(data: dict) -> None:
    """Write Azure profiles to JSON file."""
    try:
        os.makedirs(os.path.dirname(AZURE_PROFILES_PATH), exist_ok=True)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied creating directory {os.path.dirname(AZURE_PROFILES_PATH)}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/azure"
            )
        )

    try:
        with open(AZURE_PROFILES_PATH, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied writing to {AZURE_PROFILES_PATH}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/azure"
            )
        )


def _verify_azure_credentials(
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    auth_method: str = "service_principal",
    username: str = "",
    password: str = "",
):
    """Verify Azure credentials and return subscription info."""
    try:
        from azure.identity import AzureCliCredential, ClientSecretCredential, UsernamePasswordCredential
        from azure.mgmt.resource import SubscriptionClient

        if auth_method == "cli":
            credential = AzureCliCredential()
        elif auth_method == "username_password":
            cli_client_id = "04b07795-a710-4532-9ddb-53ea1d339180"
            try:
                credential = UsernamePasswordCredential(
                    client_id=cli_client_id,
                    username=username,
                    password=password,
                    tenant_id=tenant_id or "organizations",
                )
            except Exception as e:
                error_str = str(e)
                if "AADSTS50076" in error_str or "AADSTS50079" in error_str:
                    return {"valid": False, "error": "MFA is required for this account. Use Device Code authentication instead."}
                elif "AADSTS7000218" in error_str:
                    return {"valid": False, "error": "ROPC authentication is disabled for this tenant."}
                raise
        elif auth_method == "device_code":
            # Device code profiles can't be re-verified via stored creds
            # Return valid=True if we have subscription info from the original flow
            return {"valid": True, "identity": "Device Code Auth", "subscription_names": [], "subscription_ids": []}
        else:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        if subscriptions:
            return {
                "valid": True,
                "identity": subscriptions[0].display_name,
                "tenant_id": subscriptions[0].tenant_id,
                "subscription_names": [sub.display_name for sub in subscriptions],
                "subscription_ids": [sub.subscription_id for sub in subscriptions],
            }
        else:
            identity = "Azure-CLI" if auth_method == "cli" else f"Azure-{(tenant_id or 'Unknown')[:8]}"
            return {
                "valid": True,
                "identity": identity,
                "subscription_names": [],
                "subscription_ids": [],
            }
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Azure SDK not installed. Install with: pip install azure-identity azure-mgmt-resource"
        )
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
        }


@router.get("", response_model=AzureProfileListResponse)
@router.get("/", response_model=AzureProfileListResponse)
async def list_profiles():
    """
    List available Azure profiles from the profiles file.

    The profiles file is stored at /app/credentials/azure/profiles.json
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    profiles = []
    for name, profile_data in profiles_dict.items():
        profile = AzureProfile(
            name=name,
            tenant_id=profile_data.get("tenant_id", ""),
            client_id=profile_data.get("client_id", ""),
            subscription_id=profile_data.get("subscription_id"),
            identity=profile_data.get("identity"),
            subscription_names=profile_data.get("subscription_names", []),
            created_at=profile_data.get("created_at"),
            auth_method=profile_data.get("auth_method", "service_principal"),
            username=profile_data.get("username"),
        )
        profiles.append(profile)

    return AzureProfileListResponse(
        profiles=profiles,
        profiles_file_exists=os.path.exists(AZURE_PROFILES_PATH),
        profiles_path=AZURE_PROFILES_PATH,
    )


@router.get("/{profile_name}")
async def get_profile_info(profile_name: str):
    """
    Get information about a specific Azure profile (without exposing secrets).
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]
    return AzureProfile(
        name=profile_name,
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        subscription_id=profile_data.get("subscription_id"),
        identity=profile_data.get("identity"),
        subscription_names=profile_data.get("subscription_names", []),
        created_at=profile_data.get("created_at"),
        auth_method=profile_data.get("auth_method", "service_principal"),
        username=profile_data.get("username"),
    )


@router.get("/{profile_name}/credentials", include_in_schema=False)
async def get_profile_credentials(profile_name: str) -> AzureProfileCredentials:
    """
    Get credentials for an Azure profile. Internal use only - not exposed in API docs.
    Used by tool execution to get credentials.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]

    return AzureProfileCredentials(
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        client_secret=profile_data.get("client_secret", ""),
        subscription_id=profile_data.get("subscription_id"),
        auth_method=profile_data.get("auth_method", "service_principal"),
        username=profile_data.get("username"),
        password=profile_data.get("password"),
    )


@router.post("/{profile_name}/verify")
async def verify_profile(profile_name: str):
    """
    Verify that an Azure profile's credentials are valid.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]

    stored_auth_method = profile_data.get("auth_method", "service_principal")

    result = _verify_azure_credentials(
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        client_secret=profile_data.get("client_secret", ""),
        auth_method=stored_auth_method,
        username=profile_data.get("username", ""),
        password=profile_data.get("password", ""),
    )

    return {
        "profile": profile_name,
        "valid": result.get("valid", False),
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "error": result.get("error"),
        "auth_method": stored_auth_method,
    }


@router.post("")
@router.post("/")
async def save_profile(request: SaveAzureProfileRequest):
    """
    Save credentials as a new Azure profile.

    This validates the credentials first, then stores them securely.
    """
    profile_name = request.profile_name.strip()
    if not profile_name:
        raise HTTPException(status_code=400, detail="Profile name is required")

    auth_method = request.auth_method or "service_principal"

    # Validate auth_method
    if auth_method not in ("service_principal", "cli", "username_password", "device_code"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid auth_method '{auth_method}'. Must be 'service_principal', 'cli', 'username_password', or 'device_code'",
        )

    # Validate SP fields are present for service_principal auth
    if auth_method == "service_principal":
        if not (request.tenant_id and request.client_id and request.client_secret):
            raise HTTPException(
                status_code=400,
                detail="Service principal auth requires tenant_id, client_id, and client_secret",
            )
    elif auth_method == "username_password":
        if not (request.username and request.password):
            raise HTTPException(
                status_code=400,
                detail="Username/password auth requires username and password",
            )

    # Verify credentials first
    result = _verify_azure_credentials(
        tenant_id=request.tenant_id or "",
        client_id=request.client_id or "",
        client_secret=request.client_secret or "",
        auth_method=auth_method,
        username=request.username or "",
        password=request.password or "",
    )

    if not result.get("valid"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Azure credentials: {result.get('error', 'Unknown error')}"
        )

    # Read existing profiles
    data = _read_profiles_file()
    if "profiles" not in data:
        data["profiles"] = {}

    # Add or update the profile
    profile_entry = {
        "auth_method": auth_method,
        "subscription_id": request.subscription_id,
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "created_at": datetime.utcnow().isoformat(),
    }

    if auth_method == "service_principal":
        profile_entry["tenant_id"] = request.tenant_id
        profile_entry["client_id"] = request.client_id
        profile_entry["client_secret"] = request.client_secret
    elif auth_method == "username_password":
        profile_entry["tenant_id"] = request.tenant_id or result.get("tenant_id", "")
        profile_entry["username"] = request.username
        profile_entry["password"] = request.password
    elif auth_method == "device_code":
        profile_entry["tenant_id"] = request.tenant_id or ""
    else:
        # For CLI auth, store tenant_id from verification if available
        profile_entry["tenant_id"] = result.get("tenant_id", request.tenant_id or "")
        profile_entry["client_id"] = request.client_id or ""
        profile_entry["client_secret"] = ""

    data["profiles"][profile_name] = profile_entry

    # Write profiles file
    _write_profiles_file(data)

    return {
        "success": True,
        "profile": profile_name,
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "message": f"Profile '{profile_name}' saved successfully",
    }


@router.delete("/{profile_name}")
async def delete_profile(profile_name: str):
    """
    Delete an Azure profile.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    del profiles_dict[profile_name]
    data["profiles"] = profiles_dict
    _write_profiles_file(data)

    return {
        "success": True,
        "message": f"Profile '{profile_name}' deleted",
    }
