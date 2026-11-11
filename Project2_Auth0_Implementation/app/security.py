
import time
from typing import Any, Dict, Optional

import httpx
import jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings


# Extract Bearer tokens from incoming HTTP requests.
bearer_scheme = HTTPBearer(auto_error=False)

# Cache Auth0's public signing keys to avoid downloading them on every request.
_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_cache_expiry = 0.0
JWKS_CACHE_SECONDS = 300


async def get_auth0_jwks(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Retrieve Auth0's JSON Web Key Set (JWKS).
    These public keys are used to verify RS256 token signatures.
    """
    global _jwks_cache, _jwks_cache_expiry

    if (
        not force_refresh
        and _jwks_cache is not None
        and time.monotonic() < _jwks_cache_expiry
    ):
        return _jwks_cache

    jwks_url = f"{settings.issuer}.well-known/jwks.json"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
            jwks_data = response.json()

        if not isinstance(jwks_data.get("keys"), list):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Auth0 signing keys are temporarily unavailable.",
            )

        _jwks_cache = jwks_data
        _jwks_cache_expiry = time.monotonic() + JWKS_CACHE_SECONDS

        return jwks_data

    except httpx.HTTPError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve Auth0 signing keys.",
        )


async def verify_access_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        bearer_scheme
    ),
) -> Dict[str, Any]:
    """
    Verify an Auth0 access token.

    Checks:
    1. Bearer token is present.
    2. JWT uses RS256.
    3. Signing key matches Auth0's JWKS.
    4. Issuer is our Auth0 tenant.
    5. Audience is our SecureNova API.
    6. Token has not expired.
    """

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        # Read the JWT header only to select the corresponding public key.
        # The token is NOT trusted until its signature is verified below.
        unverified_header = jwt.get_unverified_header(token)

        if unverified_header.get("alg") != "RS256":
            raise jwt.InvalidTokenError("Unexpected signing algorithm.")

        kid = unverified_header.get("kid")

        if not kid:
            raise jwt.InvalidTokenError("JWT key identifier is missing.")

        # Find the public key corresponding to the token's key identifier.
        jwks = await get_auth0_jwks()

        matching_keys = [
            key for key in jwks["keys"]
            if key.get("kid") == kid
        ]

        # Refresh the cache once in case Auth0 has rotated its signing key.
        if not matching_keys:
            jwks = await get_auth0_jwks(force_refresh=True)

            matching_keys = [
                key for key in jwks["keys"]
                if key.get("kid") == kid
            ]

        if not matching_keys:
            raise jwt.InvalidTokenError("No matching signing key found.")

        signing_key = jwt.PyJWK.from_dict(
            matching_keys[0],
            algorithm="RS256",
        )

        # Verify signature and standard claims.
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.auth0_api_audience,
            issuer=settings.issuer,
            options={
                "require": ["exp", "iss", "aud", "sub"],
            },
        )

        return claims

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or incorrectly issued access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permission(required_permission: str):
    """
    Create a reusable authorization dependency.

    A valid token alone is not enough.
    The token must also contain the permission required by the endpoint.
    """

    async def permission_checker(
        claims: Dict[str, Any] = Depends(verify_access_token),
    ) -> Dict[str, Any]:

        # Auth0 RBAC may provide permissions as an array.
        permissions = claims.get("permissions", [])
        if not isinstance(permissions, list):
            permissions = []

        # Auth0 can also represent granted scopes as a space-separated string.
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str):
            scopes = ""

        granted_permissions = {
            permission
            for permission in permissions
            if isinstance(permission, str)
        }

        granted_permissions.update(scopes.split())

        if required_permission not in granted_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. "
                    f"Required: {required_permission}"
                ),
            )

        return claims

    return permission_checker
