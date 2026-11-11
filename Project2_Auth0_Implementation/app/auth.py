import time
import logging
logger = logging.getLogger(__name__)
import asyncio
import httpx
from fastapi.security import HTTPAuthorizationCredentials
from app.security import verify_access_token
from fastapi.responses import JSONResponse
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth

from app.config import settings


# Register Auth0 as our OpenID Connect identity provider.
oauth = OAuth()

oauth.register(
    name="auth0",
    client_id=settings.auth0_client_id,
    client_secret=settings.auth0_client_secret,
    server_metadata_url=settings.openid_configuration_url,
    client_kwargs={
        "scope": settings.auth0_scopes,
        "code_challenge_method": "S256",
    },
)


router = APIRouter(tags=["Authentication"])


@router.get("/login")
async def login(request: Request):
    """
    Start the Authorization Code + PKCE login process.

    Authlib automatically manages:
    - OAuth state
    - OIDC nonce
    - PKCE code verifier
    - S256 code challenge
    """

    auth0 = oauth.create_client("auth0")

    return await auth0.authorize_redirect(
        request,
        redirect_uri=settings.auth0_callback_url,
        audience=settings.auth0_api_audience,
    )


@router.get("/callback")
async def auth_callback(request: Request):
    """
    Receive the authorization code from Auth0,
    exchange it for tokens and establish a local session.
    """

    auth0 = oauth.create_client("auth0")

    try:
        # Validates OAuth state and completes the token exchange.
        # Authlib also validates the ID token because we request OIDC scopes.
        token = await auth0.authorize_access_token(request)

    except Exception:
        logger.exception("Auth0 callback failed during token exchange")

    raise HTTPException(
        status_code=400,
        detail=(
            "Auth0 login failed. Check the callback URL, "
            "OAuth state and server configuration."
        ),
    ) from None

    raise HT

    userinfo = token.get("userinfo")

    if not userinfo or not userinfo.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="Auth0 did not return a valid user identity.",
        )

    access_token = token.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="Auth0 did not issue an API access token.",
        )
	
# TEMPORARY: Display access token for local JWT inspection.
# Remove this after completing the screenshot.

    print("ID TOKEN:", token.get("id_token"))
    print("========================================\n")
    print("ACCESS TOKEN:", token.get("access_token"))

    # Keep bearer tokens on the server, not in the signed browser cookie.
    session_id = secrets.token_urlsafe(32)

    request.app.state.token_store[session_id] = {
        "access_token": access_token,
        "id_token": token.get("id_token"),
        "expires_at": token.get("expires_at"),
    }

    # Store only an opaque session identifier and minimal profile data.
    request.session.clear()

    request.session["session_id"] = session_id
    request.session["user"] = {
        "sub": userinfo.get("sub"),
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
    }

    return RedirectResponse(
        url="/auth/me",
        status_code=303,
    )


@router.get("/auth/me")
async def current_user(request: Request):
    """
    Return the profile of the currently authenticated user.
    Does not expose the access token.
    """

    session_id = request.session.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in first.",
        )

    token_record = request.app.state.token_store.get(session_id)

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please log in again.",
        )

    return {
        "status": "authenticated",
        "provider": "Auth0",
        "user": request.session.get("user"),
        "access_token_expires_at": token_record.get("expires_at"),
        "token_storage": "server-side",
    }


@router.get("/logout")
async def logout(request: Request):
    """
    End the local SecureNova application session.
    """

    session_id = request.session.get("session_id")

    if session_id:
        request.app.state.token_store.pop(session_id, None)

    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303,
    )

async def _forward_session_request(
    request: Request,
    method: str,
    endpoint: str,
    payload: dict | None = None,
):
    """
    Development-only helper.

    Uses the server-side Auth0 access token to call the
    actual protected SecureNova API endpoint.
    """

    # Restrict this diagnostic helper to local development.
    client_host = request.client.host if request.client else None

    if client_host not in ("127.0.0.1", "::1"):
        raise HTTPException(
            status_code=403,
            detail="Local diagnostic access only.",
        )

    session_id = request.session.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in first.",
        )

    token_record = request.app.state.token_store.get(session_id)

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Access token unavailable. Please log in again.",
        )

    access_token = token_record["access_token"]

    expires_at = token_record.get("expires_at")

    if expires_at and time.time() >= expires_at:
        raise HTTPException(
            status_code=401,
            detail="Access token expired. Please log in again.",
        )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            trust_env=False,
        ) as client:

            response = await client.request(
                method=method,
                url=f"http://127.0.0.1:8000{endpoint}",
                headers=headers,
                json=payload,
            )

        try:
            result = response.json()
        except ValueError:
            result = {"response": response.text}

        return JSONResponse(
            status_code=response.status_code,
            content={
                "tested_endpoint": endpoint,
                "api_http_status": response.status_code,
                "api_response": result,
            },
        )

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to reach the local SecureNova API.",
        ) from exc


@router.get("/auth/probe/ai-data")
async def probe_ai_data(request: Request):
    """Forward the current user's token to the actual GET /ai-data."""
    return await _forward_session_request(
        request,
        "GET",
        "/ai-data",
    )


@router.get("/auth/probe/admin")
async def probe_admin(request: Request):
    """Forward the current user's token to the actual POST /admin."""
    return await _forward_session_request(
        request,
        "POST",
        "/admin",
    )


@router.get("/auth/debug/token-claims")
async def debug_token_claims(request: Request):
    """
    Local-only diagnostic endpoint.

    Validates the actual stored access token and displays
    only the claims needed to diagnose permission assignment.
    Never displays the bearer token itself.
    """

    client_host = request.client.host if request.client else None

    if client_host not in ("127.0.0.1", "::1"):
        raise HTTPException(
            status_code=403,
            detail="Local diagnostic access only.",
        )

    session_id = request.session.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in again.",
        )

    token_record = request.app.state.token_store.get(session_id)

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Access token unavailable.",
        )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token_record["access_token"],
    )

    claims = await verify_access_token(credentials)

    return {
        "token_validation": "successful",
        "aud": claims.get("aud"),
        "iss": claims.get("iss"),
        "exp": claims.get("exp"),
        "scope": claims.get("scope"),
        "permissions": claims.get("permissions"),
        "azp": claims.get("azp"),
        "gty": claims.get("gty"),
    }

@router.get("/auth/debug/token-claims")
async def debug_token_claims(request: Request):
    """
    Local-only diagnostic endpoint.

    Validates the stored Auth0 access token and returns
    selected claims without exposing the actual token.
    """

    client_host = request.client.host if request.client else None

    if client_host not in ("127.0.0.1", "::1", "testclient"):
        raise HTTPException(
            status_code=403,
            detail="Local diagnostic access only.",
        )

    session_id = request.session.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in again.",
        )

    token_record = request.app.state.token_store.get(session_id)

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Access token unavailable.",
        )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token_record["access_token"],
    )

    claims = await verify_access_token(credentials)

    return {
        "token_validation": "successful",
        "aud": claims.get("aud"),
        "iss": claims.get("iss"),
        "exp": claims.get("exp"),
        "scope": claims.get("scope"),
        "permissions": claims.get("permissions"),
        "azp": claims.get("azp"),
        "gty": claims.get("gty"),
    }


@router.get("/auth/probe/authorization")
async def probe_authorization(request: Request):
    """
    Test user-level and admin-level authorization
    simultaneously using the same Auth0 access token.
    """

    client_host = request.client.host if request.client else None

    if client_host not in ("127.0.0.1", "::1"):
        raise HTTPException(
            status_code=403,
            detail="Local diagnostic access only.",
        )

    session_id = request.session.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in again.",
        )

    token_record = request.app.state.token_store.get(session_id)

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Access token unavailable.",
        )

    access_token = token_record["access_token"]
    expires_at = token_record.get("expires_at")

    remaining = (
        float(expires_at) - time.time()
        if expires_at else None
    )

    # Ensure the test begins with a sufficiently fresh token.
    if remaining is not None and remaining < 10:
        raise HTTPException(
            status_code=401,
            detail="Token expires soon. Please log in again.",
        )

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    async with httpx.AsyncClient(
        timeout=10.0,
        trust_env=False,
    ) as client:

        # Both requests use the exact same access token.
        ai_task, admin_task = await asyncio.gather(
            client.get(
                "http://127.0.0.1:8000/ai-data",
                headers=headers,
            ),
            client.post(
                "http://127.0.0.1:8000/admin",
                headers=headers,
            ),
        )

    return {
        "token_remaining_seconds_at_start": round(remaining, 2)
        if remaining is not None else None,
        "authorization_results": {
            "GET /ai-data": {
                "http_status": ai_task.status_code,
                "response": ai_task.json(),
            },
            "POST /admin": {
                "http_status": admin_task.status_code,
                "response": admin_task.json(),
            },
        },
    }

