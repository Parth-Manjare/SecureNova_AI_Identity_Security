"""SecureNova second Regular Web Application for an Auth0 SSO demonstration.

Run from the Project2_Auth0_Implementation directory:
    python -m uvicorn sso_demo:app --reload --host 127.0.0.1 --port 8001

Required .env entries:
    AUTH0_DOMAIN=your-tenant-region.auth0.com
    AUTH0_SSO_CLIENT_ID=...       # SecureNova SSO Demo Client
    AUTH0_SSO_CLIENT_SECRET=...   # SecureNova SSO Demo Client
    AUTH0_SSO_CALLBACK_URL=http://localhost:8001/callback
    SESSION_SECRET=...            # existing 32+ character local session secret

This app intentionally does NOT send prompt=login. If the same browser already
has a valid Auth0 tenant session from the main app, Auth0 should reuse it.
"""

from __future__ import annotations

import os
from html import escape
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth


load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "").strip()
AUTH0_DOMAIN = AUTH0_DOMAIN.removeprefix("https://").removeprefix("http://").rstrip("/")
SSO_CLIENT_ID = os.getenv("AUTH0_SSO_CLIENT_ID", "").strip()
SSO_CLIENT_SECRET = os.getenv("AUTH0_SSO_CLIENT_SECRET", "").strip()
SSO_CALLBACK_URL = os.getenv(
    "AUTH0_SSO_CALLBACK_URL", "http://localhost:8001/callback"
).strip()
SESSION_SECRET = os.getenv("SSO_SESSION_SECRET", "").strip() or os.getenv("SESSION_SECRET", "").strip()

missing = [
    name
    for name, value in {
        "AUTH0_DOMAIN": AUTH0_DOMAIN,
        "AUTH0_SSO_CLIENT_ID": SSO_CLIENT_ID,
        "AUTH0_SSO_CLIENT_SECRET": SSO_CLIENT_SECRET,
        "SESSION_SECRET or SSO_SESSION_SECRET": SESSION_SECRET,
    }.items()
    if not value
]
if missing:
    raise RuntimeError(
        "Missing required .env value(s): " + ", ".join(missing)
        + ". Add the SSO Demo Client credentials; never put secrets in source code."
    )
if len(SESSION_SECRET) < 32:
    raise RuntimeError("SESSION_SECRET must contain at least 32 characters.")

ISSUER = f"https://{AUTH0_DOMAIN}/"
NAMESPACE = "https://securenova.ai/"

oauth = OAuth()
oauth.register(
    name="auth0",
    client_id=SSO_CLIENT_ID,
    client_secret=SSO_CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",
    },
)

app = FastAPI(
    title="SecureNova SSO Demo Client",
    description="Second Regular Web Application used to demonstrate Auth0 SSO.",
    version="1.0.0",
)

# localhost cookies are host-scoped rather than port-scoped. Use a unique
# cookie name so this app does not overwrite the main app's session cookie.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="securenova_sso_demo_session",
    max_age=3600,
    same_site="lax",
    https_only=False,  # Local HTTP development only.
)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    logged_in = bool(request.session.get("user"))
    if logged_in:
        body = (
            '<p>Signed in to the second SecureNova client.</p>'
            '<p><a href="/me">View authenticated identity</a></p>'
            '<p><a href="/logout">Clear this app session (keeps Auth0 SSO session)</a></p>'
        )
    else:
        body = '<p><a href="/login">Continue with SecureNova / Auth0</a></p>'
    return HTMLResponse(
        "<!doctype html><html><head><title>SecureNova SSO Demo</title></head>"
        "<body style='font-family:Arial,sans-serif;max-width:760px;margin:60px auto;'>"
        "<h1>SecureNova SSO Demo Client</h1>"
        "<p>Second Regular Web Application — localhost:8001</p>"
        + body
        + "</body></html>"
    )


@app.get("/login")
async def login(request: Request):
    client = oauth.create_client("auth0")
    # Do not add prompt=login: it would force the user to re-enter credentials
    # and defeat the SSO demonstration.
    return await client.authorize_redirect(request, redirect_uri=SSO_CALLBACK_URL)


@app.get("/callback")
async def callback(request: Request):
    client = oauth.create_client("auth0")
    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Auth0 callback failed. Check the callback URL, client credentials, and browser session.",
        ) from exc

    userinfo: Any = token.get("userinfo")
    if not userinfo or not userinfo.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="Auth0 did not return a valid user identity in the ID token.",
        )

    # Keep only the minimum profile/claim data needed for this demonstration.
    request.session.clear()
    request.session["user"] = {
        "sub": userinfo.get("sub"),
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "agent_id": userinfo.get(f"{NAMESPACE}agent_id"),
    }
    return RedirectResponse(url="/me", status_code=303)


@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in. Visit /login first.")
    return {
        "status": "authenticated",
        "application": "SecureNova SSO Demo Client",
        "client_port": 8001,
        "user": user,
        "sso_note": "This client completed its own authorization-code flow using the existing Auth0 browser session when available.",
    }


@app.get("/logout")
async def logout(request: Request):
    # Clear only this application's local session; deliberately leave the
    # Auth0 tenant session intact so the SSO behaviour can be tested again.
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)
