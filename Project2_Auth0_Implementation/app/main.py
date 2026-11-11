

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.routes import router
from app.auth import router as auth_router


app = FastAPI(
    title="SecureNova AI API",
    description=(
        "Auth0-protected API demonstrating OAuth 2.0, "
        "PKCE, JWT validation, RBAC and permission-based access."
    ),
    version="1.0.0",
)

# Temporary development-only server-side token storage.
# A production deployment should use a secure shared token/session store.
app.state.token_store = {}

# Authlib uses the session to preserve OAuth state,
# OIDC nonce and the PKCE code verifier across redirects.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie="securenova_session",
    max_age=3600,
    same_site="lax",
    https_only=False,  # Local development over HTTP only.
)

# Register API endpoints.
app.include_router(router)

# Register Auth0 login and callback endpoints.
app.include_router(auth_router)


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "Welcome to SecureNova AI API.",
        "documentation": "/docs",
        "health": "/health",
        "login": "/login",
    }
