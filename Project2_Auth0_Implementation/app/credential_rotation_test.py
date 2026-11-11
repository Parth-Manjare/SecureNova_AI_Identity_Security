"""SecureNova Auth0 M2M token-expiry and replay demonstration.

Run from the project root after starting the FastAPI server:
    python credential_rotation_test.py

Required .env variables (keep .env private):
    AUTH0_DOMAIN=your-tenant.us.auth0.com
    AUTH0_API_AUDIENCE=https://api.securenova.ai
    AUTH0_M2M_CLIENT_ID=the-M2M-application-client-id
    AUTH0_M2M_CLIENT_SECRET=the-M2M-application-client-secret

This script never prints or writes the access token to disk.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from typing import Any

import httpx
from dotenv import load_dotenv


EXPECTED_TTL_SECONDS = 60
EXPIRY_SAFETY_BUFFER_SECONDS = 5


def log(message: str) -> None:
    """Print a local-time timestamp for screenshot evidence."""
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{timestamp}] {message}", flush=True)


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


def main() -> int:
    load_dotenv()
    api_base_url = os.getenv("SECURENOVA_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    chat_url = f"{api_base_url}/chat"

    try:
        domain = require_env("AUTH0_DOMAIN").removeprefix("https://").rstrip("/")
        audience = require_env("AUTH0_API_AUDIENCE")
        client_id = require_env("AUTH0_M2M_CLIENT_ID")
        client_secret = require_env("AUTH0_M2M_CLIENT_SECRET")
    except RuntimeError as exc:
        log(str(exc))
        log("Add the M2M credentials to your local .env file. Do not share that file.")
        return 2

    token_url = f"https://{domain}/oauth/token"
    token_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
        # Least privilege: /chat requires read:ai-data in app/routes.py.
        "scope": "read:ai-data",
    }

    log("Requesting an Auth0 M2M access token (client_credentials grant)...")
    try:
        with httpx.Client(timeout=20.0) as client:
            token_response = client.post(token_url, json=token_payload)
            if token_response.status_code != 200:
                log(f"TOKEN REQUEST FAILED: HTTP {token_response.status_code} {token_response.reason_phrase}")
                log(f"Auth0 response: {token_response.text[:1000]}")
                return 3

            token_data: dict[str, Any] = token_response.json()
            access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")
            granted_scope = token_data.get("scope", "")

            if not access_token:
                log("Auth0 returned HTTP 200 but no access_token field.")
                return 4
            if not isinstance(expires_in, int) or expires_in <= 0:
                log(f"Auth0 returned an unexpected expires_in value: {expires_in!r}")
                return 4

            log(f"M2M token obtained successfully; expires_in={expires_in} seconds.")
            log(f"Granted scope: {granted_scope or '(not included in response)'}")

            if expires_in != EXPECTED_TTL_SECONDS:
                log(
                    f"STOP: expected a {EXPECTED_TTL_SECONDS}-second token, "
                    f"but Auth0 issued {expires_in} seconds. Check the API Token Expiration setting."
                )
                return 5

            headers = {"Authorization": f"Bearer {access_token}"}
            body = {"message": "Credential rotation demonstration request."}

            log("Calling POST /chat with the newly issued M2M token...")
            first_response = client.post(chat_url, headers=headers, json=body)
            log(f"FIRST CALL: HTTP {first_response.status_code} {first_response.reason_phrase}")
            if first_response.status_code != 200:
                log(f"API response: {first_response.text[:1000]}")
                log("Expected HTTP 200. Check API server, audience, M2M grant and read:ai-data permission.")
                return 6

            log("Initial /chat request succeeded (HTTP 200 OK).")
            wait_seconds = expires_in + EXPIRY_SAFETY_BUFFER_SECONDS
            log(f"Waiting {wait_seconds} seconds so the access token is definitely expired...")
            time.sleep(wait_seconds)

            log("Replaying the SAME original access token after its expiry...")
            replay_response = client.post(chat_url, headers=headers, json=body)
            log(f"REPLAY CALL: HTTP {replay_response.status_code} {replay_response.reason_phrase}")

            if replay_response.status_code == 401:
                log("PASS: expired-token replay was rejected with HTTP 401 Unauthorized.")
                return 0

            if replay_response.status_code == 200:
                log("FAIL: the API accepted the token after the expected expiry period.")
                return 7

            log(
                "INCONCLUSIVE: expected HTTP 401 for an expired token; "
                f"received HTTP {replay_response.status_code}."
            )
            log(f"API response: {replay_response.text[:1000]}")
            return 8

    except httpx.ConnectError:
        log(f"Could not connect to {api_base_url}. Start the FastAPI server and try again.")
        return 9
    except httpx.TimeoutException:
        log("A request timed out. Check that Auth0 and the local API are reachable.")
        return 10
    except (ValueError, httpx.HTTPError) as exc:
        log(f"HTTP/response error: {exc}")
        return 11


if __name__ == "__main__":
    sys.exit(main())
