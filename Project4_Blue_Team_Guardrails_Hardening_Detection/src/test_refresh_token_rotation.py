from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone
import hashlib
import base64
import secrets
import json
import os
import urllib.request
import webbrowser
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / "Project2_Auth0_Implementation" / ".env"
LOG_DIR = ROOT / "Project4_Blue_Team_Guardrails_Hardening_Detection" / "logs"


def load_env_file(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Project 2 .env not found: {path}"
        )

    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


def require_env(name):
    value = os.environ.get(name, "").strip()
    if not value or value.lower().startswith("replace_"):
        raise ValueError(f"Missing or placeholder environment value: {name}")
    return value


def post_token(domain, data):
    url = f"https://{domain}/oauth/token"

    request = urllib.request.Request(
        url,
        data=urlencode(data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(
                response.read().decode("utf-8")
            )
    except HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except Exception:
            body = {"error": "http_error"}
        return error.code, body
    except URLError as error:
        raise RuntimeError(
            "Could not connect to the Auth0 token endpoint."
        ) from error


class CallbackHandler(BaseHTTPRequestHandler):
    expected_state = None
    callback_path = None
    result = None

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path != self.callback_path:
            self.send_error(404)
            return

        query = parse_qs(parsed.query)
        returned_state = query.get("state", [""])[0]

        if returned_state != self.expected_state:
            self.result = {"error": "state_mismatch"}
            message = "State verification failed. You can close this tab."
        elif "error" in query:
            self.result = {
                "error": query["error"][0],
                "description": query.get("error_description", [""])[0]
            }
            message = "Authentication was not completed. You can close this tab."
        else:
            self.result = {
                "code": query.get("code", [""])[0]
            }
            message = "Authentication callback received. You can close this tab."

        body = (
            "<html><body><h3>SecureNova test callback</h3><p>"
            + message
            + "</p></body></html>"
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Do not log query parameters or authorization codes.
        return


def main():
    load_env_file(ENV_FILE)

    domain = require_env("AUTH0_DOMAIN")
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    client_id = require_env("AUTH0_CLIENT_ID")
    client_secret = require_env("AUTH0_CLIENT_SECRET")
    audience = require_env("AUTH0_API_AUDIENCE")

    redirect_uri = os.environ.get(
        "AUTH0_CALLBACK_URL",
        "http://localhost:8000/callback"
    ).strip()

    parsed_redirect = urlparse(redirect_uri)

    if parsed_redirect.scheme != "http" or parsed_redirect.hostname not in {
        "localhost", "127.0.0.1"
    }:
        raise ValueError(
            "This test requires a local HTTP callback using localhost "
            "or 127.0.0.1."
        )

    callback_host = parsed_redirect.hostname
    callback_port = parsed_redirect.port or 80
    callback_path = parsed_redirect.path or "/callback"

    configured_scopes = os.environ.get(
        "AUTH0_DEFAULT_SCOPES",
        "openid profile email read:ai-data"
    ).split()

    scopes = list(dict.fromkeys(
        configured_scopes + ["openid", "profile", "email",
                             "offline_access"]
    ))

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")

    CallbackHandler.expected_state = state
    CallbackHandler.callback_path = callback_path
    CallbackHandler.result = None

    server = HTTPServer(
        (callback_host, callback_port),
        CallbackHandler
    )
    server.timeout = 15

    authorize_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "audience": audience,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login"
    }

    authorize_url = (
        f"https://{domain}/authorize?"
        + urlencode(authorize_params)
    )

    print("=" * 72)
    print("SECURENOVA - AUTH0 REFRESH TOKEN ROTATION TEST")
    print("=" * 72)
    print("Client: Regular Web Application")
    print("Flow: Authorization Code + PKCE")
    print("Scope includes offline_access: YES")
    print("Raw tokens will not be printed or saved.")
    print("\nOpening Auth0 login in your browser...")

    try:
        webbrowser.open(authorize_url)
        deadline = time.monotonic() + 600

        while (
            CallbackHandler.result is None
            and time.monotonic() < deadline
        ):
            server.handle_request()
    finally:
        server.server_close()

    callback = CallbackHandler.result

    if not callback or not callback.get("code"):
        error = callback.get("error") if callback else "timeout"
        raise RuntimeError(
            f"Authorization callback failed: {error}. "
            "Check the callback URL, test user risk metadata, and Auth0 login."
        )

    print("[1] Auth0 callback received and state verified.")

    status, initial = post_token(domain, {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": callback["code"],
        "redirect_uri": redirect_uri,
        "code_verifier": verifier
    })

    if status != 200:
        raise RuntimeError(
            f"Authorization code exchange failed: "
            f"{initial.get('error', 'token_exchange_failed')}. "
            "Check Allowed Callback URLs, client credentials, "
            "offline_access, and the Refresh Token grant."
        )

    old_refresh_token = initial.get("refresh_token")

    if not old_refresh_token:
        raise RuntimeError(
            "Auth0 did not issue a refresh token. Check API Allow Offline "
            "Access, offline_access scope, and application grant settings."
        )

    print("[2] Initial refresh token issued: YES (value concealed).")

    # Exchange the original refresh token once.
    status, rotated = post_token(domain, {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": old_refresh_token
    })

    if status != 200:
        raise RuntimeError(
            f"First refresh exchange failed: "
            f"{rotated.get('error', 'refresh_exchange_failed')}."
        )

    new_refresh_token = rotated.get("refresh_token")

    if not new_refresh_token:
        raise RuntimeError(
            "Rotation response did not include a replacement refresh token. "
            "Check that rotation is enabled for this client."
        )

    if new_refresh_token == old_refresh_token:
        raise RuntimeError(
            "Auth0 returned the same refresh token; rotation was not confirmed."
        )

    print("[3] Refresh token rotation: SUCCESS.")
    print("[4] Replacement refresh token issued: YES (value concealed).")

    # Replay the original token, which has already been rotated.
    status, replay = post_token(domain, {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": old_refresh_token
    })

    replay_error = replay.get("error", "")
    replay_rejected = (
        status in (400, 401)
        and replay_error in ("invalid_grant", "access_denied")
    )

    print("\n[5] OLD REFRESH TOKEN REPLAY")
    print("HTTP status:", status)
    print("Auth0 error:", replay_error or "none")
    print("Old token replay rejected:", replay_rejected)

    if replay_rejected:
        result = "PASS - OLD REFRESH TOKEN REJECTED"
    else:
        result = "FAIL - EXPECTED REPLAY REJECTION NOT CONFIRMED"

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    log = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "flow": "Authorization Code with PKCE",
        "scope_offline_access": True,
        "initial_refresh_token_issued": True,
        "rotation_succeeded": True,
        "replacement_token_issued": True,
        "old_refresh_token_replay_http_status": status,
        "old_refresh_token_replay_error": replay_error,
        "old_refresh_token_replay_rejected": replay_rejected,
        "raw_tokens_logged": False,
        "client_secret_logged": False,
        "final_result": result
    }

    log_file = LOG_DIR / f"{timestamp}_refresh_token_replay.json"
    log_file.write_text(
        json.dumps(log, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 72)
    print("REFRESH TOKEN ROTATION TEST RESULT")
    print("=" * 72)
    print(result)
    print("Audit log:", log_file)

    return 0 if replay_rejected else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"\nTEST ERROR: {type(error).__name__}: {error}")
        sys.exit(1)
