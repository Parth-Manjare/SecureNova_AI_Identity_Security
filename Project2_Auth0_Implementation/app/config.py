
import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load local environment variables from .env
load_dotenv()


@dataclass(frozen=True)
class Settings:
    auth0_domain: str = os.getenv("AUTH0_DOMAIN", "").strip().removeprefix(
        "https://"
    ).rstrip("/")

    auth0_client_id: str = os.getenv("AUTH0_CLIENT_ID", "").strip()
    auth0_client_secret: str = os.getenv("AUTH0_CLIENT_SECRET", "").strip()

    auth0_api_audience: str = os.getenv(
        "AUTH0_API_AUDIENCE", ""
    ).strip()

    app_base_url: str = os.getenv(
        "APP_BASE_URL", "http://localhost:8000"
    ).strip().rstrip("/")

    auth0_callback_url: str = os.getenv(
        "AUTH0_CALLBACK_URL", "http://localhost:8000/callback"
    ).strip()

    auth0_scopes: str = os.getenv(
        "AUTH0_SCOPES", "openid profile email read:ai-data"
    ).strip()

    session_secret: str = os.getenv("SESSION_SECRET", "").strip()

    @property
    def issuer(self) -> str:
        return f"https://{self.auth0_domain}/"

    @property
    def openid_configuration_url(self) -> str:
        return f"{self.issuer}.well-known/openid-configuration"

    def validate_auth_config(self) -> None:
        required = {
            "AUTH0_DOMAIN": self.auth0_domain,
            "AUTH0_CLIENT_ID": self.auth0_client_id,
            "AUTH0_CLIENT_SECRET": self.auth0_client_secret,
            "AUTH0_API_AUDIENCE": self.auth0_api_audience,
            "AUTH0_CALLBACK_URL": self.auth0_callback_url,
            "SESSION_SECRET": self.session_secret,
        }

        missing = [
            name for name, value in required.items() if not value
        ]

        if missing:
            raise ValueError(
                "Missing environment variables: "
                + ", ".join(missing)
            )

        if len(self.session_secret) < 32:
            raise ValueError(
                "SESSION_SECRET must contain at least 32 characters."
            )

        if not self.auth0_api_audience.startswith("https://"):
            raise ValueError(
                "AUTH0_API_AUDIENCE must be an HTTPS identifier."
            )


settings = Settings()
