from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


load_dotenv(ROOT / ".env")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def path_env(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else ROOT / value


@dataclass(frozen=True)
class Settings:
    issuer: str = os.getenv("MUXI_ISSUER", "http://127.0.0.1:9000").rstrip("/")
    database_path: Path = path_env("MUXI_DATABASE_PATH", "data/muxi-auth.db")
    signing_key_path: Path = path_env("MUXI_SIGNING_KEY_PATH", "data/oidc-signing.pem")
    enable_docs: bool = os.getenv("MUXI_ENABLE_DOCS") == "1"
    web_session_days: int = env_int("MUXI_WEB_SESSION_DAYS", 30)
    access_token_seconds: int = env_int("MUXI_ACCESS_TOKEN_SECONDS", 3600)
    refresh_token_days: int = env_int("MUXI_REFRESH_TOKEN_DAYS", 30)
    dev_verify: bool = os.getenv("MUXI_AUTH_DEV_VERIFY") == "1"

    bmc_web_client_id: str = os.getenv("MUXI_BMC_WEB_CLIENT_ID", "better-mc-web")
    bmc_web_client_secret: str = os.getenv("MUXI_BMC_WEB_CLIENT_SECRET", "")
    bmc_web_redirect_uri: str = os.getenv(
        "MUXI_BMC_WEB_REDIRECT_URI", "http://127.0.0.1:8099/api/v1/auth/callback"
    )
    bmc_launcher_client_id: str = os.getenv("MUXI_BMC_LAUNCHER_CLIENT_ID", "better-mc-launcher")
    bmc_launcher_redirect_uri: str = os.getenv(
        "MUXI_BMC_LAUNCHER_REDIRECT_URI", "http://127.0.0.1/oauth/callback"
    )

    smtp_host: str = os.getenv("MUXI_SMTP_HOST", "")
    smtp_port: int = env_int("MUXI_SMTP_PORT", 465)
    smtp_ssl: bool = os.getenv("MUXI_SMTP_SSL", "1") == "1"
    smtp_username: str = os.getenv("MUXI_SMTP_USERNAME", "")
    smtp_password: str = os.getenv("MUXI_SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("MUXI_SMTP_FROM", "Muxi Account <no-reply@muxigame.com>")

    # CZL Connect is an upstream identity broker. Keep compatibility with the
    # Client_ID / Client_Secret names already present in the local .env.
    czl_client_id: str = os.getenv("MUXI_CZL_CLIENT_ID") or os.getenv("Client_ID", "")
    czl_client_secret: str = os.getenv("MUXI_CZL_CLIENT_SECRET") or os.getenv("Client_Secret", "")
    czl_authorize_endpoint: str = os.getenv(
        "MUXI_CZL_AUTHORIZE_ENDPOINT", "https://connect.czl.net/oauth2/authorize"
    )
    czl_token_endpoint: str = os.getenv(
        "MUXI_CZL_TOKEN_ENDPOINT", "https://connect.czl.net/api/oauth2/token"
    )
    czl_userinfo_endpoint: str = os.getenv(
        "MUXI_CZL_USERINFO_ENDPOINT", "https://connect.czl.net/api/oauth2/userinfo"
    )

    @property
    def secure_cookies(self) -> bool:
        return self.issuer.lower().startswith("https://")

    @property
    def czl_redirect_uri(self) -> str:
        return f"{self.issuer}/external/czl/callback"


settings = Settings()

