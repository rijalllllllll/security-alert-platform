"""Application configuration — all values overridable via environment variables."""
import os

# --- Database ---
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./alerts.db")

# --- Security ---
# Comma-separated API keys allowed to write alerts / mutate state
ALERT_API_KEYS = [k.strip() for k in os.environ.get("ALERT_API_KEYS", "dev-key-123").split(",") if k.strip()]
# When true, every /api/* endpoint (except /healthz and /docs) requires X-API-Key
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() in ("1", "true", "yes")

# --- Optional enrichment providers ---
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# --- App ---
APP_NAME = os.environ.get("APP_NAME", "Security Alert Management Platform")
VERSION = "0.1.0"


def require_api_keys() -> bool:
    """True when auth is on AND at least one key is configured."""
    return REQUIRE_AUTH and bool(ALERT_API_KEYS)