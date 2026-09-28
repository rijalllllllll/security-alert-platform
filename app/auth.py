"""Authentication helpers.

API-key authentication for the alert API: every mutating endpoint (and,
when REQUIRE_AUTH=true, every endpoint) requires an `X-API-Key` header that
matches one of the keys in ALERT_API_KEYS. Intended to sit behind a reverse
proxy / VPN for production use.
"""
from fastapi import Header, HTTPException, status

from . import config


async def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> str:
    if not config.require_api_keys():
        return "dev"  # auth disabled
    if not x_api_key or x_api_key not in config.ALERT_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return x_api_key