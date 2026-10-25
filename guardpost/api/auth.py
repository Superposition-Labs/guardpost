"""Authentication for the API and the dashboard."""

from __future__ import annotations

import base64
import hmac
from typing import Annotated

from fastapi import Header, HTTPException, Request


def extract_basic_auth_password(request: Request) -> str | None:
    """Password from an HTTP Basic ``Authorization`` header, if present."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
    except Exception:
        return None
    _, _, password = decoded.partition(":")
    return password


def require_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """Verify API access via X-Api-Key header or HTTP Basic Auth password."""
    api_key = request.app.state.api_key
    if not api_key:
        return  # No key configured — API is open

    if x_api_key and hmac.compare_digest(x_api_key, api_key):
        return
    basic_password = extract_basic_auth_password(request)
    if basic_password and hmac.compare_digest(basic_password, api_key):
        return
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_dashboard_auth(request: Request) -> None:
    """Dashboard access via HTTP Basic Auth (password = API key; username ignored)."""
    api_key = request.app.state.api_key
    if not api_key:
        return
    basic_password = extract_basic_auth_password(request)
    if basic_password and hmac.compare_digest(basic_password, api_key):
        return
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="Guardpost Dashboard"'},
    )
