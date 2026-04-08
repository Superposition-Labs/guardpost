"""Guardpost Python SDK — client for the hosted Guardpost API.

This module provides a thin async client for integrating with a remote
Guardpost instance (self-hosted or cloud). It mirrors the REST API
with Python-native types.

Installation::

    pip install guardpost[client]
    # or for the full package: pip install guardpost[all]

Usage::

    from guardpost.client import GuardpostClient

    async with GuardpostClient("https://api.guardpost.dev", api_key="gp_...") as gp:
        result = await gp.check("user@mailinator.com", ip_address="1.2.3.4")
        print(result["is_suspicious"])   # True
        print(result["risk_score"])      # 40

        # AI scoring (hosted feature)
        ai = await gp.ai_score("xk3jf8@gmail.com")
        print(ai["risk_score"])  # 75

        # Batch AI scoring
        batch = await gp.ai_score_batch(["a@b.com", "xyz@gmail.com"])
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any

logger = logging.getLogger(__name__)


class GuardpostError(Exception):
    """Base exception for Guardpost client errors."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class GuardpostClient:
    """Async HTTP client for the Guardpost API.

    Args:
        base_url: Base URL of the Guardpost server (e.g., "https://api.guardpost.dev").
        api_key: Optional API key for authentication.
        timeout: Request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = None

    async def _ensure_client(self):
        if self._client is None:
            import httpx

            headers = {}
            if self.api_key:
                headers["X-Api-Key"] = self.api_key
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> GuardpostClient:
        await self._ensure_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        await self._ensure_client()
        assert self._client is not None
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise GuardpostError(resp.status_code, detail)
        return resp.json()

    # ------------------------------------------------------------------
    # Core endpoints
    # ------------------------------------------------------------------

    async def check(
        self,
        email: str,
        *,
        ip_address: str | None = None,
        record_ip: bool = True,
        smtp_verify: bool = False,
        check_proxy: bool = False,
        ai_score: bool = False,
    ) -> dict[str, Any]:
        """Full registration suspicion check.

        Returns:
            Dict with is_suspicious, risk_score, reasons, etc.
        """
        payload: dict[str, Any] = {
            "email": email,
            "record_ip": record_ip,
            "smtp_verify": smtp_verify,
            "check_proxy": check_proxy,
            "ai_score": ai_score,
        }
        if ip_address:
            payload["ip_address"] = ip_address
        return await self._request("POST", "/api/v1/check", json=payload)

    async def validate_email(self, email: str) -> dict[str, Any]:
        """Email-only validation (no IP, no storage)."""
        return await self._request("POST", "/api/v1/email/validate", json={"email": email})

    async def check_ip(self, ip_address: str) -> dict[str, Any]:
        """Check IP reputation."""
        return await self._request("POST", "/api/v1/ip/check", json={"ip_address": ip_address})

    async def record_ip(self, ip_address: str, is_suspicious: bool = False) -> dict[str, Any]:
        """Record a registration from an IP."""
        return await self._request(
            "POST",
            "/api/v1/ip/record",
            json={"ip_address": ip_address, "is_suspicious": is_suspicious},
        )

    async def check_proxy(self, ip_address: str) -> dict[str, Any]:
        """Check if IP is VPN/proxy/datacenter/Tor."""
        return await self._request("POST", "/api/v1/ip/proxy", json={"ip_address": ip_address})

    async def smtp_verify(self, email: str) -> dict[str, Any]:
        """SMTP mailbox verification."""
        return await self._request("POST", "/api/v1/email/smtp", json={"email": email})

    # ------------------------------------------------------------------
    # Ban management
    # ------------------------------------------------------------------

    async def ban_email(
        self,
        email: str,
        *,
        banned_by: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Add email to permanent ban list."""
        payload: dict[str, Any] = {"email": email}
        if banned_by:
            payload["banned_by"] = banned_by
        if reason:
            payload["reason"] = reason
        return await self._request("POST", "/api/v1/email/ban", json=payload)

    async def unban_email(self, email: str) -> dict[str, Any]:
        """Remove email from ban list."""
        return await self._request("DELETE", "/api/v1/email/ban", json={"email": email})

    # ------------------------------------------------------------------
    # AI scoring (hosted feature)
    # ------------------------------------------------------------------

    async def ai_score(self, email: str) -> dict[str, Any]:
        """AI-powered email risk scoring.

        Returns:
            Dict with risk_score (0-100), confidence, reasons, analysis.
        """
        return await self._request("POST", "/api/v1/ai/score", json={"email": email})

    async def ai_score_batch(self, emails: list[str]) -> dict[str, Any]:
        """Batch AI email scoring (up to 100 emails).

        Returns:
            Dict with results list.
        """
        return await self._request("POST", "/api/v1/ai/score/batch", json={"emails": emails})

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    async def pattern_report(self) -> dict[str, Any]:
        """Get registration pattern analysis report.

        Returns:
            Dict with risk_level, clusters, velocity info.
        """
        return await self._request("GET", "/api/v1/patterns/report")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Health check."""
        return await self._request("GET", "/api/v1/health")
