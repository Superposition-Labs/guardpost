"""Email enrichment — Gravatar and Have I Been Pwned lookups.

Optional enrichment layer that adds external intelligence to email checks.
Requires ``httpx`` (installed via ``pip install guardpost[enrichment]``).

Usage::

    from guardpost.email.enrichment import EmailEnrichment

    enrichment = EmailEnrichment()
    gravatar_url = await enrichment.gravatar_url("user@gmail.com")
    breaches = await enrichment.hibp_breaches("user@gmail.com")
    await enrichment.close()
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class EmailEnrichment:
    """External email enrichment lookups (Gravatar, HIBP).

    Args:
        hibp_api_key: API key for Have I Been Pwned (required for HIBP).
            Get one at https://haveibeenpwned.com/API/Key
        timeout: HTTP timeout in seconds.
    """

    def __init__(
        self,
        *,
        hibp_api_key: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        if not _HAS_HTTPX:
            raise ImportError(
                "httpx is required for email enrichment. Install with: pip install guardpost[enrichment]")
        self._hibp_api_key = hibp_api_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def gravatar_url(self, email: str) -> str | None:
        """Get the Gravatar profile image URL for an email, or None if no profile.

        Uses Gravatar's hash-based lookup — does NOT reveal the email to Gravatar.
        """
        email_hash = hashlib.md5(  # noqa: S324
            email.strip().lower().encode()
        ).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        try:
            resp = await self._client.head(url)
            if resp.status_code == 200:
                return f"https://www.gravatar.com/avatar/{email_hash}"
            return None
        except httpx.HTTPError:
            logger.debug("Gravatar lookup failed for ***@%s", email.split("@")
                         [-1] if "@" in email else "unknown", exc_info=True)
            return None

    async def hibp_breaches(self, email: str) -> list[dict[str, Any]]:
        """Check if an email appears in known data breaches via Have I Been Pwned.

        Returns a list of breach dicts with keys: Name, BreachDate, DataClasses.
        Returns empty list if no breaches found or API key not configured.

        Requires a paid HIBP API key (https://haveibeenpwned.com/API/Key).
        """
        if not self._hibp_api_key:
            logger.debug("HIBP API key not configured, skipping breach check")
            return []

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self._hibp_api_key,
            "user-agent": "guardpost",
        }
        params = {"truncateResponse": "false"}
        try:
            resp = await self._client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                breaches = resp.json()
                return [
                    {
                        "Name": b.get("Name", ""),
                        "BreachDate": b.get("BreachDate", ""),
                        "DataClasses": b.get("DataClasses", []),
                    }
                    for b in breaches
                ]
            if resp.status_code == 404:
                return []  # No breaches found
            if resp.status_code == 429:
                logger.warning("HIBP rate limit hit")
                return []
            logger.warning("HIBP returned status %d", resp.status_code)
            return []
        except httpx.HTTPError:
            logger.debug("HIBP lookup failed for ***@%s", email.split("@")
                         [-1] if "@" in email else "unknown", exc_info=True)
            return []

    async def hibp_breach_count(self, email: str) -> int:
        """Get the number of data breaches an email appears in."""
        breaches = await self.hibp_breaches(email)
        return len(breaches)
