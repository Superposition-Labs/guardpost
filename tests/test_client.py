"""Tests for the Guardpost Python SDK client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardpost.client import GuardpostClient, GuardpostError


class TestGuardpostError:
    def test_error_message(self):
        err = GuardpostError(401, "Invalid API key")
        assert err.status_code == 401
        assert err.detail == "Invalid API key"
        assert "401" in str(err)

    def test_error_is_exception(self):
        err = GuardpostError(500, "Internal error")
        assert isinstance(err, Exception)


class TestGuardpostClientConfig:
    def test_base_url_stripped(self):
        client = GuardpostClient("https://api.example.com/")
        assert client.base_url == "https://api.example.com"

    def test_defaults(self):
        client = GuardpostClient("https://api.example.com")
        assert client.api_key is None
        assert client.timeout == 30.0

    def test_custom_config(self):
        client = GuardpostClient(
            "https://api.example.com",
            api_key="gp_test",
            timeout=10.0,
        )
        assert client.api_key == "gp_test"
        assert client.timeout == 10.0


class TestGuardpostClientHTTP:
    """Test client methods with mocked HTTP."""

    @pytest.fixture
    def mock_httpx(self):
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value = mock_client
            yield mock_client

    def _make_response(self, data, status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = data
        resp.text = json.dumps(data) if isinstance(data, dict) else str(data)
        return resp

    @pytest.mark.asyncio
    async def test_check(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "email": "test@example.com",
                "is_suspicious": True,
                "risk_score": 40,
                "reasons": ["disposable_domain"],
            }
        )

        async with GuardpostClient("https://api.example.com", api_key="test") as gp:
            result = await gp.check("test@example.com", ip_address="1.2.3.4")

        assert result["is_suspicious"] is True
        assert result["risk_score"] == 40
        # Verify the request
        mock_httpx.request.assert_called_once()
        call_args = mock_httpx.request.call_args
        assert call_args[0] == ("POST", "/api/v1/check")

    @pytest.mark.asyncio
    async def test_validate_email(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "email": "test@gmail.com",
                "is_valid": True,
                "is_disposable": False,
            }
        )

        async with GuardpostClient("https://api.example.com") as gp:
            result = await gp.validate_email("test@gmail.com")

        assert result["is_valid"] is True

    @pytest.mark.asyncio
    async def test_ai_score(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "email": "xk3jf8@gmail.com",
                "risk_score": 75,
                "confidence": 0.9,
                "reasons": ["auto_generated_username"],
            }
        )

        async with GuardpostClient("https://api.example.com", api_key="test") as gp:
            result = await gp.ai_score("xk3jf8@gmail.com")

        assert result["risk_score"] == 75
        call_args = mock_httpx.request.call_args
        assert call_args[0] == ("POST", "/api/v1/ai/score")

    @pytest.mark.asyncio
    async def test_ai_score_batch(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "results": [
                    {"email": "a@b.com", "risk_score": 10},
                    {"email": "xk3@gmail.com", "risk_score": 75},
                ]
            }
        )

        async with GuardpostClient("https://api.example.com", api_key="test") as gp:
            result = await gp.ai_score_batch(["a@b.com", "xk3@gmail.com"])

        assert len(result["results"]) == 2

    @pytest.mark.asyncio
    async def test_pattern_report(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "total_registrations": 5,
                "risk_level": "low",
            }
        )

        async with GuardpostClient("https://api.example.com") as gp:
            result = await gp.pattern_report()

        assert result["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_ban_email(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response(
            {
                "email": "bad@test.com",
                "banned": True,
            }
        )

        async with GuardpostClient("https://api.example.com", api_key="test") as gp:
            result = await gp.ban_email("bad@test.com", banned_by="admin", reason="spam")

        assert result["banned"] is True
        call_args = mock_httpx.request.call_args
        payload = call_args[1]["json"]
        assert payload["banned_by"] == "admin"
        assert payload["reason"] == "spam"

    @pytest.mark.asyncio
    async def test_health(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response({"status": "ok", "version": "0.1.0"})

        async with GuardpostClient("https://api.example.com") as gp:
            result = await gp.health()

        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_error_handling(self, mock_httpx):
        resp = MagicMock()
        resp.status_code = 401
        resp.text = '{"detail": "Invalid API key"}'
        resp.json.return_value = {"detail": "Invalid API key"}
        mock_httpx.request.return_value = resp

        async with GuardpostClient("https://api.example.com") as gp:
            with pytest.raises(GuardpostError) as exc_info:
                await gp.check("test@example.com")

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_error_non_json_response(self, mock_httpx):
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"
        resp.json.side_effect = Exception("not json")
        mock_httpx.request.return_value = resp

        async with GuardpostClient("https://api.example.com") as gp:
            with pytest.raises(GuardpostError) as exc_info:
                await gp.check("test@example.com")

        assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_check_with_all_options(self, mock_httpx):
        mock_httpx.request.return_value = self._make_response({"email": "t@t.com", "is_suspicious": False})

        async with GuardpostClient("https://api.example.com", api_key="key") as gp:
            await gp.check(
                "t@t.com",
                ip_address="1.2.3.4",
                smtp_verify=True,
                check_proxy=True,
                ai_score=True,
            )

        payload = mock_httpx.request.call_args[1]["json"]
        assert payload["smtp_verify"] is True
        assert payload["check_proxy"] is True
        assert payload["ai_score"] is True
        assert payload["ip_address"] == "1.2.3.4"
