"""Tests for AI email scorer."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardpost.ai.scorer import AIScorer, AIScoreResult


class TestAIScoreResult:
    def test_to_dict(self):
        result = AIScoreResult(
            email="test@example.com",
            risk_score=75,
            confidence=0.9,
            reasons=["auto_generated_username"],
            analysis="Looks auto-generated",
            model="openai/gpt-4o-mini",
        )
        d = result.to_dict()
        assert d["email"] == "test@example.com"
        assert d["risk_score"] == 75
        assert d["confidence"] == 0.9
        assert d["reasons"] == ["auto_generated_username"]
        assert d["cached"] is False

    def test_defaults(self):
        result = AIScoreResult(email="a@b.com", risk_score=0, confidence=0.0)
        assert result.reasons == []
        assert result.analysis == ""
        assert result.model == ""
        assert result.cached is False


class TestAIScorerParsing:
    """Test response parsing without making real API calls."""

    def setup_method(self):
        self.scorer = AIScorer(api_key="test-key")

    def test_parse_valid_response(self):
        data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_score": 75,
                                "confidence": 0.9,
                                "reasons": ["auto_generated_username"],
                                "analysis": "Looks auto-generated",
                            }
                        )
                    }
                }
            ]
        }
        result = self.scorer._parse_response("test@gmail.com", data)
        assert result.risk_score == 75
        assert result.confidence == 0.9
        assert result.reasons == ["auto_generated_username"]
        assert result.model == "openai/gpt-4o-mini"

    def test_parse_response_with_markdown_blocks(self):
        data = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '```json\n{"risk_score": 60, "confidence": 0.8, "reasons": [], "analysis": "ok"}\n```'
                        )
                    }
                }
            ]
        }
        result = self.scorer._parse_response("test@gmail.com", data)
        assert result.risk_score == 60
        assert result.confidence == 0.8

    def test_parse_clamps_risk_score(self):
        data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_score": 150,
                                "confidence": 2.0,
                                "reasons": [],
                                "analysis": "",
                            }
                        )
                    }
                }
            ]
        }
        result = self.scorer._parse_response("a@b.com", data)
        assert result.risk_score == 100
        assert result.confidence == 1.0

    def test_parse_clamps_negative(self):
        data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_score": -10,
                                "confidence": -0.5,
                                "reasons": [],
                                "analysis": "",
                            }
                        )
                    }
                }
            ]
        }
        result = self.scorer._parse_response("a@b.com", data)
        assert result.risk_score == 0
        assert result.confidence == 0.0

    def test_parse_invalid_json(self):
        data = {"choices": [{"message": {"content": "not json at all"}}]}
        result = self.scorer._parse_response("a@b.com", data)
        assert result.risk_score == 50  # fallback
        assert result.confidence == 0.0
        assert "ai_parse_error" in result.reasons

    def test_parse_truncates_long_reasons(self):
        data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_score": 50,
                                "confidence": 0.5,
                                "reasons": ["x" * 200] * 20,
                                "analysis": "y" * 1000,
                            }
                        )
                    }
                }
            ]
        }
        result = self.scorer._parse_response("a@b.com", data)
        assert len(result.reasons) <= 10
        for r in result.reasons:
            assert len(r) <= 100
        assert len(result.analysis) <= 500


class TestAIScorerCache:
    def setup_method(self):
        self.scorer = AIScorer(api_key="test-key", cache_ttl=3600)

    @pytest.mark.asyncio
    async def test_cache_miss(self):
        assert await self.scorer._get_cached("a@b.com") is None

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        result = AIScoreResult(
            email="a@b.com",
            risk_score=50,
            confidence=0.5,
            model="test",
        )
        await self.scorer._set_cached("a@b.com", result)
        cached = await self.scorer._get_cached("a@b.com")
        assert cached is not None
        assert cached.risk_score == 50
        assert cached.cached is True

    @pytest.mark.asyncio
    async def test_cache_key_normalized(self):
        r1 = AIScoreResult(email="A@B.com", risk_score=50, confidence=0.5)
        await self.scorer._set_cached("A@B.com", r1)
        # Same email, different case → cache hit
        assert await self.scorer._get_cached("a@b.com") is not None

    @pytest.mark.asyncio
    async def test_cache_eviction(self):
        scorer = AIScorer(api_key="test-key", max_cache_size=2)
        for i in range(3):
            r = AIScoreResult(email=f"u{i}@b.com",
                              risk_score=i, confidence=0.5)
            await scorer._set_cached(f"u{i}@b.com", r)
        # First entry should be evicted
        assert await scorer._get_cached("u0@b.com") is None
        assert await scorer._get_cached("u1@b.com") is not None
        assert await scorer._get_cached("u2@b.com") is not None

    def test_clear_cache(self):
        r = AIScoreResult(email="a@b.com", risk_score=50, confidence=0.5)
        self.scorer._cache[self.scorer._cache_key(
            "a@b.com")] = (r, __import__("time").monotonic())
        count = self.scorer.clear_cache()
        assert count == 1


class TestAIScorerConfig:
    def test_default_model(self):
        scorer = AIScorer(api_key="test")
        assert scorer.model == "openai/gpt-4o-mini"

    def test_custom_model(self):
        scorer = AIScorer(api_key="test", model="anthropic/claude-3-haiku")
        assert scorer.model == "anthropic/claude-3-haiku"

    def test_custom_timeout(self):
        scorer = AIScorer(api_key="test", timeout=5.0)
        assert scorer.timeout == 5.0


class TestAIScorerIntegration:
    """Test score() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_score_caches_result(self):
        scorer = AIScorer(api_key="test-key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_score": 70,
                                "confidence": 0.85,
                                "reasons": ["auto_generated_username"],
                                "analysis": "Random chars",
                            }
                        )
                    }
                }
            ]
        }

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await scorer.score("xk3jf8@gmail.com")
            assert result.risk_score == 70
            assert result.cached is False

            # Second call should hit cache
            result2 = await scorer.score("xk3jf8@gmail.com")
            assert result2.risk_score == 70
            assert result2.cached is True
            # Only one API call
            assert mock_client.post.call_count == 1
