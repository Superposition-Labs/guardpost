"""Tests for SMTP verification module."""

import asyncio
from unittest.mock import patch

import pytest

from guardpost.email.smtp import SMTPResult, SMTPStatus, SMTPVerifier, _random_local


class TestSMTPResult:
    def test_to_dict(self):
        result = SMTPResult(
            email="test@example.com",
            status=SMTPStatus.DELIVERABLE,
            smtp_code=250,
            smtp_message="OK",
            mx_host="mx.example.com",
        )
        d = result.to_dict()
        assert d["email"] == "test@example.com"
        assert d["status"] == "deliverable"
        assert d["smtp_code"] == 250
        assert d["is_catch_all"] is False
        assert d["mx_host"] == "mx.example.com"

    def test_status_enum_values(self):
        assert SMTPStatus.DELIVERABLE.value == "deliverable"
        assert SMTPStatus.UNDELIVERABLE.value == "undeliverable"
        assert SMTPStatus.RISKY.value == "risky"
        assert SMTPStatus.UNKNOWN.value == "unknown"


class TestRandomLocal:
    def test_random_local_format(self):
        local = _random_local()
        assert local.startswith("guardpost-probe-")
        assert len(local) == len("guardpost-probe-") + 12

    def test_random_local_unique(self):
        locals_ = {_random_local() for _ in range(100)}
        assert len(locals_) == 100  # All unique


class TestSMTPVerifier:
    def test_init_defaults(self):
        v = SMTPVerifier()
        assert v.timeout == 10.0
        assert v.helo_host == "guardpost.local"
        assert v.from_email == "verify@guardpost.local"
        assert v.catch_all_check is True
        assert v.proxy is None

    def test_init_custom(self):
        v = SMTPVerifier(
            timeout=5.0,
            helo_host="my.host",
            from_email="test@my.host",
            catch_all_check=False,
            proxy=("socks.example.com", 1080),
        )
        assert v.timeout == 5.0
        assert v.helo_host == "my.host"
        assert v.from_email == "test@my.host"
        assert v.catch_all_check is False
        assert v.proxy == ("socks.example.com", 1080)


@pytest.mark.asyncio
class TestSMTPVerifyInvalidInput:
    async def test_empty_email(self):
        v = SMTPVerifier()
        result = await v.verify("")
        assert result.status == SMTPStatus.UNKNOWN
        assert "invalid_email_format" in result.reasons

    async def test_no_at_sign(self):
        v = SMTPVerifier()
        result = await v.verify("notanemail")
        assert result.status == SMTPStatus.UNKNOWN
        assert "invalid_email_format" in result.reasons

    @patch("guardpost.email.smtp._resolve_mx", return_value=[])
    async def test_no_mx_records(self, mock_mx):
        v = SMTPVerifier()
        result = await v.verify("user@nonexistent-domain-xyz.com")
        assert result.status == SMTPStatus.UNDELIVERABLE
        assert "no_mx_records" in result.reasons


class TestSMTPInterpretRCPT:
    def test_250_deliverable(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 250, "OK", "mx.example.com")
        assert result.status == SMTPStatus.DELIVERABLE

    def test_550_undeliverable(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 550, "User not found", "mx.example.com")
        assert result.status == SMTPStatus.UNDELIVERABLE
        assert "mailbox_not_found" in result.reasons

    def test_451_temporary_failure(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 451, "Try later", "mx.example.com")
        assert result.status == SMTPStatus.RISKY
        assert "temporary_failure" in result.reasons

    def test_552_mailbox_full(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 552, "Mailbox full", "mx.example.com")
        assert result.status == SMTPStatus.RISKY
        assert "mailbox_full" in result.reasons

    def test_251_forwarded(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 251, "Forwarding", "mx.example.com")
        assert result.status == SMTPStatus.RISKY
        assert "forwarded" in result.reasons

    def test_554_transaction_failed(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 554, "Failed", "mx.example.com")
        assert result.status == SMTPStatus.UNDELIVERABLE
        assert "transaction_failed" in result.reasons

    def test_unexpected_code(self):
        v = SMTPVerifier()
        result = v._interpret_rcpt("user@example.com", 599, "Unknown", "mx.example.com")
        assert result.status == SMTPStatus.UNKNOWN
        assert "unexpected_code_599" in result.reasons


@pytest.mark.asyncio
class TestSMTPProbeMX:
    async def test_connection_refused_returns_none(self):
        """Connection refused should return None to try next MX."""
        v = SMTPVerifier(timeout=2.0)
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
            result = await v._probe_mx("user@example.com", "mx.example.com")
            assert result is None

    async def test_os_error_returns_none(self):
        """OS error should return None to try next MX."""
        v = SMTPVerifier(timeout=2.0)
        with patch("asyncio.open_connection", side_effect=OSError("Network unreachable")):
            result = await v._probe_mx("user@example.com", "mx.example.com")
            assert result is None

    async def test_timeout_returns_unknown(self):
        """Timeout should return UNKNOWN status."""
        v = SMTPVerifier(timeout=0.1)
        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
            result = await v._probe_mx("user@example.com", "mx.example.com")
            assert result is not None
            assert result.status == SMTPStatus.UNKNOWN
            assert "timeout" in result.reasons

    async def test_all_mx_unreachable(self):
        """When all MXes fail, return UNKNOWN."""
        v = SMTPVerifier(timeout=2.0)
        with patch("guardpost.email.smtp._resolve_mx", return_value=["mx1.example.com", "mx2.example.com"]):
            with patch.object(v, "_probe_mx", return_value=None):
                result = await v.verify("user@example.com")
                assert result.status == SMTPStatus.UNKNOWN
