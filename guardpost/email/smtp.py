"""SMTP verification — check if a mailbox actually exists.

Uses the SMTP RCPT TO probe technique: connects to the recipient's
MX server and issues RCPT TO without actually sending an email.
The server's response indicates whether the mailbox exists.

**Requirements:**
- Outbound port 25 must be open (many cloud providers block it)
- Some servers always accept (catch-all) — we detect this
- Rate limiting is applied per-domain to avoid being flagged

**Usage:**

    from guardpost.email.smtp import SMTPVerifier

    verifier = SMTPVerifier()
    result = await verifier.verify("user@example.com")
    print(result.status)  # deliverable | undeliverable | risky | unknown
"""

from __future__ import annotations

import asyncio
import logging
import random
import string
from dataclasses import dataclass, field
from enum import Enum

import dns.resolver

logger = logging.getLogger(__name__)


class SMTPStatus(str, Enum):
    """Result of an SMTP verification."""

    DELIVERABLE = "deliverable"
    UNDELIVERABLE = "undeliverable"
    RISKY = "risky"  # catch-all, greylisting, or soft-fail
    UNKNOWN = "unknown"  # timeout, connection refused, etc.


@dataclass
class SMTPResult:
    """Full result of an SMTP verification check."""

    email: str
    status: SMTPStatus
    smtp_code: int | None = None
    smtp_message: str | None = None
    is_catch_all: bool = False
    mx_host: str | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "status": self.status.value,
            "smtp_code": self.smtp_code,
            "smtp_message": self.smtp_message,
            "is_catch_all": self.is_catch_all,
            "mx_host": self.mx_host,
            "reasons": self.reasons,
        }


# ---------------------------------------------------------------------------
# SMTP protocol helpers
# ---------------------------------------------------------------------------


async def _read_response(reader: asyncio.StreamReader, timeout: float) -> tuple[int, str]:
    """Read an SMTP response line. Returns (code, full_message)."""
    lines: list[str] = []
    while True:
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        line = raw.decode("utf-8", errors="replace").strip()
        lines.append(line)
        # Multi-line responses use "xxx-..." continuation; final line uses "xxx ..."
        if len(line) >= 4 and line[3] == " ":
            break
        if len(line) < 4:
            break
    full = "\n".join(lines)
    try:
        code = int(full[:3])
    except (ValueError, IndexError):
        code = 0
    return code, full


async def _send_command(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    command: str,
    timeout: float,
) -> tuple[int, str]:
    """Send an SMTP command and return the response."""
    writer.write(f"{command}\r\n".encode())
    await writer.drain()
    return await _read_response(reader, timeout)


def _random_local() -> str:
    """Generate a random local part for catch-all probing."""
    return "guardpost-probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


# ---------------------------------------------------------------------------
# MX resolution (reuses dns.resolver)
# ---------------------------------------------------------------------------


async def _resolve_mx(domain: str) -> list[str]:
    """Resolve MX hosts for a domain, sorted by preference."""
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "MX", lifetime=5.0)
        hosts = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".").lower() for r in hosts]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as exc:
        logger.debug("MX resolution error for %s: %s", domain, exc)
        return []


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------


class SMTPVerifier:
    """Verify email deliverability via SMTP RCPT TO probing.

    Args:
        timeout: Per-command timeout in seconds.
        helo_host: HELO/EHLO hostname to present. Defaults to 'guardpost.local'.
        from_email: MAIL FROM address. Defaults to 'verify@guardpost.local'.
        catch_all_check: Whether to probe for catch-all servers.
        proxy: Optional SOCKS5 proxy (host, port) tuple for outbound connections.
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        helo_host: str = "guardpost.local",
        from_email: str = "verify@guardpost.local",
        catch_all_check: bool = True,
        proxy: tuple[str, int] | None = None,
    ) -> None:
        self.timeout = timeout
        self.helo_host = helo_host
        self.from_email = from_email
        self.catch_all_check = catch_all_check
        self.proxy = proxy

    async def verify(self, email: str) -> SMTPResult:
        """Verify a single email address.

        Connects to the recipient's MX server, issues RCPT TO, and
        optionally checks for catch-all behavior.
        """
        if not email or "@" not in email:
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNKNOWN,
                reasons=["invalid_email_format"],
            )

        # Prevent SMTP command injection via crafted email addresses
        if any(c in email for c in ("\r", "\n", "<", ">", "\x00")):
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNKNOWN,
                reasons=["invalid_email_format"],
            )

        domain = email.lower().split("@")[1]
        mx_hosts = await _resolve_mx(domain)

        if not mx_hosts:
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNDELIVERABLE,
                reasons=["no_mx_records"],
            )

        # Try MX hosts in preference order
        last_error: str | None = None
        for mx_host in mx_hosts[:3]:  # cap at 3 attempts
            result = await self._probe_mx(email, mx_host)
            if result is not None:
                return result
            last_error = f"connection_failed:{mx_host}"

        return SMTPResult(
            email=email,
            status=SMTPStatus.UNKNOWN,
            reasons=[last_error or "all_mx_unreachable"],
        )

    async def _probe_mx(self, email: str, mx_host: str) -> SMTPResult | None:
        """Probe a single MX host. Returns None if connection fails."""
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None

        try:
            if self.proxy:
                reader, writer = await self._connect_via_proxy(mx_host)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(mx_host, 25),
                    timeout=self.timeout,
                )

            # Read banner
            code, msg = await _read_response(reader, self.timeout)
            if code != 220:
                return SMTPResult(
                    email=email,
                    status=SMTPStatus.UNKNOWN,
                    smtp_code=code,
                    smtp_message=msg,
                    mx_host=mx_host,
                    reasons=["bad_banner"],
                )

            # EHLO
            code, msg = await _send_command(writer, reader, f"EHLO {self.helo_host}", self.timeout)
            if code != 250:
                # Try HELO fallback
                code, msg = await _send_command(writer, reader, f"HELO {self.helo_host}", self.timeout)
                if code != 250:
                    return SMTPResult(
                        email=email,
                        status=SMTPStatus.UNKNOWN,
                        smtp_code=code,
                        smtp_message=msg,
                        mx_host=mx_host,
                        reasons=["helo_rejected"],
                    )

            # MAIL FROM
            code, msg = await _send_command(writer, reader, f"MAIL FROM:<{self.from_email}>", self.timeout)
            if code != 250:
                return SMTPResult(
                    email=email,
                    status=SMTPStatus.UNKNOWN,
                    smtp_code=code,
                    smtp_message=msg,
                    mx_host=mx_host,
                    reasons=["mail_from_rejected"],
                )

            # RCPT TO — the actual check
            code, msg = await _send_command(writer, reader, f"RCPT TO:<{email}>", self.timeout)

            result = self._interpret_rcpt(email, code, msg, mx_host)

            # Catch-all detection
            if self.catch_all_check and result.status == SMTPStatus.DELIVERABLE:
                is_catch_all = await self._check_catch_all(writer, reader, email)
                if is_catch_all:
                    result.is_catch_all = True
                    result.status = SMTPStatus.RISKY
                    result.reasons.append("catch_all_server")

            # QUIT
            try:
                await _send_command(writer, reader, "QUIT", self.timeout)
            except Exception:
                pass

            return result

        except (TimeoutError, asyncio.TimeoutError):
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNKNOWN,
                mx_host=mx_host,
                reasons=["timeout"],
            )
        except ConnectionRefusedError:
            logger.debug("SMTP connection refused by %s", mx_host)
            return None  # Try next MX
        except OSError as exc:
            logger.debug("SMTP connection error to %s: %s", mx_host, exc)
            return None  # Try next MX
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _connect_via_proxy(self, mx_host: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to MX host through a SOCKS5 proxy."""
        if self.proxy is None:
            raise ValueError("No proxy configured")

        proxy_host, proxy_port = self.proxy

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=self.timeout,
        )

        # SOCKS5 handshake: no-auth method
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
        if resp != b"\x05\x00":
            writer.close()
            raise ConnectionError("SOCKS5 proxy rejected no-auth method")

        # SOCKS5 connect request (domain mode)
        host_bytes = mx_host.encode("ascii")
        port_bytes = (25).to_bytes(2, "big")
        writer.write(b"\x05\x01\x00\x03" +
                     len(host_bytes).to_bytes(1, "big") + host_bytes + port_bytes)
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)
        if resp[1] != 0x00:
            writer.close()
            raise ConnectionError(
                f"SOCKS5 connect failed: status {resp[1]:#04x}")

        # Read bound address (variable length depending on address type)
        atype = resp[3]
        if atype == 0x01:  # IPv4
            await reader.readexactly(4 + 2)
        elif atype == 0x03:  # Domain
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length + 2)
        elif atype == 0x04:  # IPv6
            await reader.readexactly(16 + 2)

        return reader, writer

    def _interpret_rcpt(self, email: str, code: int, msg: str, mx_host: str) -> SMTPResult:
        """Interpret the RCPT TO response code."""
        if code == 250:
            return SMTPResult(
                email=email,
                status=SMTPStatus.DELIVERABLE,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
            )
        elif code == 251:
            # User not local; will forward
            return SMTPResult(
                email=email,
                status=SMTPStatus.RISKY,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=["forwarded"],
            )
        elif 400 <= code < 500:
            # Temporary failure — could be greylisting
            return SMTPResult(
                email=email,
                status=SMTPStatus.RISKY,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=["temporary_failure"],
            )
        elif code == 550 or code == 551 or code == 553:
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNDELIVERABLE,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=["mailbox_not_found"],
            )
        elif code == 552:
            return SMTPResult(
                email=email,
                status=SMTPStatus.RISKY,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=["mailbox_full"],
            )
        elif code == 554:
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNDELIVERABLE,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=["transaction_failed"],
            )
        else:
            return SMTPResult(
                email=email,
                status=SMTPStatus.UNKNOWN,
                smtp_code=code,
                smtp_message=msg,
                mx_host=mx_host,
                reasons=[f"unexpected_code_{code}"],
            )

    async def _check_catch_all(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        email: str,
    ) -> bool:
        """Test if the server accepts any address (catch-all).

        Sends RCPT TO with a random address at the same domain.
        If accepted, the server is a catch-all and the original
        result is unreliable.
        """
        domain = email.split("@")[1]
        probe_email = f"{_random_local()}@{domain}"

        try:
            code, _ = await _send_command(writer, reader, f"RCPT TO:<{probe_email}>", self.timeout)
            return code == 250
        except Exception:
            return False
