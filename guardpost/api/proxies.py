"""Client-IP resolution behind reverse proxies.

X-Forwarded-For is attacker-controlled: anyone can send
``X-Forwarded-For: 1.2.3.4`` and, if the server believes it, pick the identity
the rate limiter keys on. So the header is honoured only when the direct peer
is a proxy we trust (``GUARDPOST_TRUSTED_PROXIES``, comma-separated CIDRs or
addresses), and even then only the hops our own proxies appended are believed:
walking the chain right to left, the client is the first hop that is not a
trusted proxy. With no trusted proxies configured the header is ignored and the
peer address is the client.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Iterable, Sequence

logger = logging.getLogger(__name__)

TRUSTED_PROXIES_ENV = "GUARDPOST_TRUSTED_PROXIES"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted_proxies(value: str | Iterable[str] | None) -> tuple[IPNetwork, ...]:
    """Parse comma-separated CIDRs / addresses. Raises ValueError on a bad entry."""
    if not value:
        return ()
    items = value.split(",") if isinstance(value, str) else value
    networks = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid entry in {TRUSTED_PROXIES_ENV}: {item!r}") from exc
    return tuple(networks)


def trusted_proxies_from_env() -> tuple[IPNetwork, ...]:
    return parse_trusted_proxies(os.environ.get(TRUSTED_PROXIES_ENV))


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = value.strip()
    # Tolerate "[v6]:port" and "v4:port", which some proxies emit.
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _is_trusted(ip, trusted: Sequence[IPNetwork]) -> bool:
    return any(ip.version == net.version and ip in net for net in trusted)


def resolve_client_ip(
    peer: str | None,
    forwarded_for: Iterable[str],
    trusted: Sequence[IPNetwork],
) -> str:
    """Return the client address for a request.

    Args:
        peer: the direct TCP peer (``request.client.host``).
        forwarded_for: every X-Forwarded-For header value, in order.
        trusted: networks whose hops may append to X-Forwarded-For.
    """
    if not peer:
        return "unknown"
    peer_ip = _parse_ip(peer)
    if peer_ip is None or not trusted or not _is_trusted(peer_ip, trusted):
        return str(peer_ip) if peer_ip else peer

    hops = [h.strip() for value in forwarded_for for h in value.split(",") if h.strip()]
    nearest = str(peer_ip)
    for hop in reversed(hops):
        hop_ip = _parse_ip(hop)
        if hop_ip is None:
            # A trusted proxy wrote something that is not an address. Nothing
            # to its left can be believed, so stop at the last hop we could.
            return nearest
        if not _is_trusted(hop_ip, trusted):
            return str(hop_ip)
        nearest = str(hop_ip)
    # Every hop is one of our proxies: the leftmost one is the best we have.
    return nearest


def request_client_ip(request, trusted: Sequence[IPNetwork]) -> str:
    """resolve_client_ip() for a Starlette/FastAPI request."""
    peer = request.client.host if request.client else None
    return resolve_client_ip(peer, request.headers.getlist("x-forwarded-for"), trusted)
