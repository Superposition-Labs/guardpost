"""Address classification shared by the device and same-person rules.

Ports Factory v2's ``isGlobalIp`` (``device-repeat.ts``, which defers to the
SSRF ranges of ``lib/fetch-safe.ts``) and ``networkKey`` (``same-person.ts``).
These are NOT Python's ``ipaddress.is_global``: v2 blocks multicast and the
240/4 reserved block, and for IPv6 only the seven listed ranges, after
unwrapping IPv4-mapped (``::ffff:a.b.c.d``) and NAT64 (``64:ff9b::/96``)
addresses to vet the embedded IPv4.
"""

from __future__ import annotations

import ipaddress

from guardpost.ip.reputation import subnet_key

__all__ = ["canonical_ip", "is_global_ip", "network_key", "subnet_key"]

_V4_BLOCKED = tuple(ipaddress.ip_network(c) for c in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",  # CGNAT
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
))

_V6_BLOCKED = tuple(ipaddress.ip_network(c) for c in (
    "::/128",
    "::1/128",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
))

_V6_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_V6_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _parse(ip: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not ip or not isinstance(ip, str):
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def canonical_ip(ip: str | None) -> str | None:
    """The address in canonical text form (IPv6 compressed, lowercase), or None."""
    parsed = _parse(ip)
    return str(parsed) if parsed is not None else None


def _v4_public(addr: ipaddress.IPv4Address) -> bool:
    return not any(addr in net for net in _V4_BLOCKED)


def is_global_ip(ip: str | None) -> bool:
    """A public, routable unicast address by v2's ranges; False if unparseable."""
    addr = _parse(ip)
    if addr is None:
        return False
    if addr.version == 4:
        return _v4_public(addr)
    bare = ipaddress.IPv6Address(int(addr))  # drop any %zone
    if bare in _V6_MAPPED or bare in _V6_NAT64:
        return _v4_public(ipaddress.IPv4Address(int(bare) & 0xFFFFFFFF))
    return not any(bare in net for net in _V6_BLOCKED)


def network_key(ip: str | None) -> str | None:
    """The /24 of a global IPv4 ("203.0.114"), the address itself for IPv6, else None.

    Same shape as v2 (no trailing ".0/24"). IPv4-mapped IPv6 stays IPv6 and
    keys on the exact address, as in v2.
    """
    if not is_global_ip(ip):
        return None
    canon = canonical_ip(ip)
    assert canon is not None
    if ":" not in canon:
        return canon[: canon.rindex(".")]
    return canon
