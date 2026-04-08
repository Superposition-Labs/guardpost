"""VPN, proxy, and datacenter IP detection.

Identifies IPs belonging to cloud providers, VPNs, proxies, and Tor
exit nodes. Most registration abuse comes from datacenter IPs, not
residential connections.

**Detection layers:**
1. Built-in datacenter CIDR list (AWS, GCP, Azure, DigitalOcean, etc.)
2. MaxMind GeoLite2 ASN database (optional, local file)
3. Tor exit node detection (fetched from public list)
4. Optional IPinfo.io integration (privacy detection API)

**Usage:**

    from guardpost.ip.proxy import ProxyDetector

    detector = ProxyDetector()
    result = await detector.check("1.2.3.4")
    print(result.is_datacenter, result.provider)
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IPType(str, Enum):
    """Classification of an IP address."""

    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    VPN = "vpn"
    PROXY = "proxy"
    TOR = "tor"
    UNKNOWN = "unknown"


@dataclass
class ProxyResult:
    """Result of a proxy/VPN/datacenter check."""

    ip_address: str
    ip_type: IPType = IPType.UNKNOWN
    is_datacenter: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    provider: str | None = None  # e.g. "AWS", "Google Cloud", "DigitalOcean"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "ip_type": self.ip_type.value,
            "is_datacenter": self.is_datacenter,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "provider": self.provider,
            "reasons": self.reasons,
        }

    @property
    def is_suspicious(self) -> bool:
        """Any non-residential classification is suspicious for registration."""
        return self.is_datacenter or self.is_vpn or self.is_proxy or self.is_tor


# ---------------------------------------------------------------------------
# Built-in datacenter IP ranges
# ---------------------------------------------------------------------------
# These are well-known CIDR blocks from major cloud providers.
# Not exhaustive, but covers the most common abuse sources.
# Last updated: 2025-06

_DATACENTER_RANGES: dict[str, list[str]] = {
    "AWS": [
        "3.0.0.0/8",
        "13.32.0.0/12",
        "13.48.0.0/13",
        "13.56.0.0/14",
        "15.152.0.0/16",
        "15.177.0.0/16",
        "16.0.0.0/8",
        "18.0.0.0/8",
        "23.20.0.0/14",
        "34.192.0.0/10",
        "35.152.0.0/13",
        "44.192.0.0/10",
        "46.51.0.0/16",
        "50.16.0.0/14",
        "52.0.0.0/10",
        "54.64.0.0/10",
        "54.128.0.0/10",
        "54.192.0.0/10",
        "64.252.0.0/16",
        "75.101.128.0/17",
        "76.223.0.0/17",
        "99.77.0.0/16",
        "99.150.0.0/16",
        "107.20.0.0/14",
        "174.129.0.0/16",
        "175.41.128.0/17",
        "176.34.0.0/16",
        "184.72.0.0/13",
        "204.236.128.0/17",
    ],
    "Google Cloud": [
        "8.34.208.0/20",
        "8.35.192.0/20",
        "23.236.48.0/20",
        "23.251.128.0/19",
        "34.0.0.0/8",
        "35.184.0.0/13",
        "35.192.0.0/11",
        "35.224.0.0/12",
        "35.240.0.0/13",
        "104.154.0.0/15",
        "104.196.0.0/14",
        "107.167.160.0/19",
        "107.178.192.0/18",
        "108.59.80.0/20",
        "108.170.192.0/18",
        "130.211.0.0/16",
        "146.148.0.0/17",
        "162.216.148.0/22",
        "162.222.176.0/21",
        "173.255.112.0/20",
        "199.192.112.0/22",
        "199.223.232.0/21",
        "209.85.128.0/17",
    ],
    "Microsoft Azure": [
        "13.64.0.0/11",
        "13.96.0.0/13",
        "13.104.0.0/14",
        "20.0.0.0/8",
        "23.96.0.0/13",
        "40.64.0.0/10",
        "51.104.0.0/14",
        "51.124.0.0/14",
        "51.136.0.0/15",
        "51.140.0.0/14",
        "52.96.0.0/11",
        "52.136.0.0/13",
        "52.148.0.0/14",
        "52.152.0.0/13",
        "52.160.0.0/11",
        "52.224.0.0/11",
        "65.52.0.0/14",
        "70.37.0.0/16",
        "104.40.0.0/13",
        "104.208.0.0/13",
        "137.116.0.0/15",
        "137.135.0.0/16",
        "157.55.0.0/16",
        "168.61.0.0/16",
        "168.62.0.0/15",
        "191.232.0.0/13",
    ],
    "DigitalOcean": [
        "24.199.64.0/18",
        "45.55.0.0/16",
        "64.225.0.0/16",
        "67.205.128.0/17",
        "68.183.0.0/16",
        "104.131.0.0/16",
        "104.236.0.0/16",
        "107.170.0.0/16",
        "128.199.0.0/16",
        "134.122.0.0/16",
        "134.209.0.0/16",
        "137.184.0.0/16",
        "138.68.0.0/16",
        "138.197.0.0/16",
        "139.59.0.0/16",
        "142.93.0.0/16",
        "143.110.0.0/16",
        "143.198.0.0/16",
        "146.190.0.0/16",
        "157.230.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "159.203.0.0/16",
        "161.35.0.0/16",
        "162.243.0.0/16",
        "164.90.0.0/16",
        "164.92.0.0/16",
        "165.22.0.0/16",
        "165.227.0.0/16",
        "167.71.0.0/16",
        "167.99.0.0/16",
        "167.172.0.0/16",
        "170.64.0.0/16",
        "174.138.0.0/16",
        "178.128.0.0/16",
        "178.62.0.0/16",
        "188.166.0.0/16",
        "192.241.128.0/17",
        "198.199.64.0/18",
        "206.189.0.0/16",
        "209.97.128.0/17",
    ],
    "Hetzner": [
        "5.9.0.0/16",
        "23.88.0.0/15",
        "46.4.0.0/16",
        "49.12.0.0/14",
        "65.21.0.0/16",
        "65.108.0.0/16",
        "78.46.0.0/15",
        "85.10.192.0/18",
        "88.99.0.0/16",
        "91.107.128.0/17",
        "95.216.0.0/15",
        "116.202.0.0/15",
        "116.203.0.0/16",
        "128.140.0.0/16",
        "135.181.0.0/16",
        "136.243.0.0/16",
        "138.201.0.0/16",
        "142.132.128.0/17",
        "148.251.0.0/16",
        "157.90.0.0/16",
        "159.69.0.0/16",
        "162.55.0.0/16",
        "168.119.0.0/16",
        "176.9.0.0/16",
        "178.63.0.0/16",
        "188.40.0.0/16",
        "195.201.0.0/16",
        "213.133.96.0/19",
        "213.239.192.0/18",
    ],
    "OVH": [
        "5.39.0.0/16",
        "5.135.0.0/16",
        "5.196.0.0/16",
        "37.59.0.0/16",
        "37.187.0.0/16",
        "46.105.0.0/16",
        "51.38.0.0/15",
        "51.68.0.0/14",
        "51.75.0.0/16",
        "51.77.0.0/16",
        "51.79.0.0/16",
        "51.89.0.0/16",
        "51.91.0.0/16",
        "51.161.0.0/16",
        "51.178.0.0/16",
        "51.195.0.0/16",
        "51.210.0.0/16",
        "54.36.0.0/14",
        "91.121.0.0/16",
        "92.222.0.0/16",
        "135.125.0.0/16",
        "137.74.0.0/16",
        "141.94.0.0/16",
        "141.95.0.0/16",
        "145.239.0.0/16",
        "149.202.0.0/16",
        "151.80.0.0/16",
        "158.69.0.0/16",
        "164.132.0.0/16",
        "167.114.0.0/16",
        "176.31.0.0/16",
        "178.32.0.0/16",
        "185.228.96.0/22",
        "188.165.0.0/16",
        "193.70.0.0/16",
        "198.27.64.0/18",
        "198.50.128.0/17",
    ],
    "Linode": [
        "23.92.16.0/20",
        "23.239.0.0/20",
        "45.33.0.0/17",
        "45.56.0.0/16",
        "45.79.0.0/16",
        "50.116.0.0/17",
        "66.175.208.0/20",
        "69.164.192.0/20",
        "72.14.176.0/20",
        "74.207.224.0/20",
        "96.126.96.0/19",
        "97.107.128.0/20",
        "139.144.0.0/16",
        "139.162.0.0/16",
        "143.42.0.0/16",
        "170.187.128.0/17",
        "172.104.0.0/15",
        "172.232.0.0/14",
        "173.230.128.0/19",
        "173.255.192.0/18",
        "176.58.96.0/19",
        "178.79.128.0/17",
        "192.155.80.0/20",
        "194.195.208.0/20",
        "198.58.96.0/19",
        "212.71.232.0/21",
    ],
    "Vultr": [
        "45.32.0.0/16",
        "45.63.0.0/16",
        "45.76.0.0/16",
        "45.77.0.0/16",
        "64.156.0.0/16",
        "64.176.0.0/16",
        "66.42.0.0/16",
        "78.141.192.0/18",
        "80.240.16.0/20",
        "95.179.128.0/17",
        "104.156.224.0/19",
        "104.207.128.0/17",
        "108.61.0.0/16",
        "136.244.64.0/18",
        "137.220.32.0/19",
        "140.82.0.0/16",
        "141.164.32.0/19",
        "144.202.0.0/16",
        "149.28.0.0/16",
        "149.248.0.0/16",
        "155.138.128.0/17",
        "207.148.0.0/17",
        "209.250.224.0/19",
        "216.128.128.0/17",
        "217.69.0.0/16",
    ],
    "Oracle Cloud": [
        "129.146.0.0/16",
        "129.148.0.0/16",
        "129.151.0.0/16",
        "129.153.0.0/16",
        "129.154.0.0/16",
        "129.157.0.0/16",
        "129.158.0.0/16",
        "129.159.0.0/16",
        "130.35.0.0/16",
        "130.61.0.0/16",
        "130.162.0.0/16",
        "132.145.0.0/16",
        "134.65.0.0/16",
        "134.70.0.0/16",
        "140.91.0.0/16",
        "140.238.0.0/16",
        "141.144.192.0/18",
        "141.147.0.0/16",
        "144.21.0.0/16",
        "144.24.0.0/14",
        "147.154.0.0/16",
        "150.136.0.0/16",
        "152.67.0.0/16",
        "152.69.0.0/16",
        "152.70.0.0/15",
        "155.248.0.0/16",
        "158.101.0.0/16",
        "158.178.0.0/15",
        "168.75.0.0/16",
        "168.138.0.0/16",
        "192.29.0.0/16",
        "193.122.0.0/15",
        "193.123.0.0/16",
    ],
}


# Pre-compiled network objects for fast lookup
_COMPILED_RANGES: list[tuple[ipaddress.IPv4Network |
                             ipaddress.IPv6Network, str]] = []


def _compile_ranges() -> None:
    """Compile CIDR strings into network objects (once at import)."""
    global _COMPILED_RANGES
    if _COMPILED_RANGES:
        return
    for provider, cidrs in _DATACENTER_RANGES.items():
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                _COMPILED_RANGES.append((net, provider))
            except ValueError as exc:
                logger.warning("Invalid CIDR %s for %s: %s",
                               cidr, provider, exc)
    # Sort by prefix length (most specific first) for faster matching
    _COMPILED_RANGES.sort(key=lambda x: x[0].prefixlen, reverse=True)


_compile_ranges()


# ---------------------------------------------------------------------------
# Tor exit node list (fetched lazily)
# ---------------------------------------------------------------------------

_tor_exit_nodes: set[str] | None = None
_tor_last_fetch: float = 0.0
_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_REFRESH_INTERVAL = 6 * 3600  # refresh every 6 hours


async def _fetch_tor_exits() -> set[str]:
    """Fetch Tor exit node list. Returns empty set on failure. Refreshes every 6 hours."""
    global _tor_exit_nodes, _tor_last_fetch
    import time as _time

    now = _time.monotonic()
    if _tor_exit_nodes is not None and (now - _tor_last_fetch) < _TOR_REFRESH_INTERVAL:
        return _tor_exit_nodes

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_TOR_LIST_URL)
            resp.raise_for_status()
            _tor_exit_nodes = {
                line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")
            }
            _tor_last_fetch = now
            logger.info("Loaded %d Tor exit nodes", len(_tor_exit_nodes))
            return _tor_exit_nodes
    except ImportError:
        logger.debug("httpx not installed — Tor exit node detection disabled")
        _tor_exit_nodes = _tor_exit_nodes or set()
        return _tor_exit_nodes
    except Exception as exc:
        logger.debug("Failed to fetch Tor exit node list: %s", exc)
        _tor_exit_nodes = _tor_exit_nodes or set()
        return _tor_exit_nodes


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------


class ProxyDetector:
    """Detect VPN, proxy, datacenter, and Tor IPs.

    Args:
        ipinfo_token: Optional IPinfo.io API token for enhanced detection.
        check_tor: Whether to check against Tor exit node list.
        extra_ranges: Additional CIDR ranges to flag as datacenter.
    """

    def __init__(
        self,
        *,
        ipinfo_token: str | None = None,
        check_tor: bool = True,
        extra_ranges: dict[str, list[str]] | None = None,
        maxmind_db_path: str | None = None,
    ) -> None:
        self.ipinfo_token = ipinfo_token
        self.check_tor = check_tor

        # MaxMind GeoLite2 ASN reader (optional)
        self._maxmind_reader = None
        if maxmind_db_path:
            try:
                import geoip2.database

                self._maxmind_reader = geoip2.database.Reader(maxmind_db_path)
                logger.info(
                    "MaxMind GeoLite2 ASN database loaded: %s", maxmind_db_path)
            except ImportError:
                logger.warning(
                    "geoip2 not installed — MaxMind detection disabled. pip install geoip2")
            except Exception as exc:
                logger.warning("Failed to load MaxMind DB %s: %s",
                               maxmind_db_path, exc)

        # Compile extra ranges if provided
        self._extra: list[tuple[ipaddress.IPv4Network |
                                ipaddress.IPv6Network, str]] = []
        if extra_ranges:
            for provider, cidrs in extra_ranges.items():
                for cidr in cidrs:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        self._extra.append((net, provider))
                    except ValueError:
                        pass

    async def check(self, ip_address: str) -> ProxyResult:
        """Check an IP address for proxy/VPN/datacenter/Tor.

        Layers checked in order:
        1. Built-in datacenter CIDR ranges
        2. Tor exit node list
        3. IPinfo.io privacy API (if token provided)
        """
        result = ProxyResult(ip_address=ip_address)

        try:
            addr = ipaddress.ip_address(ip_address)
        except ValueError:
            result.reasons.append("invalid_ip_format")
            return result

        # Skip private/reserved IPs
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            result.ip_type = IPType.RESIDENTIAL
            result.reasons.append("private_ip")
            return result

        # Layer 1: Built-in datacenter ranges
        provider = self._check_datacenter_ranges(addr)
        if provider:
            result.is_datacenter = True
            result.ip_type = IPType.DATACENTER
            result.provider = provider
            result.reasons.append(f"datacenter_range:{provider}")
            return result

        # Layer 2: MaxMind GeoLite2 ASN (hosting/datacenter detection)
        if self._maxmind_reader:
            maxmind_result = self._check_maxmind(ip_address)
            if maxmind_result:
                result.is_datacenter = True
                result.ip_type = IPType.DATACENTER
                result.provider = maxmind_result
                result.reasons.append(f"maxmind_asn:{maxmind_result}")
                return result

        # Layer 3: Tor exit nodes
        if self.check_tor:
            tor_nodes = await _fetch_tor_exits()
            if ip_address in tor_nodes:
                result.is_tor = True
                result.ip_type = IPType.TOR
                result.reasons.append("tor_exit_node")
                return result

        # Layer 4: IPinfo.io (if configured)
        if self.ipinfo_token:
            ipinfo_result = await self._check_ipinfo(ip_address)
            if ipinfo_result:
                result.is_vpn = ipinfo_result.get("vpn", False)
                result.is_proxy = ipinfo_result.get("proxy", False)
                result.is_datacenter = ipinfo_result.get("hosting", False)
                result.is_tor = ipinfo_result.get(
                    "tor", False) or result.is_tor

                if result.is_tor:
                    result.ip_type = IPType.TOR
                elif result.is_vpn:
                    result.ip_type = IPType.VPN
                elif result.is_proxy:
                    result.ip_type = IPType.PROXY
                elif result.is_datacenter:
                    result.ip_type = IPType.DATACENTER

                if result.is_suspicious:
                    result.reasons.append("ipinfo_flagged")

        return result

    def _check_datacenter_ranges(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        """Check if an IP falls within known datacenter CIDR ranges."""
        # Check extra ranges first (user-provided, higher priority)
        for net, provider in self._extra:
            if addr in net:
                return provider

        # Check built-in ranges
        for net, provider in _COMPILED_RANGES:
            if addr in net:
                return provider

        return None

    # ASN organization names that indicate hosting/datacenter infrastructure
    _HOSTING_ORG_KEYWORDS = frozenset(
        [
            "hosting",
            "cloud",
            "server",
            "datacenter",
            "data center",
            "colocation",
            "colo",
            "vps",
            "dedicated",
            "infrastructure",
            "hetzner",
            "ovh",
            "leaseweb",
            "choopa",
            "vultr",
            "linode",
            "digitalocean",
            "amazon",
            "google",
            "microsoft",
            "azure",
            "oracle",
            "rackspace",
            "softlayer",
            "cogent",
            "quadranet",
            "psychz",
            "contabo",
            "scaleway",
            "upcloud",
            "kamatera",
        ]
    )

    def _check_maxmind(self, ip_address: str) -> str | None:
        """Check if an IP belongs to a hosting/datacenter ASN via MaxMind GeoLite2."""
        if not self._maxmind_reader:
            return None
        try:
            resp = self._maxmind_reader.asn(ip_address)
            org = (resp.autonomous_system_organization or "").lower()
            for keyword in self._HOSTING_ORG_KEYWORDS:
                if keyword in org:
                    return resp.autonomous_system_organization
        except Exception:
            pass
        return None

    async def _check_ipinfo(self, ip_address: str) -> dict | None:
        """Query IPinfo.io privacy detection API."""
        try:
            import httpx

            url = f"https://ipinfo.io/{ip_address}/privacy"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    url,
                    params={"token": self.ipinfo_token},
                )
                if resp.status_code == 200:
                    return resp.json()
                logger.debug("IPinfo API returned %d for %s",
                             resp.status_code, ip_address)
                return None
        except ImportError:
            logger.debug("httpx not installed — IPinfo detection disabled")
            return None
        except Exception as exc:
            logger.debug("IPinfo API error for %s: %s", ip_address, exc)
            return None
