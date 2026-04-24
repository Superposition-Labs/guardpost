"""Email validation engine for registration abuse detection.

Provides multi-layer email validation:
- Layer 1: Community-maintained disposable email blocklist (5,200+ domains)
- Layer 2: Custom blocklist for manually confirmed disposable domains (170+)
- Layer 3: Trusted domain whitelist (skip expensive DNS checks)
- Layer 4: MX infrastructure detection (catch fresh throwaway domains)
- Layer 5: DNS MX record validation with caching

Philosophy: Silent degradation — don't block suspicious registrations,
deny bonuses silently so attackers can't learn detection signals.
"""

import asyncio
import logging
import re
from pathlib import Path

import dns.resolver

logger = logging.getLogger(__name__)

# === LAYER 1: Community-maintained disposable email blocklist (5,200+ domains) ===
# Source: https://github.com/disposable-email-domains/disposable-email-domains
_BLOCKLIST_PATH = Path(__file__).resolve().parent.parent / \
    "data" / "disposable_email_blocklist.conf"
try:
    _community_blocklist = {
        line.strip() for line in _BLOCKLIST_PATH.read_text().splitlines() if line.strip() and not line.startswith("#")
    }
    COMMUNITY_DISPOSABLE_DOMAINS: frozenset[str] = frozenset(
        _community_blocklist)
    logger.info("Loaded %d community disposable domains",
                len(COMMUNITY_DISPOSABLE_DOMAINS))
except FileNotFoundError:
    logger.warning(
        "Blocklist file not found at %s — disposable domain detection will be limited", _BLOCKLIST_PATH)
    COMMUNITY_DISPOSABLE_DOMAINS = frozenset()

# === LAYER 2: Custom blocklist — manually confirmed disposable domains ===
CUSTOM_DISPOSABLE_DOMAINS = frozenset(
    [
        # Popular disposable services
        "10minutemail.com",
        "10minutemail.net",
        "20minutemail.com",
        "33mail.com",
        "discard.email",
        "discardmail.com",
        "disposable.email",
        "disposableemailaddresses.com",
        "emailondeck.com",
        "fakeinbox.com",
        "fakemailgenerator.com",
        "getnada.com",
        "guerrillamail.com",
        "guerrillamail.info",
        "guerrillamail.net",
        "guerrillamail.org",
        "mailcatch.com",
        "maildrop.cc",
        "mailinator.com",
        "mailinator.net",
        "mailnesia.com",
        "mailsac.com",
        "mohmal.com",
        "sharklasers.com",
        "spam4.me",
        "spamgourmet.com",
        "temp-mail.org",
        "tempail.com",
        "tempemail.co",
        "tempemail.net",
        "tempinbox.com",
        "tempmail.com",
        "tempmail.net",
        "tempmailaddress.com",
        "tempmails.net",
        "temporaryemail.net",
        "temporaryinbox.com",
        "throwaway.email",
        "throwawaymail.com",
        "trashmail.com",
        "trashmail.net",
        "wegwerfmail.de",
        "yopmail.com",
        "yopmail.fr",
        "yopmail.net",
        # Russian disposable providers
        "dropmail.me",
        "mailforspam.com",
        "mytemp.email",
        "temp-mail.ru",
        "tempmailo.com",
        "tempr.email",
        # Additional confirmed disposable
        "burnermail.io",
        "cock.li",
        "dispostable.com",
        "emailfake.com",
        "emailtemporaire.fr",
        "fakeemail.com",
        "getairmail.com",
        "guerrillamailblock.com",
        "harakirimail.com",
        "hidemail.de",
        "incognitomail.com",
        "inboxalias.com",
        "jetable.org",
        "kasmail.com",
        "mailexpire.com",
        "mailnator.com",
        "mintemail.com",
        "mt2015.com",
        "mytrashmail.com",
        "nomail.xl.cx",
        "nospam.ze.tc",
        "objectmail.com",
        "proxymail.eu",
        "rcpt.at",
        "rejectmail.com",
        "safetymail.info",
        "spambox.us",
        "spamfree24.org",
        "spoofmail.de",
        "tempinbox.co.uk",
        "tempomail.fr",
        "thankyou2010.com",
        "trash-amil.com",
        "trash2009.com",
        "trashymail.com",
        "trbvm.com",
        "wegwerfadresse.de",
        "wetrashmail.com",
        "whyspam.me",
        "willhackforfood.biz",
        "willselfdestruct.com",
        "xyzfree.net",
        "yamet.com",
        "zehnminuten.de",
        # Domains routing through known disposable MX infrastructure
        "zzuux.com",
        "qqwwt.com",
        "vvkku.com",
        "seuuo.com",
        "dollicons.com",
        "ongvo.com",
        "sharebot.net",
        "kayilo.com",
        "mailshun.com",
        "fanymail.com",
        "pindush.net",
        "seduck.com",
        "jsncos.com",
        "izkat.com",
        "atminmail.com",
        "uiemail.com",
        "california.edu.pl",
        "7novels.com",
        "cslua.com",
        "bultoc.com",
        "mailbali.com",
        # Self-hosted on VPS, no website, gibberish usernames
        "vubids.com",
        "flownue.com",
        "ideaicu.com",
        # Investigation-discovered domains
        "minitts.net",
        "webxio.pro",
        "awsl.uk",
        "airsworld.net",
        "virgilian.com",
        "cimario.com",
        "2200freefonts.com",
        "icubik.com",
        # Apr 2026: temp-mail-go.info evaded blocklist via hyphenated variant
        "temp-mail-go.info",
        # Apr 2026: caught via tempamail.com MX infrastructure
        "mailfrs.com",
        "ozvmail.com",
        # Apr 2026: caught via sparkblink.org shared MX infrastructure
        "forgecomet.org",
        "cobaltbeam.com",
        "worldplanck.com",
        "databeta.net",
        "beamcobalt.com",
        # Apr 2026: Cloudflare Email Routing abuse (no A record, no website)
        # route[1-3].mx.cloudflare.net MX + zero A record = pure throwaway relay
        "greance.us",
        "demdon.online",
        "chiencapcut.site",
        "mooncapt.shop",
        # Apr 2026: solutioncipher.com shared MX infrastructure
        "spaceeclipse.com",
        "linkzulu.com",
        # Apr 2026: mail.tm subdomain MX infrastructure
        "deltajohnsons.com",
        # Apr 2026: centerzeta.com MX infrastructure (also caught by MX check)
        "loopquant.net",
    ]
)

# Combined disposable domain set
DISPOSABLE_EMAIL_DOMAINS = COMMUNITY_DISPOSABLE_DOMAINS | CUSTOM_DISPOSABLE_DOMAINS

# === LAYER 3: Known-good domains (skip MX check for performance) ===
TRUSTED_EMAIL_DOMAINS = frozenset(
    [
        # Major email providers
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.fr",
        "ymail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "protonmail.com",
        "proton.me",
        "pm.me",
        "aol.com",
        "zoho.com",
        "fastmail.com",
        "tutanota.com",
        "tuta.io",
        # Russian email providers
        "mail.ru",
        "inbox.ru",
        "list.ru",
        "bk.ru",
        "vk.com",
        "yandex.ru",
        "yandex.com",
        "ya.ru",
        "rambler.ru",
        # Regional providers
        "gmx.com",
        "gmx.de",
        "gmx.net",
        "web.de",
        "qq.com",
        "163.com",
        "126.com",
    ]
)

# === B2C (consumer) email provider detection ===
# Free/consumer email providers — registrations from these are individuals,
# not businesses. Superset of TRUSTED_EMAIL_DOMAINS.
_EXTRA_B2C_DOMAINS = frozenset(
    [
        # Microsoft regional
        "hotmail.co.uk",
        "hotmail.fr",
        "hotmail.de",
        "hotmail.it",
        "hotmail.es",
        "live.co.uk",
        "live.fr",
        # Yahoo regional
        "yahoo.de",
        "yahoo.co.jp",
        "yahoo.co.in",
        "yahoo.com.br",
        "rocketmail.com",
        # Legacy
        "aim.com",
        # Additional regional consumer providers
        "naver.com",
        "daum.net",
        "hanmail.net",
        "sina.com",
        "sohu.com",
        "yeah.net",
        "foxmail.com",
        "t-online.de",
        "freenet.de",
        "laposte.net",
        "orange.fr",
        "free.fr",
        "sfr.fr",
        "virgilio.it",
        "libero.it",
        "alice.it",
        "terra.com.br",
        "uol.com.br",
        "bol.com.br",
        "rediffmail.com",
        "cox.net",
        "comcast.net",
        "verizon.net",
        "att.net",
        "sbcglobal.net",
        "bellsouth.net",
        "charter.net",
        "earthlink.net",
    ]
)
B2C_EMAIL_DOMAINS = TRUSTED_EMAIL_DOMAINS | _EXTRA_B2C_DOMAINS

# === LAYER 4: Known disposable MX infrastructure ===
# Domains whose MX records point to these hosts are disposable, even if
# the domain itself isn't in any blocklist.
DISPOSABLE_MX_HOSTS = frozenset(
    [
        "mail.tm",
        "anonymmail.net",
        "tempamail.com",
        "wabblywabble.com",
        "wallywatts.com",
        "stxtc.com",
        "rakibbd.com",
        "yopmail.com",
        "guerrillamail.com",
        "grr.la",
        "mailinator.com",
        "temp-mail.org",
        # Apr 2026: shared MX infrastructure serving multiple throwaway domains
        "sparkblink.org",
        "centerzeta.com",
        # Apr 2026: solutioncipher.com serves spaceeclipse.com, linkzulu.com
        "solutioncipher.com",
        # Apr 2026: temporary-mail.net serves justdefinition.com (via mail.temporary-mail.net)
        "temporary-mail.net",
    ]
)

# === LAYER 4b: Suspicious domain name keywords ===
# Domains whose name contains these keywords are almost certainly disposable,
# even if they aren't in any blocklist yet (e.g. temp-mail-go.info).
_SUSPICIOUS_DOMAIN_KEYWORDS = (
    "temp-mail",
    "tempmail",
    "temp-email",
    "tempemail",
    "throwaway",
    "disposable",
    "trashmail",
    "trash-mail",
    "fakeemail",
    "fake-email",
    "fakemail",
    "fake-mail",
    "spammail",
    "spam-mail",
    "guerrillamail",
    "guerrilla-mail",
    "yopmail",
    "mailinator",
    "10minutemail",
    "10-minute-mail",
    "burnermail",
    "burner-mail",
)

# === LAYER 4c: Gibberish / random username detection ===
# Usernames that lack vowel structure are likely auto-generated (e.g. 3ob7nnj1da).
_VOWELS = set("aeiou")


def _is_gibberish_username(local: str) -> bool:
    """Detect auto-generated / random-looking usernames.

    Heuristics:
    - Must be >= 6 chars (short names can look random but aren't)
    - Very low vowel ratio (< 20%) in alpha characters + high digit ratio
    - Interleaved digits and letters (3ob7nnj1da vs mark2001)
    - Pure consonant strings with no vowels at all (>= 7 alpha chars)
    """
    if len(local) < 6:
        return False

    alpha_chars = [c for c in local if c.isalpha()]
    digit_chars = [c for c in local if c.isdigit()]
    total_alnum = len(alpha_chars) + len(digit_chars)

    if total_alnum < 5:
        return False

    # Check vowel ratio in alpha characters
    if alpha_chars:
        vowel_count = sum(1 for c in alpha_chars if c.lower() in _VOWELS)
        vowel_ratio = vowel_count / len(alpha_chars)
    else:
        vowel_ratio = 0.0

    # Check digit mixing ratio
    digit_ratio = len(digit_chars) / total_alnum if total_alnum else 0.0

    # Check if digits are interleaved with letters (strong gibberish signal)
    # e.g. "3ob7nnj1da" has digits scattered throughout
    # vs "mark2001" has digits only at the end
    has_interleaved_digits = False
    if len(digit_chars) >= 2 and len(alpha_chars) >= 2:
        # Find positions of digits in the alnum-only string
        alnum_only = [c for c in local if c.isalnum()]
        digit_positions = [i for i, c in enumerate(alnum_only) if c.isdigit()]
        alpha_positions = [i for i, c in enumerate(alnum_only) if c.isalpha()]
        if digit_positions and alpha_positions:
            # Digits are interleaved if min digit position < max alpha position
            # AND max digit position > min alpha position (digits aren't just prefix or suffix)
            first_digit = min(digit_positions)
            last_digit = max(digit_positions)
            first_alpha = min(alpha_positions)
            last_alpha = max(alpha_positions)
            has_interleaved_digits = (first_digit < last_alpha) and (
                last_digit > first_alpha)

    # Strong signal: low vowels + interleaved digits = auto-generated
    # e.g. "3ob7nnj1da" has 2 vowels/7 alpha = 28.6%, digits scattered
    if vowel_ratio < 0.30 and digit_ratio >= 0.25 and has_interleaved_digits:
        return True

    # Original strict check: very few vowels + high digit ratio
    if vowel_ratio < 0.20 and digit_ratio >= 0.30:
        return True

    # Also catch pure consonant strings with no vowels at all
    # e.g. "xkjfqwrt" — but allow known patterns like abbreviations
    if len(alpha_chars) >= 7 and vowel_ratio == 0.0:
        return True

    return False


# === LAYER 5: DNS MX record cache ===
_mx_cache: dict[str, bool] = {}
_MX_CACHE_MAX_SIZE = 10_000
_DNS_ERROR = "__DNS_ERROR__"
_mx_host_cache: dict[str, str | None] = {}


# ---------------------------------------------------------------------------
# Role account prefixes (info@, admin@, etc.)
# ---------------------------------------------------------------------------
ROLE_ACCOUNT_PREFIXES = frozenset(
    [
        # RFC 2142 required
        "abuse",
        "admin",
        "administrator",
        "hostmaster",
        "info",
        "mailer-daemon",
        "noc",
        "postmaster",
        "root",
        "security",
        "usenet",
        "webmaster",
        # Common departments / functions
        "accounting",
        "accounts",
        "admissions",
        "advertising",
        "ap",
        "ar",
        "billing",
        "bookings",
        "business",
        "careers",
        "checkout",
        "claims",
        "client",
        "clients",
        "comms",
        "communications",
        "community",
        "company",
        "compliance",
        "contact",
        "contactus",
        "contracts",
        "controller",
        "copywriting",
        "creative",
        "cs",
        "customercare",
        "customers",
        "customerservice",
        "delivery",
        "design",
        "dev",
        "developer",
        "developers",
        "devnull",
        "digital",
        "director",
        "dispatch",
        "dns",
        "donations",
        "editor",
        "education",
        "employment",
        "engineer",
        "engineering",
        "enquiries",
        "enquiry",
        "events",
        "facilities",
        "fax",
        "feedback",
        "finance",
        "frontdesk",
        "ftp",
        "fulfillment",
        "general",
        "group",
        "guest",
        "guests",
        "hello",
        "help",
        "helpdesk",
        "hiring",
        "hospitality",
        "hr",
        "incident",
        "inquiries",
        "inquiry",
        "insurance",
        "intern",
        "interns",
        "invest",
        "investor",
        "investors",
        "invoices",
        "invoicing",
        "it",
        "jobs",
        "legal",
        "liaison",
        "list",
        "listserv",
        "logistics",
        "mail",
        "mailbox",
        "mailing",
        "mailinglist",
        "management",
        "manager",
        "managing",
        "marketing",
        "media",
        "member",
        "members",
        "membership",
        "news",
        "newsletter",
        "no-reply",
        "nobody",
        "noreply",
        "not-reply",
        "notification",
        "notifications",
        "notify",
        "office",
        "online",
        "operations",
        "ops",
        "order",
        "orders",
        "outreach",
        "owner",
        "parking",
        "partner",
        "partners",
        "partnerships",
        "payments",
        "payroll",
        "pharmacy",
        "planning",
        "platform",
        "postbox",
        "pr",
        "press",
        "principal",
        "privacy",
        "procurement",
        "product",
        "production",
        "project",
        "projects",
        "promotions",
        "purchasing",
        "quality",
        "reception",
        "recruit",
        "recruiting",
        "recruitment",
        "refund",
        "refunds",
        "registrar",
        "registration",
        "relations",
        "rentals",
        "reply",
        "report",
        "request",
        "reservations",
        "returns",
        "rma",
        "safety",
        "sales",
        "schedule",
        "secretary",
        "server",
        "service",
        "shipping",
        "social",
        "spam",
        "staff",
        "store",
        "subscribe",
        "subscriptions",
        "suggestions",
        "support",
        "survey",
        "sysadmin",
        "team",
        "tech",
        "technical",
        "test",
        "tickets",
        "training",
        "travel",
        "trouble",
        "undisclosed-recipients",
        "unsubscribe",
        "update",
        "updates",
        "vendor",
        "vendors",
        "voicemail",
        "volunteer",
        "web",
        "webadmin",
        "welcome",
        "wiki",
        "www",
    ]
)


# ---------------------------------------------------------------------------
# Public API functions
# ---------------------------------------------------------------------------


def normalize_email(email: str) -> str:
    """Normalize email to detect aliases and duplicates.

    Handles provider-specific normalization:
    - Gmail/Googlemail: removes dots and +suffix
    - Outlook/Hotmail/Live: removes +suffix (dots are significant)
    - Yahoo: removes -suffix (Yahoo uses hyphens)
    - Other: removes +suffix

    Returns:
        Normalized lowercase email.
    """
    if not email or "@" not in email:
        return email.lower() if email else ""

    try:
        local, domain = email.lower().strip().split("@", 1)
    except ValueError:
        return email.lower().strip()

    if domain in ("gmail.com", "googlemail.com"):
        local = local.replace(".", "")
        if "+" in local:
            local = local.split("+")[0]
        domain = "gmail.com"
    elif domain in ("outlook.com", "hotmail.com", "live.com", "msn.com"):
        if "+" in local:
            local = local.split("+")[0]
    elif domain in ("yahoo.com", "yahoo.co.uk", "yahoo.fr", "ymail.com"):
        if "-" in local:
            local = local.split("-")[0]
    elif "+" in local:
        local = local.split("+")[0]

    return f"{local}@{domain}"


def get_email_domain(email: str) -> str:
    """Extract domain from an email address (lowercase)."""
    if not email or "@" not in email:
        return ""
    try:
        return email.lower().split("@")[1].strip()
    except (ValueError, IndexError):
        return ""


def is_disposable_email(email: str) -> bool:
    """Check if email is from a known disposable provider."""
    domain = get_email_domain(email)
    if not domain:
        return False
    is_disposable = domain in DISPOSABLE_EMAIL_DOMAINS
    if is_disposable:
        logger.warning("Disposable email detected (domain: %s)", domain)
    return is_disposable


def is_role_account(email: str) -> bool:
    """Check if email is a role/functional account (info@, admin@, etc.)."""
    if not email or "@" not in email:
        return False
    local = email.lower().split("@")[0]
    return local in ROLE_ACCOUNT_PREFIXES


def is_b2c_email(email: str) -> bool:
    """Check if email is from a free/consumer (B2C) provider.

    B2C emails (gmail, yahoo, hotmail, etc.) indicate individual users
    rather than business registrations. Useful for segmenting B2B vs B2C
    signups without blocking either.
    """
    domain = get_email_domain(email)
    if not domain:
        return False
    return domain in B2C_EMAIL_DOMAINS


def _resolve_dns(domain: str, rdtype: str, lifetime: float = 3.0):
    """Synchronous DNS resolution (to be called via asyncio.to_thread)."""
    return dns.resolver.resolve(domain, rdtype, lifetime=lifetime)


async def _resolve_mx_host(domain: str) -> str | None:
    """Resolve the primary MX host for a domain (cached).

    Returns the MX hostname, None if no records, or _DNS_ERROR on transient failure.
    """
    if domain in _mx_host_cache:
        return _mx_host_cache[domain]

    mx_host = None
    try:
        mx_records = await asyncio.to_thread(_resolve_dns, domain, "MX")
        if mx_records:
            best = min(mx_records, key=lambda r: r.preference)
            mx_host = str(best.exchange).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        mx_host = None
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        mx_host = _DNS_ERROR
        logger.debug("DNS lookup timeout/error for %s, assuming valid", domain)
    except Exception as e:
        mx_host = _DNS_ERROR
        logger.debug("Unexpected DNS error for %s: %s", domain, e)

    if len(_mx_host_cache) < _MX_CACHE_MAX_SIZE:
        _mx_host_cache[domain] = mx_host

    return mx_host


async def check_domain_has_mx(domain: str) -> bool:
    """Check if a domain has valid MX records (cached)."""
    if domain in _mx_cache:
        return _mx_cache[domain]

    if domain in TRUSTED_EMAIL_DOMAINS:
        _mx_cache[domain] = True
        return True

    result = await _resolve_mx_host(domain)
    if result is None:
        has_mx = False
    elif result == _DNS_ERROR:
        has_mx = True  # Transient failure — benefit of the doubt
    else:
        has_mx = True

    if len(_mx_cache) < _MX_CACHE_MAX_SIZE:
        _mx_cache[domain] = has_mx

    if not has_mx:
        logger.warning("Domain has no MX records: %s", domain)

    return has_mx


async def check_mx_points_to_disposable(domain: str) -> bool:
    """Check if a domain's MX points to known disposable mail infrastructure.

    Catches fresh throwaway domains that share backend MX hosts
    (e.g. mail.tm, anonymmail.net) even when the domain itself is new.
    """
    if domain in TRUSTED_EMAIL_DOMAINS:
        return False

    mx_host = await _resolve_mx_host(domain)
    if not mx_host or mx_host == _DNS_ERROR:
        return False

    # Direct match
    if mx_host in DISPOSABLE_MX_HOSTS:
        logger.warning(
            "Domain %s MX points to known disposable infra: %s", domain, mx_host)
        return True

    # Subdomain match (mx1.mail.tm → mail.tm)
    for known_host in DISPOSABLE_MX_HOSTS:
        if mx_host.endswith("." + known_host):
            logger.warning(
                "Domain %s MX subdomain of disposable infra: %s → %s", domain, mx_host, known_host)
            return True

    # Self-referencing MX heuristic
    if mx_host in (f"mail.{domain}", f"c.{domain}", f"mx.{domain}"):
        try:
            a_records = await asyncio.to_thread(_resolve_dns, mx_host, "A")
            if not a_records:
                logger.warning(
                    "Domain %s has self-referencing MX %s with no A record", domain, mx_host)
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.warning(
                "Domain %s has self-referencing MX %s that doesn't resolve", domain, mx_host)
            return True
        except Exception:
            logger.debug("DNS error checking A record for %s", mx_host)

        # Self-hosted MX but no website — strong throwaway signal
        try:
            await asyncio.to_thread(_resolve_dns, domain, "A")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.warning(
                "Domain %s has self-referencing MX %s but no website", domain, mx_host)
            return True
        except Exception:
            pass

    # Cloudflare Email Routing abuse: route[1-3].mx.cloudflare.net is a free
    # service legitimate businesses use — BUT legitimate users always have a website
    # (A record). Pure email-only domains with CF routing and no A record are a
    # strong throwaway signal (greance.us, demdon.online, mooncapt.shop pattern).
    if mx_host.endswith(".mx.cloudflare.net"):
        try:
            await asyncio.to_thread(_resolve_dns, domain, "A")
            # Has A record → could be a real site with Cloudflare email routing, allow
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.warning(
                "Domain %s uses Cloudflare Email Routing but has no website (no A record)", domain)
            return True
        except Exception:
            pass  # Transient DNS error — give benefit of the doubt

    return False


async def is_suspicious_email(email: str) -> tuple[bool, list[str]]:
    """Multi-layer email suspicion check.

    Layers:
    1. Disposable domain blocklist
    2. Heuristic patterns (numeric domains, short domains, keyword domains)
    3. DNS MX record validation
    4. MX infrastructure check

    Returns:
        (is_suspicious, reasons)
    """
    reasons: list[str] = []

    if is_disposable_email(email):
        reasons.append("disposable_domain")

    domain = get_email_domain(email)
    if domain:
        if domain in TRUSTED_EMAIL_DOMAINS:
            return len(reasons) > 0, reasons

        domain_name = domain.split(".")[0]
        digit_count = sum(c.isdigit() for c in domain_name)
        if digit_count >= 4:
            reasons.append("numeric_domain")

        if len(domain_name) <= 2:
            reasons.append("very_short_domain")

        # Keyword-based detection: domain name contains disposable keywords
        # e.g. temp-mail-go.info, my-tempmail.xyz, throwaway-email.net
        domain_lower = domain.lower()
        for keyword in _SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in domain_lower:
                reasons.append("suspicious_domain_keyword")
                break

        if not reasons:
            if not await check_domain_has_mx(domain):
                reasons.append("no_mx_records")
            elif await check_mx_points_to_disposable(domain):
                reasons.append("disposable_mx_infrastructure")

    return len(reasons) > 0, reasons


async def check_registration_suspicion(email: str) -> tuple[bool, list[str]]:
    """Full registration suspicion check with all layers.

    Delegates to is_suspicious_email() and adds registration-specific
    checks (format validation, alias abuse, role accounts).

    Does NOT block registration — returns info for silent degradation:
    - Allow registration (no error shown to user)
    - Deny welcome bonus / referral credits
    - Flag user as suspicious internally

    Returns:
        (is_suspicious, reasons)
    """
    if not email or "@" not in email:
        return True, ["invalid_format"]

    # Core suspicion checks (disposable, heuristic, DNS)
    is_suspicious, reasons = await is_suspicious_email(email)

    # Registration-specific extras
    local = email.split("@")[0]
    if local.count("+") > 1:
        reasons.append("multiple_aliases")

    if is_role_account(email):
        reasons.append("role_account")

    # TODO: Replace with ML-based gibberish detector (HuggingFace model)
    # Heuristic _is_gibberish_username() disabled — too many edge cases.
    # clean_local = local.split("+")[0]
    # if _is_gibberish_username(clean_local):
    #     reasons.append("gibberish_username")

    is_suspicious = len(reasons) > 0
    if is_suspicious:
        domain = get_email_domain(email)
        logger.info(
            "Suspicious email (silent degradation): ***@%s — reasons: %s", domain, reasons)

    return is_suspicious, reasons


def validate_email_format(email: str) -> tuple[bool, str | None]:
    """Validate email format only (not suspiciousness).

    Returns:
        (is_valid, error_message)
    """
    if not email or "@" not in email:
        return False, "Invalid email format"

    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return False, "Invalid email format"

    return True, None


def clear_caches() -> None:
    """Clear DNS MX caches (useful for testing)."""
    _mx_cache.clear()
    _mx_host_cache.clear()
