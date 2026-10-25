"""Email validation engine for registration abuse detection.

Provides multi-layer email validation:
- Layer 1: Community-maintained disposable email blocklist (9,900+ domains)
- Layer 2: Custom blocklist for manually confirmed disposable domains (170+)
- Layer 3: Trusted domain whitelist (skip expensive DNS checks)
- Layer 4: MX infrastructure detection (catch fresh throwaway domains)
- Layer 5: DNS MX record validation with caching

Philosophy: Silent degradation — don't block suspicious registrations,
deny bonuses silently so attackers can't learn detection signals.
"""

import asyncio
import logging
import os
import re
from collections.abc import Iterable, Mapping
from enum import Enum
from pathlib import Path
from types import MappingProxyType

import dns.resolver

logger = logging.getLogger(__name__)

# === LAYER 1: Community-maintained disposable email blocklist (9,900+ domains) ===
# Source: https://github.com/disposable-email-domains/disposable-email-domains
BLOCKLIST_PATH = Path(__file__).resolve().parent.parent / \
    "data" / "disposable_email_blocklist.conf"
_BLOCKLIST_PATH = BLOCKLIST_PATH  # backward-compatible alias


def parse_blocklist(text: str) -> frozenset[str]:
    """Parse a blocklist file body: one domain per line, '#' starts a comment."""
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )


try:
    COMMUNITY_DISPOSABLE_DOMAINS: frozenset[str] = parse_blocklist(BLOCKLIST_PATH.read_text())
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
        # Jun 2026: CIS-popular disposable / API-driven temp-mail services
        # commonly used for RU bonus farming, missing from the community list
        "1secmail.com",
        "1secmail.org",
        "1secmail.net",
        "tempmail.plus",
        "etempmail.com",
        "mailpoof.com",
        "mail-temp.com",
        "vremennaya-pochta.ru",
        "temp-mails.com",
        "tempmailbox.net",
        # Aug 2026: found in a factory_ru sweep of 10,695 users. Every domain
        # below was DNS-verified against a throwaway MX farm or a blackhole
        # host, and none has ever had a paying user.
        #   self-hosted single-domain farms (keep an A record, so the
        #   "self-referencing MX with no website" rule misses them)
        "imxwe.com",
        "ygwpr.com",
        "dbwot.com",
        "mailpotus.com",
        "mailbinmart.com",
        "emailinbo.live",
        "fl-v.com",
        #   shared farm MX: kuromee / cloakfast / 24.email / hope-mail / netxmail
        "starlight.store",
        "labsharmony.com",
        "duskilon.com",
        "fromru.com",
        "eclipsezen.com",
        #   (indox.ru and maul.ru also point at void.blackhole.mx, but they are
        #   typos of inbox.ru / mail.ru, so they belong to the typo map.)
        #   NOTE: the typo-squatters found in the same sweep (gnail.com,
        #   gmai.com, gmaii.com, gmil.com, icloug.com, yabdex.ru, xmail.ru,
        #   501gmail.com) live in EMAIL_DOMAIN_TYPO_MAP instead, not here. They
        #   are a different failure — the user meant a real provider — and
        #   listing them twice would score one address under two reasons.
        #   misc throwaway providers
        "trashlify.com",
        "tmail.ae",
        "smallmailo.my",
        # Oct 2026: removed from the community list upstream, but the Factory
        # still flags them (its vendored copy of the list predates the removal).
        # Pinned here so a list refresh cannot silently un-flag them; recorded
        # as known divergences from upstream.
        "atomicmail.io",
        "ip6.li",
        "iwi.net",
        "mailhub.pro",
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
        "internet.ru",
        "mail.ua",
        "vk.com",
        "yandex.ru",
        "yandex.com",
        "ya.ru",
        "yandex.by",
        "yandex.kz",
        "yandex.ua",
        "rambler.ru",
        "rambler.ua",
        "lenta.ru",
        "autorambler.ru",
        "myrambler.ru",
        "ro.ru",
        "nm.ru",
        "pochta.ru",
        "qip.ru",
        # CIS regional consumer providers
        "ukr.net",
        "i.ua",
        "meta.ua",
        "tut.by",
        "mail.kz",
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

# === LAYER 3a: Deployment-specific trusted domains ===
# Synthetic domains that belong to ONE integrating app do not belong in the
# shared list above. The Factory, for example, mints telegram_<id>@factory.bot
# accounts and rewrites a soft-deleted address to @deleted.local; neither
# resolves, so without trust they trip no_mx_records on every check. Such a
# deployment sets GUARDPOST_TRUSTED_EXTRA_DOMAINS=factory.bot,deleted.local (or
# passes trusted_extra_domains= to the engine). Per-tenant config replaces this.
TRUSTED_EXTRA_DOMAINS_ENV = "GUARDPOST_TRUSTED_EXTRA_DOMAINS"


def parse_domain_list(value: str | Iterable[str] | None) -> frozenset[str]:
    """Normalize a comma-separated string (or iterable) of domains."""
    if not value:
        return frozenset()
    items = value.split(",") if isinstance(value, str) else value
    return frozenset(d.strip().lower().lstrip("@") for d in items if d and d.strip())


def trusted_extra_domains_from_env() -> frozenset[str]:
    """Read the deployment's extra trusted domains from the environment."""
    return parse_domain_list(os.environ.get(TRUSTED_EXTRA_DOMAINS_ENV))

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

# === Alias-group domains (same mailbox across multiple domains) ===
# Registering the same local-part under any sibling domain reaches the same
# inbox, so these must be canonicalized in normalize_email() to stop
# multi-accounting / bonus farming that bypasses the banned-email hash.
MAILRU_GROUP_DOMAINS = frozenset(
    ["mail.ru", "bk.ru", "list.ru", "inbox.ru"]
)
YANDEX_GROUP_DOMAINS = frozenset(
    ["yandex.ru", "yandex.com", "ya.ru", "yandex.by", "yandex.kz", "yandex.ua"]
)

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
        # Aug 2026: shared MX farms found in the factory_ru sweep
        "kuromee.com",        # starlight.store
        "cloakfast.org",      # labsharmony.com
        "24.email",           # duskilon.com
        "hope-mail.com",      # fromru.com
        "netxmail.com",       # eclipsezen.com
        "temp-mailo.org",     # greance.us
        "fex.plus",           # mailto.plus
        #   typo-squatter catch-all infrastructure
        "h-email.net",        # gmai.com
        "oweb.cn",            # gnail.com
        "yaxmail.net",        # gmil.com
        # Aug 2026: blackhole MX — the host accepts and discards every message,
        # so the address is unreachable by design (indox.ru, maul.ru).
        "blackhole.mx",
    ]
)

# === LAYER 4a: MX hosts that mean "this domain cannot receive mail" ===
# A domain publishing one of these is not merely suspicious, it is undeliverable.
# "." is the RFC 7505 null MX; "localhost" is a misconfiguration squatters leave
# behind (gmaii.com). Both currently satisfy a naive bool(answers) MX check.
_NULL_MX_HOSTS = frozenset(["", ".", "localhost", "localhost.localdomain"])

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
    # Aug 2026: bare "trash" catches trashlify.com, which the compound
    # "trashmail"/"trash-mail" entries above miss.
    "trash",
    "tempmailo",
    "mailtemp",
)
SUSPICIOUS_DOMAIN_KEYWORDS = _SUSPICIOUS_DOMAIN_KEYWORDS

# === LAYER 4d: Lookalike / typo domains ===
# Domains that are one keystroke from a major provider. Two distinct kinds live
# here and both matter:
#   - dead typos (gmail.con, mail.ry) — the user never receives anything, so the
#     right product action is to suggest the correction, not to deny a bonus;
#   - live squatters (gnail.com, gmai.com, indox.ru) — they run a catch-all MX,
#     so the DNS layers pass them cleanly and only this map stops them.
# Mirrored from the Factory deployment's EMAIL_DOMAIN_TYPO_MAP, plus the
# Aug 2026 factory_ru additions.
EMAIL_DOMAIN_TYPO_MAP = {
    # gmail
    "gmai.com": "gmail.com",
    "gmail.cm": "gmail.com",
    "gmail.co": "gmail.com",
    "gmail.comm": "gmail.com",
    "gmail.con": "gmail.com",
    "gmail.ocm": "gmail.com",
    "gmail.om": "gmail.com",
    "gmailc.om": "gmail.com",
    "gmaill.com": "gmail.com",
    "gmal.com": "gmail.com",
    "gmil.com": "gmail.com",
    "gnail.com": "gmail.com",
    "gemail.com": "gmail.com",
    # hotmail
    "hotmai.com": "hotmail.com",
    "hotmall.com": "hotmail.com",
    "hotmial.com": "hotmail.com",
    "hotmil.com": "hotmail.com",
    # icloud
    "iclod.com": "icloud.com",
    "icloud.co": "icloud.com",
    "icloud.con": "icloud.com",
    "iclould.com": "icloud.com",
    "icoud.com": "icloud.com",
    # mail.ru
    "mail.tu": "mail.ru",
    "mail.u": "mail.ru",
    "maill.ru": "mail.ru",
    "meil.ru": "mail.ru",
    "mial.ru": "mail.ru",
    # outlook
    "outlok.com": "outlook.com",
    "outloock.com": "outlook.com",
    # yandex
    "yadnex.ru": "yandex.ru",
    "yandeks.ru": "yandex.ru",
    "yandex.tu": "yandex.ru",
    "yandex.u": "yandex.ru",
    "yandx.ru": "yandex.ru",
    "yndex.ru": "yandex.ru",
    # Aug 2026: observed in factory_ru
    "gmaii.com": "gmail.com",
    "gomil.com": "gmail.com",
    "icloug.com": "icloud.com",
    "indox.ru": "inbox.ru",
    "maul.ru": "mail.ru",
    "yabdex.ru": "yandex.ru",
    "xmail.ru": "mail.ru",
    "mail.ry": "mail.ru",
    "bk.ry": "bk.ru",
    "yandex.ry": "yandex.ru",
}

# A ".ru" or ".com" typed with the wrong final key. Anchored to a known provider
# name on purpose: ".om" (Oman) and ".cm" (Cameroon) are real country TLDs, so a
# bare suffix test would rewrite legitimate domains such as bank.om.
_TYPO_TLD_RE = re.compile(
    r"^(gmail|googlemail|yandex|mail|bk|list|inbox|ya|outlook|hotmail|icloud|yahoo)"
    r"\.(ry|rue|ruu|cm|con|comm|ocm|om)$"
)

# Machine-generated lookalikes: 501gmail.com, 536mail.ru. A digit run glued to a
# provider name is never a real domain a person would own.
_NUMERIC_PROVIDER_RE = re.compile(r"^\d{1,4}(gmail|gmai|mail|yandex|inbox)\.[a-z]{2,6}$")

# === LAYER 4e: Email relay / alias providers ===
# Legitimate privacy services, NOT disposable — but one person can mint an
# unlimited number of addresses through them, so they are a weak signal only.
RELAY_EMAIL_DOMAINS = frozenset(
    [
        "duck.com",
        "relay.firefox.com",
        "mozmail.com",
        "simplelogin.io",
        "simplelogin.com",
        "aleeas.com",
        "slmail.me",
        "anonaddy.me",
        "anonaddy.com",
        "addy.io",
        "33mail.com",
        "spamgourmet.com",
    ]
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


# === LAYER 4f: Dot-noise Gmail addresses ===
# Gmail ignores dots, so a.b.c@gmail.com and abc@gmail.com are one mailbox.
# That makes normalize_email() collapse aliases of the SAME name — but it does
# nothing against the opposite trick: take a plausible full name, sprinkle
# random dots through it, and every variant becomes a DIFFERENT canonical
# address. A human types zero or one dot; a generator types many.
#
# Measured on 4,374 Gmail addresses in factory_ru (Aug 2026):
#   0 dots  3,744 users  181 paid
#   1 dot     453 users   18 paid
#   2 dots     99 users    3 paid
#   3+ dots    78 users    0 paid   <-- no legitimate user has ever been here
_DOT_NOISE_DOMAINS = frozenset(["gmail.com", "googlemail.com"])
_DOT_NOISE_MIN_DOTS = 3
_DOT_NOISE_MIN_RATIO = 0.20


def has_dot_noise(email: str) -> bool:
    """Detect machine-inserted dot noise in a Gmail-family local part.

    Fires on 4+ dots outright, or on 3 dots when they make up at least 20% of
    the local part — the ratio guard stops a genuinely long name from tripping
    on three ordinary separators.
    """
    domain = get_email_domain(email)
    if domain not in _DOT_NOISE_DOMAINS:
        return False

    local = email.lower().split("@")[0].split("+")[0]
    if not local:
        return False

    dots = local.count(".")
    if dots >= _DOT_NOISE_MIN_DOTS + 1:
        return True
    return dots >= _DOT_NOISE_MIN_DOTS and dots / len(local) >= _DOT_NOISE_MIN_RATIO


# === LAYER 4g: Lookalike / typo domain detection ===
# Which rule produced a typo match. The Factory only has the exact map, so a
# caller comparing verdicts can tell a shared match ("map") from a
# Guardpost-only heuristic ("tld", "numeric").
TYPO_SOURCE_MAP = "map"
TYPO_SOURCE_TLD = "tld"
TYPO_SOURCE_NUMERIC = "numeric"


def classify_domain_typo(email_or_domain: str) -> tuple[str, str] | None:
    """Return (suggested_domain, source) for a lookalike domain, or None.

    ``source`` is one of TYPO_SOURCE_MAP (exact EMAIL_DOMAIN_TYPO_MAP entry),
    TYPO_SOURCE_TLD (mistyped TLD: .ry for .ru, .con for .com) or
    TYPO_SOURCE_NUMERIC (digit-prefixed provider name: 501gmail.com).
    """
    domain = get_email_domain(email_or_domain) if "@" in email_or_domain \
        else email_or_domain.lower().strip()
    if not domain:
        return None

    corrected = EMAIL_DOMAIN_TYPO_MAP.get(domain)
    if corrected:
        return corrected, TYPO_SOURCE_MAP

    tld_typo = _TYPO_TLD_RE.match(domain)
    if tld_typo:
        # The ".ry" family is a mistyped ".ru"; the rest are mistyped ".com".
        suffix = ".ru" if tld_typo.group(2).startswith("r") else ".com"
        return f"{tld_typo.group(1)}{suffix}", TYPO_SOURCE_TLD

    if _NUMERIC_PROVIDER_RE.match(domain):
        return re.sub(r"^\d+", "", domain), TYPO_SOURCE_NUMERIC

    return None


def suggest_domain_correction(email_or_domain: str) -> str | None:
    """Return the domain the user probably meant, or None.

    Recognises three shapes: an exact entry in EMAIL_DOMAIN_TYPO_MAP, a mistyped
    TLD (.ry for .ru, .con for .com), and a digit-prefixed provider name
    (501gmail.com). classify_domain_typo() also says which one matched.
    """
    match = classify_domain_typo(email_or_domain)
    return match[0] if match else None


def is_typo_domain(email: str) -> bool:
    """Check whether the domain is a lookalike of a real provider."""
    return suggest_domain_correction(email) is not None


# === LAYER 4h: Homograph domains ===
# A domain that mixes scripts, or renders as a trusted domain once Cyrillic
# lookalikes are folded to Latin, is an impersonation attempt — factory_ru
# contains "gmail.сом" with a Cyrillic с/о/м.
_CONFUSABLE_FOLD = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "м": "m",
    "к": "k", "в": "b", "т": "t", "н": "h", "г": "r",
})


def is_homograph_domain(email: str) -> bool:
    """Detect a non-ASCII domain that impersonates a trusted one."""
    domain = get_email_domain(email)
    if not domain or domain.isascii():
        return False

    folded = domain.translate(_CONFUSABLE_FOLD)
    if not folded.isascii():
        return False
    return folded in TRUSTED_EMAIL_DOMAINS or folded in EMAIL_DOMAIN_TYPO_MAP


# === LAYER 4i: Gibberish domain labels ===
# Deliberately a WEAK signal. On real data it also matches legitimate Russian
# academic and corporate domains (rudn.ru, kpfu.ru, ptkivs.ru, tomsk.cc), so it
# must never condemn an address on its own — it only raises the risk score.
_GIBBERISH_DOMAIN_MIN_LEN = 4
_GIBBERISH_DOMAIN_MAX_LEN = 6
_GIBBERISH_DOMAIN_MAX_VOWEL_RATIO = 0.25


def has_gibberish_domain(email: str) -> bool:
    """Detect a short, vowel-poor domain label such as ygwpr.com or dbwot.com."""
    domain = get_email_domain(email)
    if not domain or domain in TRUSTED_EMAIL_DOMAINS or domain in RELAY_EMAIL_DOMAINS:
        return False

    label = domain.split(".")[0]
    if not label.isalpha() or not label.isascii():
        return False
    if not _GIBBERISH_DOMAIN_MIN_LEN <= len(label) <= _GIBBERISH_DOMAIN_MAX_LEN:
        return False

    vowel_ratio = sum(c in _VOWELS for c in label) / len(label)
    return vowel_ratio <= _GIBBERISH_DOMAIN_MAX_VOWEL_RATIO


def is_relay_email(email: str) -> bool:
    """Check whether the address belongs to a privacy relay / alias provider."""
    return get_email_domain(email) in RELAY_EMAIL_DOMAINS


# === Reason tiers ===
# Every reason belongs to one of three tiers; a check's decision is the highest
# tier present:
#   HARD -> block   (refuse the signup outright)
#   SOFT -> degrade (allow it, deny bonuses: the Factory's "suspicious")
#   WEAK -> score   (raise risk_score only, never change the verdict)
#
# The defaults reproduce the Factory's semantics exactly:
#   - HARD is empty. Guardpost has no block-class reasons yet; the Factory's
#     blocking gates arrive with per-tenant tiers. So `is_suspicious` (hard or
#     soft) still covers everything it covered before tiers existed.
#   - WEAK holds the signals the Factory does not flag. gibberish_domain matches
#     ygwpr.com and dbwot.com, but it also matches rudn.ru and kpfu.ru, and no
#     rule that can zero a real student's welcome credits belongs above WEAK.
#   - Everything else is SOFT, including subnet_burst (degrade-only, never a
#     block) and any reason not listed here — forgetting to classify a new
#     signal fails safe (it degrades) rather than silently vanishing.


class ReasonTier(str, Enum):
    HARD = "hard"
    SOFT = "soft"
    WEAK = "weak"


HARD_REASONS: frozenset[str] = frozenset()

WEAK_REASONS = frozenset(
    [
        "gibberish_domain",
        "relay_domain",
        # dev@, design@, hello@ ... — the Factory does not flag these.
        "role_account_extended",
        # Guardpost-only: the Factory's MX test accepts a null MX ("." is an
        # answer) and has no homograph check.
        "homograph_domain",
        "null_mx",
    ]
)

DEFAULT_REASON_TIER = ReasonTier.SOFT

DEFAULT_REASON_TIERS: Mapping[str, ReasonTier] = MappingProxyType({
    **{r: ReasonTier.HARD for r in HARD_REASONS},
    **{r: ReasonTier.WEAK for r in WEAK_REASONS},
})

ReasonTiers = Mapping[str, "ReasonTier | str"]


def split_reason(reason: str) -> str:
    """Strip the detail suffix from a reason ("subnet_burst:1.2.3.0/24")."""
    return reason.split(":", 1)[0]


def reason_tier(reason: str, tiers: ReasonTiers | None = None) -> ReasonTier:
    """Tier of one reason. ``tiers`` overrides the defaults per reason kind."""
    kind = split_reason(reason)
    if tiers and kind in tiers:
        return ReasonTier(tiers[kind])
    return DEFAULT_REASON_TIERS.get(kind, DEFAULT_REASON_TIER)


def partition_reasons(
    reasons: list[str], tiers: ReasonTiers | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Split reasons into (hard, soft, weak), preserving order within each tier."""
    out: dict[ReasonTier, list[str]] = {t: [] for t in ReasonTier}
    for r in reasons:
        out[reason_tier(r, tiers)].append(r)
    return out[ReasonTier.HARD], out[ReasonTier.SOFT], out[ReasonTier.WEAK]


def has_suspicious_reason(reasons: list[str], tiers: ReasonTiers | None = None) -> bool:
    """True if any reason is hard or soft, i.e. the address is suspicious."""
    return any(reason_tier(r, tiers) is not ReasonTier.WEAK for r in reasons)


def has_hard_reason(reasons: list[str]) -> bool:
    """Pre-tier name for has_suspicious_reason(): any reason that is not weak.

    Kept for callers written when there were only two tiers ("hard" then meant
    "condemns"). It is true for soft reasons too; for the block tier use
    ``partition_reasons(reasons)[0]``.
    """
    return has_suspicious_reason(reasons)


# === LAYER 5: DNS MX record cache ===
_mx_cache: dict[str, bool] = {}
_MX_CACHE_MAX_SIZE = 10_000
_DNS_ERROR = "__DNS_ERROR__"
_mx_host_cache: dict[str, str | None] = {}


# ---------------------------------------------------------------------------
# Role account prefixes (info@, admin@, etc.)
# ---------------------------------------------------------------------------
# The Factory's 43 prefixes. Reason "role_account" — the Factory flags these as
# suspicious, so they sit in the soft tier and keep the verdicts aligned.
# Pinned by tests/test_factory_superset.py against Factory v2's email-lists.json.
CORE_ROLE_ACCOUNT_PREFIXES = frozenset(
    [
        "abuse",
        "admin",
        "administrator",
        "billing",
        "contact",
        "cs",
        "customerservice",
        "help",
        "helpdesk",
        "hostmaster",
        "hr",
        "info",
        "legal",
        "mailer-daemon",
        "marketing",
        "no-reply",
        "noc",
        "noreply",
        "not-reply",
        "notifications",
        "notify",
        "office",
        "operations",
        "ops",
        "payments",
        "postmaster",
        "press",
        "privacy",
        "root",
        "sales",
        "security",
        "service",
        "shipping",
        "spam",
        "support",
        "sysadmin",
        "team",
        "tech",
        "tickets",
        "unsubscribe",
        "usenet",
        "webmaster",
        "welcome",
    ]
)

# Guardpost-only prefixes. Reason "role_account_extended" — a weak signal: the
# Factory never flags dev@, design@ or hello@, so they only raise the score.
EXTENDED_ROLE_ACCOUNT_PREFIXES = frozenset(
    [
        # Common departments / functions
        "accounting",
        "accounts",
        "admissions",
        "advertising",
        "ap",
        "ar",
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
        "contactus",
        "contracts",
        "controller",
        "copywriting",
        "creative",
        "customercare",
        "customers",
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
        "hiring",
        "hospitality",
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
        "media",
        "member",
        "members",
        "membership",
        "news",
        "newsletter",
        "nobody",
        "notification",
        "online",
        "order",
        "orders",
        "outreach",
        "owner",
        "parking",
        "partner",
        "partners",
        "partnerships",
        "payroll",
        "pharmacy",
        "planning",
        "platform",
        "postbox",
        "pr",
        "principal",
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
        "schedule",
        "secretary",
        "server",
        "social",
        "staff",
        "store",
        "subscribe",
        "subscriptions",
        "suggestions",
        "survey",
        "technical",
        "test",
        "training",
        "travel",
        "trouble",
        "undisclosed-recipients",
        "update",
        "updates",
        "vendor",
        "vendors",
        "voicemail",
        "volunteer",
        "web",
        "webadmin",
        "wiki",
        "www",
    ]
) - CORE_ROLE_ACCOUNT_PREFIXES

# Every role prefix, either tier (is_role_account() and older callers).
ROLE_ACCOUNT_PREFIXES = CORE_ROLE_ACCOUNT_PREFIXES | EXTENDED_ROLE_ACCOUNT_PREFIXES


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
    elif domain in MAILRU_GROUP_DOMAINS:
        # Mail.ru group shares one namespace: user@mail.ru == user@bk.ru
        # == user@list.ru == user@inbox.ru (same mailbox). Canonicalize so the
        # banned-email hash and alias-collision checks can't be bypassed by
        # registering the same name under each sibling domain.
        if "+" in local:
            local = local.split("+")[0]
        domain = "mail.ru"
    elif domain in YANDEX_GROUP_DOMAINS:
        # Yandex shares one account across ya.ru / yandex.ru / yandex.com and the
        # regional TLDs (by/kz/ua). Canonicalize to a single domain.
        if "+" in local:
            local = local.split("+")[0]
        domain = "yandex.ru"
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
    """Check if email is a role/functional account (info@, admin@, etc.).

    True for either tier; role_account_reason() tells them apart.
    """
    if not email or "@" not in email:
        return False
    local = email.lower().split("@")[0]
    return local in ROLE_ACCOUNT_PREFIXES


def role_account_reason(email: str) -> str | None:
    """Return "role_account" (Factory prefixes), "role_account_extended", or None."""
    if not email or "@" not in email:
        return None
    local = email.lower().split("@")[0]
    if local in CORE_ROLE_ACCOUNT_PREFIXES:
        return "role_account"
    if local in EXTENDED_ROLE_ACCOUNT_PREFIXES:
        return "role_account_extended"
    return None


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
        # A null MX (RFC 7505, exchange ".") is an answer, but it declares that
        # the domain accepts no mail at all. Without this guard a bare
        # bool(answers) test would call such a domain deliverable.
        has_mx = result not in _NULL_MX_HOSTS

    if len(_mx_cache) < _MX_CACHE_MAX_SIZE:
        _mx_cache[domain] = has_mx

    if not has_mx:
        logger.warning("Domain has no MX records: %s", domain)

    return has_mx


async def check_domain_has_null_mx(domain: str) -> bool:
    """Check whether a domain publishes an RFC 7505 null MX.

    Distinct from "no MX at all": the operator has explicitly declared the
    domain unable to receive mail. Shares _resolve_mx_host()'s cache, so this
    costs no extra DNS query.
    """
    result = await _resolve_mx_host(domain)
    if result is None or result == _DNS_ERROR:
        return False
    if result in _NULL_MX_HOSTS:
        logger.warning("Domain %s publishes a null MX — it accepts no mail", domain)
        return True
    return False


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


async def is_suspicious_email(
    email: str,
    *,
    trusted_extra_domains: Iterable[str] = (),
) -> tuple[bool, list[str]]:
    """Multi-layer email suspicion check.

    Layers:
    1. Disposable domain blocklist
    2. Lookalike / homograph domain detection
    3. Heuristic patterns (numeric domains, short domains, keyword domains)
    4. DNS MX record validation (including RFC 7505 null MX)
    5. MX infrastructure check

    Args:
        trusted_extra_domains: deployment-specific domains treated exactly like
            TRUSTED_EMAIL_DOMAINS (see TRUSTED_EXTRA_DOMAINS_ENV).

    Returns:
        (is_suspicious, reasons)
    """
    reasons: list[str] = []

    if is_disposable_email(email):
        reasons.append("disposable_domain")

    # A homograph domain renders as a trusted one, so it has to be tested before
    # the trusted short-circuit below — "gmail.сом" must never look trusted.
    if is_homograph_domain(email):
        reasons.append("homograph_domain")

    domain = get_email_domain(email)
    if domain:
        if domain in TRUSTED_EMAIL_DOMAINS or domain in trusted_extra_domains:
            return has_suspicious_reason(reasons), reasons

        # Lookalikes have live catch-all MX as often as not, so the DNS layers
        # below cannot be relied on to catch them.
        if is_typo_domain(email):
            reasons.append("typo_domain")

        if has_gibberish_domain(email):
            reasons.append("gibberish_domain")

        if is_relay_email(email):
            reasons.append("relay_domain")

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

        # Only a hard or soft reason short-circuits the DNS layers. Guarding
        # on `reasons` instead would let a weak signal such as gibberish_domain
        # silently suppress the MX checks that do the real work.
        if not has_suspicious_reason(reasons):
            if await check_domain_has_null_mx(domain):
                reasons.append("null_mx")
            elif not await check_domain_has_mx(domain):
                reasons.append("no_mx_records")
            elif await check_mx_points_to_disposable(domain):
                reasons.append("disposable_mx_infrastructure")

    return has_suspicious_reason(reasons), reasons


async def check_registration_suspicion(
    email: str,
    *,
    trusted_extra_domains: Iterable[str] = (),
) -> tuple[bool, list[str]]:
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
    is_suspicious, reasons = await is_suspicious_email(
        email, trusted_extra_domains=trusted_extra_domains)

    # Registration-specific extras
    local = email.split("@")[0]
    if local.count("+") > 1:
        reasons.append("multiple_aliases")

    # "role_account" for the Factory's prefixes, "role_account_extended" (weak)
    # for the Guardpost-only rest.
    role_reason = role_account_reason(email)
    if role_reason:
        reasons.append(role_reason)

    # Gmail-family only, so this has to run here rather than inside
    # is_suspicious_email(), which returns early for every trusted domain.
    if has_dot_noise(email):
        reasons.append("dot_noise_local")

    # TODO: Replace with ML-based gibberish detector (HuggingFace model)
    # Heuristic _is_gibberish_username() disabled — too many edge cases.
    # clean_local = local.split("+")[0]
    # if _is_gibberish_username(clean_local):
    #     reasons.append("gibberish_username")

    is_suspicious = has_suspicious_reason(reasons)
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
