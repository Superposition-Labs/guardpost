"""Guardpost's lists must be a superset of the Factory's (Guardpost ⊇ Factory).

The fixture is a verbatim snapshot of Factory v2's
``src/modules/auth/lists/email-lists.json`` (origin/main, Oct 2026). Refresh it
with::

    git -C ../Factory-v2 show origin/main:src/modules/auth/lists/email-lists.json \\
        > tests/fixtures/factory_v2_email_lists.json

A failure here means the Factory flags something Guardpost would miss, which
would show up as a ``gp_looser`` mismatch once v2 runs Guardpost in shadow.
"""

import json
from pathlib import Path

import pytest

from guardpost.email.validator import (
    CORE_ROLE_ACCOUNT_PREFIXES,
    CUSTOM_DISPOSABLE_DOMAINS,
    DISPOSABLE_MX_HOSTS,
    EMAIL_DOMAIN_TYPO_MAP,
    EXTENDED_ROLE_ACCOUNT_PREFIXES,
    ROLE_ACCOUNT_PREFIXES,
    SUSPICIOUS_DOMAIN_KEYWORDS,
    TRUSTED_EMAIL_DOMAINS,
    check_registration_suspicion,
    classify_domain_typo,
    is_disposable_email,
    role_account_reason,
    suggest_domain_correction,
)

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "factory_v2_email_lists.json"
FACTORY = json.loads(_FIXTURE.read_text())

# Synthetic domains only the Factory mints; trusted through deployment config
# (GUARDPOST_TRUSTED_EXTRA_DOMAINS), not the shared list.
FACTORY_TRUSTED_EXTRA = frozenset({"factory.bot", "deleted.local"})


def test_fixture_has_every_list():
    assert set(FACTORY) == {
        "CUSTOM_DISPOSABLE_DOMAINS",
        "DISPOSABLE_MX_HOSTS",
        "EMAIL_DOMAIN_TYPO_MAP",
        "SUSPICIOUS_DOMAIN_KEYWORDS",
        "TRUSTED_EMAIL_DOMAINS",
        "_ROLE_ACCOUNT_PREFIXES",
    }


def test_custom_disposable_domains():
    # Pinned in code, not just present in the community file: a list refresh
    # must never be able to un-flag a domain the Factory flags.
    missing = set(FACTORY["CUSTOM_DISPOSABLE_DOMAINS"]) - CUSTOM_DISPOSABLE_DOMAINS
    assert not missing, sorted(missing)


@pytest.mark.parametrize("domain", FACTORY["CUSTOM_DISPOSABLE_DOMAINS"])
def test_factory_disposable_domain_is_flagged(domain):
    assert is_disposable_email(f"someone@{domain}") is True


def test_disposable_mx_hosts():
    missing = set(FACTORY["DISPOSABLE_MX_HOSTS"]) - DISPOSABLE_MX_HOSTS
    assert not missing, sorted(missing)


def test_suspicious_domain_keywords():
    missing = set(FACTORY["SUSPICIOUS_DOMAIN_KEYWORDS"]) - set(SUSPICIOUS_DOMAIN_KEYWORDS)
    assert not missing, sorted(missing)


@pytest.mark.parametrize("typo,meant", sorted(FACTORY["EMAIL_DOMAIN_TYPO_MAP"].items()))
def test_typo_map_entry(typo, meant):
    assert EMAIL_DOMAIN_TYPO_MAP.get(typo) == meant
    assert suggest_domain_correction(typo) == meant
    # Factory entries come from the exact map, so they are tagged "map".
    assert classify_domain_typo(typo) == (meant, "map")


def test_role_prefixes_core_is_exactly_the_factory_set():
    # The core tier decides `role_account`, which the Factory treats as
    # suspicious; it must match the Factory exactly, not just contain it.
    assert CORE_ROLE_ACCOUNT_PREFIXES == frozenset(FACTORY["_ROLE_ACCOUNT_PREFIXES"])
    assert CORE_ROLE_ACCOUNT_PREFIXES <= ROLE_ACCOUNT_PREFIXES
    assert not CORE_ROLE_ACCOUNT_PREFIXES & EXTENDED_ROLE_ACCOUNT_PREFIXES


@pytest.mark.parametrize("prefix", FACTORY["_ROLE_ACCOUNT_PREFIXES"])
def test_factory_role_prefix_gives_role_account(prefix):
    assert role_account_reason(f"{prefix}@example.com") == "role_account"


def test_trusted_domains():
    factory_trusted = frozenset(FACTORY["TRUSTED_EMAIL_DOMAINS"])
    missing = factory_trusted - TRUSTED_EMAIL_DOMAINS - FACTORY_TRUSTED_EXTRA
    assert not missing, sorted(missing)
    # The Factory's synthetic domains stay out of the shared list.
    assert not TRUSTED_EMAIL_DOMAINS & FACTORY_TRUSTED_EXTRA


@pytest.mark.asyncio
@pytest.mark.parametrize("email", ["telegram_123456@factory.bot", "deleted_abc@deleted.local"])
async def test_factory_synthetic_domains_clean_with_extra_trust(email):
    suspicious, reasons = await check_registration_suspicion(
        email, trusted_extra_domains=FACTORY_TRUSTED_EXTRA)
    assert suspicious is False
    assert reasons == []
