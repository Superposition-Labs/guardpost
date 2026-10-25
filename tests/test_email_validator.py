"""Tests for email validation engine."""

from guardpost.email.validator import (
    EMAIL_DOMAIN_TYPO_MAP,
    HARD_REASONS,
    TRUSTED_EMAIL_DOMAINS,
    ReasonTier,
    _mx_host_cache,
    check_domain_has_mx,
    check_domain_has_null_mx,
    check_registration_suspicion,
    classify_domain_typo,
    clear_caches,
    get_email_domain,
    has_dot_noise,
    has_gibberish_domain,
    has_hard_reason,
    has_suspicious_reason,
    is_disposable_email,
    is_homograph_domain,
    is_role_account,
    is_suspicious_email,
    normalize_email,
    parse_domain_list,
    partition_reasons,
    reason_tier,
    role_account_reason,
    suggest_domain_correction,
    trusted_extra_domains_from_env,
    validate_email_format,
)

# ---------------------------------------------------------------------------
# normalize_email
# ---------------------------------------------------------------------------


class TestNormalizeEmail:
    def test_gmail_dots_removed(self):
        assert normalize_email("j.o.h.n@gmail.com") == "john@gmail.com"

    def test_gmail_plus_removed(self):
        assert normalize_email("user+tag@gmail.com") == "user@gmail.com"

    def test_gmail_dots_and_plus(self):
        assert normalize_email("u.s.e.r+extra@gmail.com") == "user@gmail.com"

    def test_googlemail_normalizes_to_gmail(self):
        assert normalize_email("test@googlemail.com") == "test@gmail.com"

    def test_outlook_plus_removed(self):
        assert normalize_email("user+tag@outlook.com") == "user@outlook.com"

    def test_outlook_dots_preserved(self):
        assert normalize_email("j.o.h.n@outlook.com") == "j.o.h.n@outlook.com"

    def test_yahoo_hyphen_removed(self):
        assert normalize_email("user-alias@yahoo.com") == "user@yahoo.com"

    def test_other_plus_removed(self):
        assert normalize_email("user+tag@example.com") == "user@example.com"

    def test_mailru_group_canonicalized(self):
        # mail.ru / bk.ru / list.ru / inbox.ru share one mailbox namespace
        assert normalize_email("abuser@bk.ru") == "abuser@mail.ru"
        assert normalize_email("abuser@list.ru") == "abuser@mail.ru"
        assert normalize_email("abuser@inbox.ru") == "abuser@mail.ru"
        assert normalize_email("abuser@mail.ru") == "abuser@mail.ru"

    def test_mailru_group_plus_alias_stripped(self):
        assert normalize_email("abuser+promo@bk.ru") == "abuser@mail.ru"

    def test_yandex_group_canonicalized(self):
        # ya.ru / yandex.ru / yandex.com / regional TLDs share one account
        assert normalize_email("abuser@ya.ru") == "abuser@yandex.ru"
        assert normalize_email("abuser@yandex.com") == "abuser@yandex.ru"
        assert normalize_email("abuser@yandex.by") == "abuser@yandex.ru"
        assert normalize_email("abuser@yandex.kz") == "abuser@yandex.ru"
        assert normalize_email("abuser@yandex.ua") == "abuser@yandex.ru"

    def test_preserves_case(self):
        assert normalize_email("User@Gmail.Com") == "user@gmail.com"

    def test_empty_string(self):
        assert normalize_email("") == ""

    def test_no_at_sign(self):
        assert normalize_email("invalid") == "invalid"


# ---------------------------------------------------------------------------
# get_email_domain
# ---------------------------------------------------------------------------


class TestGetEmailDomain:
    def test_simple(self):
        assert get_email_domain("user@example.com") == "example.com"

    def test_uppercase(self):
        assert get_email_domain("User@EXAMPLE.COM") == "example.com"

    def test_empty(self):
        assert get_email_domain("") == ""

    def test_no_at(self):
        assert get_email_domain("invalid") == ""


# ---------------------------------------------------------------------------
# is_disposable_email
# ---------------------------------------------------------------------------


class TestIsDisposableEmail:
    def test_known_disposable(self):
        assert is_disposable_email("user@mailinator.com") is True

    def test_known_disposable_yopmail(self):
        assert is_disposable_email("user@yopmail.com") is True

    def test_gmail_not_disposable(self):
        assert is_disposable_email("user@gmail.com") is False

    def test_custom_blocklist(self):
        assert is_disposable_email("user@guerrillamail.com") is True

    def test_cis_disposable_additions(self):
        assert is_disposable_email("user@1secmail.com") is True
        assert is_disposable_email("user@tempmail.plus") is True
        assert is_disposable_email("user@vremennaya-pochta.ru") is True

    def test_trusted_cis_providers_not_disposable(self):
        for addr in ("user@ukr.net", "user@tut.by", "user@internet.ru", "user@i.ua"):
            assert is_disposable_email(addr) is False


# ---------------------------------------------------------------------------
# is_role_account
# ---------------------------------------------------------------------------


class TestIsRoleAccount:
    def test_info(self):
        assert is_role_account("info@example.com") is True

    def test_admin(self):
        assert is_role_account("admin@example.com") is True

    def test_postmaster(self):
        assert is_role_account("postmaster@example.com") is True

    def test_noreply(self):
        assert is_role_account("noreply@example.com") is True

    def test_regular_user(self):
        assert is_role_account("john.doe@example.com") is False

    def test_empty(self):
        assert is_role_account("") is False


# ---------------------------------------------------------------------------
# validate_email_format
# ---------------------------------------------------------------------------


class TestValidateEmailFormat:
    def test_valid(self):
        is_valid, err = validate_email_format("user@example.com")
        assert is_valid is True
        assert err is None

    def test_invalid_no_at(self):
        is_valid, err = validate_email_format("invalid")
        assert is_valid is False
        assert err is not None

    def test_invalid_format(self):
        is_valid, err = validate_email_format("user@.com")
        assert is_valid is False

    def test_empty(self):
        is_valid, err = validate_email_format("")
        assert is_valid is False


# ---------------------------------------------------------------------------
# is_suspicious_email (integration of all layers, mocked DNS)
# ---------------------------------------------------------------------------


class TestIsSuspiciousEmail:
    async def test_disposable_flagged(self):
        is_suspicious, reasons = await is_suspicious_email("test@mailinator.com")
        assert is_suspicious is True
        assert "disposable_domain" in reasons

    async def test_trusted_domain_clean(self):
        is_suspicious, reasons = await is_suspicious_email("test@gmail.com")
        assert is_suspicious is False
        assert reasons == []

    async def test_numeric_domain(self):
        is_suspicious, reasons = await is_suspicious_email("test@1234domain.com")
        assert is_suspicious is True
        assert "numeric_domain" in reasons

    async def test_very_short_domain(self):
        is_suspicious, reasons = await is_suspicious_email("test@ab.com")
        assert is_suspicious is True
        assert "very_short_domain" in reasons


# ---------------------------------------------------------------------------
# check_registration_suspicion
# ---------------------------------------------------------------------------


class TestCheckRegistrationSuspicion:
    async def test_invalid_format(self):
        is_susp, reasons = await check_registration_suspicion("invalid")
        assert is_susp is True
        assert "invalid_format" in reasons

    async def test_disposable(self):
        is_susp, reasons = await check_registration_suspicion("x@yopmail.com")
        assert is_susp is True
        assert "disposable_domain" in reasons

    async def test_multiple_aliases(self):
        is_susp, reasons = await check_registration_suspicion("user+a+b@example.com")
        assert is_susp is True
        assert "multiple_aliases" in reasons

    async def test_role_account_detected(self):
        is_susp, reasons = await check_registration_suspicion("admin@example.com")
        assert is_susp is True
        assert "role_account" in reasons

    async def test_clean_gmail(self):
        is_susp, reasons = await check_registration_suspicion("realuser@gmail.com")
        assert is_susp is False
        assert reasons == []


# ---------------------------------------------------------------------------
# Aug 2026 signals — every case below is drawn from the factory_ru sweep
# ---------------------------------------------------------------------------


class TestDotNoiseLocal:
    """Gmail dot noise: a generator's signature, not a person's typing."""

    def test_real_abuse_samples_detected(self):
        # Verbatim from factory_ru. None of these accounts ever paid.
        for addr in (
            "pe.llig.rino.phi.lip.os.e7.60@gmail.com",
            "z.u.le.i.kad.e.n.e.k.e@gmail.com",
            "v.u.ph.uo.n.g.t.r.an.g8.6.0.5@gmail.com",
            "w.illia.mf.dani.ell7.1.7@gmail.com",
            "inf.u.sedr.a.indro.ps12.6@googlemail.com",
        ):
            assert has_dot_noise(addr) is True, addr

    def test_ordinary_names_untouched(self):
        # 4,296 of 4,374 Gmail users in factory_ru sit at 0-2 dots.
        for addr in (
            "ivan.petrov@gmail.com",
            "a.b@gmail.com",
            "john.smith.jr@gmail.com",
            "realuser@gmail.com",
            "maria.ivanova.1990@gmail.com",
        ):
            assert has_dot_noise(addr) is False, addr

    def test_three_dots_needs_the_ratio(self):
        # Three dots in a long name are ordinary separators...
        assert has_dot_noise("alexander.konstantinovich.petrov.jr@gmail.com") is False
        # ...but three dots in a short local part are noise.
        assert has_dot_noise("a.b.c.d@gmail.com") is True

    def test_plus_tag_ignored(self):
        # The tag is not part of the name the attacker is mutating.
        assert has_dot_noise("user+a.b.c.d.e@gmail.com") is False

    def test_only_gmail_family(self):
        # Dots are significant everywhere else, so the rule must not apply.
        assert has_dot_noise("a.b.c.d.e@yandex.ru") is False
        assert has_dot_noise("a.b.c.d.e@outlook.com") is False

    async def test_survives_the_trusted_short_circuit(self):
        # gmail.com is trusted, so is_suspicious_email() returns early. The rule
        # only works if check_registration_suspicion() applies it afterwards.
        is_susp, reasons = await check_registration_suspicion(
            "z.u.le.i.kad.e.n.e.k.e@gmail.com")
        assert is_susp is True
        assert "dot_noise_local" in reasons


class TestTypoDomain:
    def test_dead_typos(self):
        assert suggest_domain_correction("x@gmail.con") == "gmail.com"
        assert suggest_domain_correction("x@mail.ry") == "mail.ru"
        assert suggest_domain_correction("x@yandex.ry") == "yandex.ru"

    def test_live_squatters(self):
        # These run a catch-all MX, so no DNS layer would stop them.
        assert suggest_domain_correction("x@gnail.com") == "gmail.com"
        assert suggest_domain_correction("x@gmai.com") == "gmail.com"
        assert suggest_domain_correction("x@indox.ru") == "inbox.ru"
        assert suggest_domain_correction("x@maul.ru") == "mail.ru"

    def test_digit_prefixed_provider(self):
        assert suggest_domain_correction("x@501gmail.com") == "gmail.com"
        assert suggest_domain_correction("x@536gmail.com") == "gmail.com"

    def test_real_domains_untouched(self):
        for domain in ("gmail.com", "yandex.ru", "mail.ru", "rudn.ru",
                       "kpfu.ru", "outlook.com", "example.com"):
            assert suggest_domain_correction(f"x@{domain}") is None, domain

    async def test_reason_is_hard(self):
        is_susp, reasons = await check_registration_suspicion("user@gnail.com")
        assert is_susp is True
        assert "typo_domain" in reasons


class TestHomographDomain:
    def test_cyrillic_gmail_detected(self):
        # "gmail.сом" — the last three letters are Cyrillic с, о, м.
        assert is_homograph_domain("x@gmail.сом") is True

    def test_ascii_domains_ignored(self):
        assert is_homograph_domain("x@gmail.com") is False
        assert is_homograph_domain("x@ygwpr.com") is False

    def test_unrelated_unicode_domain_ignored(self):
        # A real internationalised domain is not an impersonation.
        assert is_homograph_domain("x@почта.рф") is False


class TestWeakSignalTier:
    def test_gibberish_domain_matches_farms(self):
        for domain in ("ygwpr.com", "dbwot.com", "qqwwt.com", "vvkku.com", "wshu.net"):
            assert has_gibberish_domain(f"x@{domain}") is True, domain

    def test_vowel_bearing_farm_domains_left_to_the_blocklist(self):
        # imxwe.com is a farm too, but it carries two vowels, so this rule
        # cannot reach it. The explicit blocklist entry is what stops it —
        # a reminder that the weak tier supplements the lists, never replaces
        # them.
        assert has_gibberish_domain("x@imxwe.com") is False
        assert is_disposable_email("x@imxwe.com") is True

    def test_gibberish_domain_also_matches_real_universities(self):
        # Exactly why this signal must stay weak — these are real institutions.
        assert has_gibberish_domain("student@rudn.ru") is True
        assert has_gibberish_domain("staff@kpfu.ru") is True

    def test_gibberish_never_condemns_alone(self):
        # rudn.ru resolves and is not blocklisted, so gibberish_domain is the
        # only thing it can trip. It must not make the address suspicious.
        assert has_hard_reason(["gibberish_domain"]) is False
        assert has_hard_reason(["gibberish_domain", "relay_domain"]) is False

    def test_one_hard_reason_is_enough(self):
        assert has_hard_reason(["gibberish_domain", "disposable_domain"]) is True

    def test_unknown_reasons_default_to_hard(self):
        # Forgetting to classify a new signal must fail safe.
        assert has_hard_reason(["some_future_signal"]) is True

    def test_detail_suffix_stripped(self):
        assert has_hard_reason(["subnet_burst:1.2.3.0/24"]) is True

    def test_partition_preserves_order(self):
        hard, soft, weak = partition_reasons(
            ["disposable_domain", "gibberish_domain", "no_mx_records", "relay_domain"])
        assert hard == []
        assert soft == ["disposable_domain", "no_mx_records"]
        assert weak == ["gibberish_domain", "relay_domain"]

    async def test_relay_domain_is_not_suspicious(self):
        # Privacy relays are legitimate. They enable multi-accounting, so they
        # are worth scoring, but they must never deny anyone a bonus.
        is_susp, reasons = await check_registration_suspicion("user@duck.com")
        assert is_susp is False
        assert "relay_domain" in reasons


class TestNullMX:
    """RFC 7505: an MX of "." declares that the domain accepts no mail.

    It is still an answer, so a bare bool(records) test calls such a domain
    deliverable. factory_ru holds three of them, including the gmaii.com
    typo-squatter, whose only MX is "localhost".
    """

    def setup_method(self):
        clear_caches()

    def teardown_method(self):
        clear_caches()

    async def test_null_mx_is_not_deliverable(self):
        # Seed the resolver cache instead of mocking DNS: _resolve_mx_host()
        # reads it first, so the test stays offline and deterministic.
        _mx_host_cache["nullmx.example"] = ""
        assert await check_domain_has_null_mx("nullmx.example") is True
        assert await check_domain_has_mx("nullmx.example") is False

    async def test_localhost_mx_is_not_deliverable(self):
        _mx_host_cache["squatter.example"] = "localhost"
        assert await check_domain_has_null_mx("squatter.example") is True
        assert await check_domain_has_mx("squatter.example") is False

    async def test_real_mx_unaffected(self):
        _mx_host_cache["real.example"] = "mx.real.example"
        assert await check_domain_has_null_mx("real.example") is False
        assert await check_domain_has_mx("real.example") is True

    async def test_no_records_is_not_null_mx(self):
        # "no MX at all" and "null MX" are different failures.
        _mx_host_cache["missing.example"] = None
        assert await check_domain_has_null_mx("missing.example") is False
        assert await check_domain_has_mx("missing.example") is False

    async def test_reason_reported(self):
        _mx_host_cache["nullmx.example"] = ""
        is_susp, reasons = await is_suspicious_email("user@nullmx.example")
        assert "null_mx" in reasons
        assert "no_mx_records" not in reasons
        # Weak: the Factory's MX test accepts a null MX, so Guardpost scores
        # it but does not call the address suspicious on that alone.
        assert is_susp is False

    async def test_weak_signal_does_not_suppress_the_dns_layers(self):
        # ygwpr.com is gibberish (weak). If the DNS block were guarded on
        # `reasons` rather than on hard reasons, that weak signal alone would
        # skip the MX checks entirely.
        _mx_host_cache["ygwpq.example"] = None
        is_susp, reasons = await is_suspicious_email("user@ygwpq.example")
        assert "gibberish_domain" in reasons
        assert "no_mx_records" in reasons
        assert is_susp is True


class TestTypoTLDNarrowness:
    """.om (Oman) and .cm (Cameroon) are real country TLDs.

    An unanchored suffix test would rewrite legitimate domains, so the TLD rule
    only fires when a known provider name precedes the bad suffix.
    """

    def test_provider_prefixed_tld_typo_corrected(self):
        assert suggest_domain_correction("x@gmail.om") == "gmail.com"
        assert suggest_domain_correction("x@yandex.ry") == "yandex.ru"
        assert suggest_domain_correction("x@bk.ry") == "bk.ru"

    def test_real_country_tlds_left_alone(self):
        for domain in ("bank.om", "shop.cm", "omantel.om", "camtel.cm"):
            assert suggest_domain_correction(f"x@{domain}") is None, domain


class TestRoleAccountTiers:
    """The Factory's 43 prefixes give role_account; the rest are extended."""

    def test_core_prefix(self):
        assert role_account_reason("info@example.com") == "role_account"
        assert role_account_reason("Support@Example.com") == "role_account"

    def test_extended_prefix(self):
        assert role_account_reason("dev@example.com") == "role_account_extended"
        assert role_account_reason("hello@example.com") == "role_account_extended"

    def test_not_a_role(self):
        assert role_account_reason("ivan.petrov@example.com") is None
        assert role_account_reason("") is None

    def test_is_role_account_still_covers_both_tiers(self):
        assert is_role_account("dev@example.com") is True
        assert is_role_account("info@example.com") is True

    async def test_extended_prefix_is_weak(self):
        is_susp, reasons = await check_registration_suspicion("hello@gmail.com")
        assert reasons == ["role_account_extended"]
        assert is_susp is False

    async def test_core_prefix_still_flags(self):
        is_susp, reasons = await check_registration_suspicion("admin@gmail.com")
        assert reasons == ["role_account"]
        assert is_susp is True


class TestTypoSource:
    def test_map(self):
        assert classify_domain_typo("x@gnail.com") == ("gmail.com", "map")

    def test_tld(self):
        # Not in the map, so only the TLD rule can match it.
        assert "googlemail.con" not in EMAIL_DOMAIN_TYPO_MAP
        assert classify_domain_typo("x@googlemail.con") == ("googlemail.com", "tld")
        assert classify_domain_typo("inbox.ry") == ("inbox.ru", "tld")

    def test_numeric(self):
        assert classify_domain_typo("x@501gmail.com") == ("gmail.com", "numeric")

    def test_no_match(self):
        assert classify_domain_typo("x@gmail.com") is None
        assert classify_domain_typo("") is None

    def test_suggest_domain_correction_unchanged(self):
        assert suggest_domain_correction("x@googlemail.con") == "googlemail.com"


class TestTrustedExtraDomains:
    def setup_method(self):
        clear_caches()

    def teardown_method(self):
        clear_caches()

    def test_factory_domains_are_not_shared_trust(self):
        assert "factory.bot" not in TRUSTED_EMAIL_DOMAINS
        assert "deleted.local" not in TRUSTED_EMAIL_DOMAINS

    async def test_untrusted_by_default(self):
        _mx_host_cache["factory.bot"] = None  # does not resolve
        is_susp, reasons = await is_suspicious_email("telegram_1@factory.bot")
        assert "no_mx_records" in reasons
        assert is_susp is True

    async def test_extra_trust_skips_dns(self):
        _mx_host_cache["factory.bot"] = None
        is_susp, reasons = await is_suspicious_email(
            "telegram_1@factory.bot", trusted_extra_domains={"factory.bot"})
        assert reasons == []
        assert is_susp is False

    async def test_extra_trust_does_not_hide_a_disposable_domain(self):
        is_susp, reasons = await is_suspicious_email(
            "x@mailinator.com", trusted_extra_domains={"mailinator.com"})
        assert "disposable_domain" in reasons
        assert is_susp is True

    def test_parse_domain_list(self):
        assert parse_domain_list(" Factory.bot, ,@deleted.local ") == {"factory.bot", "deleted.local"}
        assert parse_domain_list(None) == frozenset()
        assert parse_domain_list(["A.example"]) == {"a.example"}

    def test_env(self, monkeypatch):
        monkeypatch.setenv("GUARDPOST_TRUSTED_EXTRA_DOMAINS", "factory.bot,deleted.local")
        assert trusted_extra_domains_from_env() == {"factory.bot", "deleted.local"}
        monkeypatch.delenv("GUARDPOST_TRUSTED_EXTRA_DOMAINS")
        assert trusted_extra_domains_from_env() == frozenset()


class TestReasonTiers:
    def test_defaults_reproduce_factory_semantics(self):
        assert HARD_REASONS == frozenset()
        for kind in ("gibberish_domain", "relay_domain", "role_account_extended", "homograph_domain", "null_mx"):
            assert reason_tier(kind) is ReasonTier.WEAK, kind
        for kind in ("disposable_domain", "disposable_mx_infrastructure", "no_mx_records", "typo_domain",
                     "dot_noise_local", "role_account", "suspicious_domain_keyword", "invalid_format",
                     "multiple_aliases", "numeric_domain", "very_short_domain", "subnet_burst"):
            assert reason_tier(kind) is ReasonTier.SOFT, kind

    def test_detail_suffix_and_unknown_reasons(self):
        assert reason_tier("subnet_burst:1.2.3.0/24") is ReasonTier.SOFT
        assert reason_tier("datacenter_range:AWS") is ReasonTier.SOFT
        assert reason_tier("some_future_signal") is ReasonTier.SOFT

    def test_overrides(self):
        tiers = {"typo_domain": "hard", "subnet_burst": ReasonTier.WEAK}
        hard, soft, weak = partition_reasons(
            ["typo_domain", "subnet_burst:1.2.3.0/24", "disposable_domain"], tiers)
        assert hard == ["typo_domain"]
        assert soft == ["disposable_domain"]
        assert weak == ["subnet_burst:1.2.3.0/24"]

    def test_every_reason_lands_in_exactly_one_tier(self):
        reasons = ["role_account", "null_mx", "subnet_burst:1.2.3.0/24", "relay_domain"]
        hard, soft, weak = partition_reasons(reasons)
        assert sorted(hard + soft + weak) == sorted(reasons)

    def test_has_suspicious_reason(self):
        assert has_suspicious_reason(["gibberish_domain", "null_mx"]) is False
        assert has_suspicious_reason(["gibberish_domain", "role_account"]) is True
        assert has_suspicious_reason(["typo_domain"], {"typo_domain": "weak"}) is False

    def test_tier_values_are_strings(self):
        assert ReasonTier("hard") is ReasonTier.HARD
        assert ReasonTier.SOFT == "soft"
