"""Tests for email validation engine."""

from guardpost.email.validator import (
    check_registration_suspicion,
    get_email_domain,
    is_disposable_email,
    is_role_account,
    is_suspicious_email,
    normalize_email,
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
