"""Tests for scripts/check_blocklist.py, the guard on the weekly list refresh."""

import importlib.util
import sys
from pathlib import Path

import pytest

from guardpost.email.validator import BLOCKLIST_PATH, COMMUNITY_DISPOSABLE_DOMAINS, CUSTOM_DISPOSABLE_DOMAINS

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_blocklist.py"
_spec = importlib.util.spec_from_file_location("check_blocklist", _SCRIPT)
check_blocklist_mod = importlib.util.module_from_spec(_spec)
sys.modules["check_blocklist"] = check_blocklist_mod  # dataclasses resolve their module
_spec.loader.exec_module(check_blocklist_mod)

check_blocklist = check_blocklist_mod.check_blocklist
render_summary = check_blocklist_mod.render_summary


def _body(domains):
    return "\n".join(domains) + "\n"


OLD = [f"spam{i}.example" for i in range(1000)]


class TestShrinkGuard:
    def test_growth_passes(self):
        report = check_blocklist(_body(OLD), _body(OLD + ["new.example"]), custom_domains=set())
        assert report.ok
        assert report.added == ["new.example"]

    def test_small_shrink_passes(self):
        # 10 of 1000 removed = exactly 1%, which is allowed.
        report = check_blocklist(_body(OLD), _body(OLD[10:]), custom_domains=set())
        assert report.ok, report.errors
        assert len(report.removed) == 10

    def test_shrink_over_one_percent_fails(self):
        report = check_blocklist(_body(OLD), _body(OLD[11:]), custom_domains=set())
        assert not report.ok
        assert "shorter" in report.errors[0]

    def test_truncated_download_fails(self):
        report = check_blocklist(_body(OLD), _body(OLD[:200]), custom_domains=set())
        assert not report.ok

    def test_empty_download_fails(self):
        report = check_blocklist(_body(OLD), "", custom_domains=set())
        assert not report.ok
        assert "new list is empty" in report.errors

    def test_html_error_page_fails(self):
        page = "<html>\n<body>Rate limited</body>\n</html>\n"
        report = check_blocklist(_body(OLD), _body(OLD) + page, custom_domains=set())
        assert not report.ok
        assert any("non-domain" in e for e in report.errors)

    def test_comments_and_blank_lines_ignored(self):
        report = check_blocklist(_body(OLD), "# header\n\n" + _body(OLD), custom_domains=set())
        assert report.ok, report.errors


class TestCustomDomains:
    def test_removed_custom_domain_is_reported_as_pinned(self):
        new = [d for d in OLD if d != "spam5.example"]
        report = check_blocklist(_body(OLD), _body(new), custom_domains={"spam5.example"})
        assert report.ok
        assert report.removed_but_pinned == ["spam5.example"]
        assert "known divergence" in render_summary(report)

    def test_real_custom_domains_survive_an_emptied_community_file(self):
        # Even if upstream ships an empty file the guard fails for the
        # emptiness, never because a pinned domain fell out.
        report = check_blocklist(_body(OLD), "", custom_domains=CUSTOM_DISPOSABLE_DOMAINS)
        assert not any("custom domains" in e for e in report.errors)


class TestShippedList:
    def test_shipped_list_passes_against_itself(self):
        text = BLOCKLIST_PATH.read_text()
        report = check_blocklist(text, text, custom_domains=CUSTOM_DISPOSABLE_DOMAINS)
        assert report.ok, report.errors
        assert report.invalid_lines == []

    def test_shipped_list_is_the_full_refresh(self):
        # Guards against a partial checkout of the 9,913-line refresh.
        assert len(COMMUNITY_DISPOSABLE_DOMAINS) >= 9_900

    @pytest.mark.parametrize("domain", ["atomicmail.io", "ip6.li", "iwi.net", "mailhub.pro"])
    def test_upstream_removals_still_flagged(self, domain):
        from guardpost.email.validator import is_disposable_email

        assert domain not in COMMUNITY_DISPOSABLE_DOMAINS
        assert domain in CUSTOM_DISPOSABLE_DOMAINS
        assert is_disposable_email(f"user@{domain}") is True


class TestCli:
    def test_main_writes_summary_and_fails_on_truncation(self, tmp_path):
        old, new, summary = tmp_path / "old.conf", tmp_path / "new.conf", tmp_path / "s.md"
        old.write_text(_body(OLD))
        new.write_text(_body(OLD[:500]))
        assert check_blocklist_mod.main([str(old), str(new), "--summary", str(summary)]) == 1
        assert "Guard failures" in summary.read_text()

    def test_main_passes_on_growth(self, tmp_path):
        old, new = tmp_path / "old.conf", tmp_path / "new.conf"
        old.write_text(_body(OLD))
        new.write_text(_body(OLD + ["fresh.example"]))
        assert check_blocklist_mod.main([str(old), str(new)]) == 0
