"""Tests for X-Forwarded-For handling (GUARDPOST_TRUSTED_PROXIES)."""

import pytest

from guardpost.api.proxies import parse_trusted_proxies, resolve_client_ip, trusted_proxies_from_env

TRUSTED = parse_trusted_proxies("10.0.0.0/8, 172.16.0.1")


class TestParse:
    def test_cidrs_and_bare_addresses(self):
        nets = parse_trusted_proxies("10.0.0.0/8,172.16.0.1, ::1")
        assert [str(n) for n in nets] == ["10.0.0.0/8", "172.16.0.1/32", "::1/128"]

    def test_empty(self):
        assert parse_trusted_proxies(None) == ()
        assert parse_trusted_proxies(" , ") == ()

    def test_invalid_entry_raises(self):
        with pytest.raises(ValueError, match="GUARDPOST_TRUSTED_PROXIES"):
            parse_trusted_proxies("10.0.0.0/8,not-a-cidr")

    def test_env(self, monkeypatch):
        monkeypatch.setenv("GUARDPOST_TRUSTED_PROXIES", "192.168.0.0/16")
        assert [str(n) for n in trusted_proxies_from_env()] == ["192.168.0.0/16"]


class TestResolve:
    def test_no_trusted_proxies_ignores_header(self):
        assert resolve_client_ip("203.0.113.9", ["1.2.3.4"], ()) == "203.0.113.9"

    def test_untrusted_peer_cannot_spoof(self):
        assert resolve_client_ip("203.0.113.9", ["1.2.3.4"], TRUSTED) == "203.0.113.9"

    def test_trusted_peer_single_hop(self):
        assert resolve_client_ip("10.1.2.3", ["198.51.100.7"], TRUSTED) == "198.51.100.7"

    def test_rightmost_untrusted_hop_wins_over_spoofed_left(self):
        # The client sent "X-Forwarded-For: 1.2.3.4"; our proxy appended the
        # real address. Only the appended hop is believed.
        assert resolve_client_ip("10.1.2.3", ["1.2.3.4, 198.51.100.7"], TRUSTED) == "198.51.100.7"

    def test_chain_of_trusted_proxies_is_skipped(self):
        xff = ["1.2.3.4, 198.51.100.7, 172.16.0.1, 10.9.9.9"]
        assert resolve_client_ip("10.1.2.3", xff, TRUSTED) == "198.51.100.7"

    def test_multiple_header_lines_are_one_chain(self):
        assert resolve_client_ip("10.1.2.3", ["1.2.3.4", "198.51.100.7"], TRUSTED) == "198.51.100.7"

    def test_trusted_peer_without_header(self):
        assert resolve_client_ip("10.1.2.3", [], TRUSTED) == "10.1.2.3"

    def test_all_hops_trusted_returns_leftmost(self):
        assert resolve_client_ip("10.1.2.3", ["10.5.5.5, 172.16.0.1"], TRUSTED) == "10.5.5.5"

    def test_garbage_hop_stops_the_walk(self):
        assert resolve_client_ip("10.1.2.3", ["1.2.3.4, garbage, 10.4.4.4"], TRUSTED) == "10.4.4.4"

    def test_hop_with_port_and_v6(self):
        assert resolve_client_ip("10.1.2.3", ["198.51.100.7:4711"], TRUSTED) == "198.51.100.7"
        assert resolve_client_ip("10.1.2.3", ["[2001:db8::1]:443"], TRUSTED) == "2001:db8::1"

    def test_ipv4_mapped_peer(self):
        assert resolve_client_ip("::ffff:10.1.2.3", ["198.51.100.7"], TRUSTED) == "198.51.100.7"

    def test_non_ip_peer_passes_through(self):
        assert resolve_client_ip("testclient", ["1.2.3.4"], TRUSTED) == "testclient"
        assert resolve_client_ip(None, [], TRUSTED) == "unknown"
