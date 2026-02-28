import threading
from unittest.mock import patch, MagicMock

from dnslib import DNSRecord, QTYPE, RR, A, EDNS0

from coreguard.config import Config, UpstreamProvider
from coreguard.upstream import (
    _get_doh_client,
    close_doh_client,
    resolve_upstream,
    prepare_dnssec_request,
    check_dnssec_response,
    DNSSECError,
)

import pytest


def _make_config(providers=None, mode="doh"):
    config = Config()
    config.upstream_mode = mode
    config.upstream_timeout = 2.0
    if providers is not None:
        config.upstream_providers = providers
    return config


class TestUpstreamFailover:
    @patch("coreguard.upstream.resolve_doh")
    def test_first_provider_succeeds(self, mock_doh):
        mock_doh.return_value = b"\x00\x01"
        config = _make_config()

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x01"
        assert mock_doh.call_count == 1
        # Should have used Cloudflare (first provider)
        assert mock_doh.call_args[0][1] == "https://1.1.1.1/dns-query"

    @patch("coreguard.upstream.resolve_doh")
    def test_failover_to_second_provider(self, mock_doh):
        mock_doh.side_effect = [
            Exception("Cloudflare down"),
            b"\x00\x02",  # Google succeeds
        ]
        config = _make_config()

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x02"
        assert mock_doh.call_count == 2
        # Second call should use Google
        assert mock_doh.call_args_list[1][0][1] == "https://8.8.8.8/dns-query"

    @patch("coreguard.upstream.resolve_plain")
    @patch("coreguard.upstream.resolve_doh")
    def test_fallback_to_plain_dns(self, mock_doh, mock_plain):
        mock_doh.side_effect = Exception("All DoH down")
        mock_plain.return_value = b"\x00\x03"
        config = _make_config()

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x03"
        # DoH tried 3 times (3 providers), then plain tried once (first provider succeeds)
        assert mock_doh.call_count == 3
        assert mock_plain.call_count == 1

    @patch("coreguard.upstream.resolve_plain")
    @patch("coreguard.upstream.resolve_doh")
    def test_all_providers_fail(self, mock_doh, mock_plain):
        mock_doh.side_effect = Exception("DoH down")
        mock_plain.side_effect = Exception("Plain down")
        config = _make_config()

        with pytest.raises(Exception, match="Plain down"):
            resolve_upstream(b"\x00", config)
        # 3 DoH attempts + 3 plain fallback attempts
        assert mock_doh.call_count == 3
        assert mock_plain.call_count == 3

    @patch("coreguard.upstream.resolve_doh")
    def test_single_provider(self, mock_doh):
        """Backward compat: single provider works fine."""
        mock_doh.return_value = b"\x00\x01"
        provider = UpstreamProvider("custom", "https://custom.dns/query", "custom.dns", "", "10.0.0.1")
        config = _make_config(providers=[provider])

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x01"
        assert mock_doh.call_count == 1

    @patch("coreguard.upstream.resolve_dot")
    def test_dot_mode_uses_dot_field(self, mock_dot):
        mock_dot.return_value = b"\x00\x01"
        config = _make_config(mode="dot")

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x01"
        # Should use Cloudflare's dot server
        assert mock_dot.call_args[0][1] == "1.1.1.1"

    @patch("coreguard.upstream.resolve_plain")
    def test_plain_mode_no_double_fallback(self, mock_plain):
        """In plain mode, no secondary fallback round should occur."""
        mock_plain.side_effect = Exception("All plain down")
        config = _make_config(mode="plain")

        with pytest.raises(Exception):
            resolve_upstream(b"\x00", config)
        # Only 3 attempts (one per provider), no extra fallback round
        assert mock_plain.call_count == 3


def _make_dns_response(domain: str = "example.com", ad: bool = False) -> bytes:
    """Build a packed DNS response with configurable AD flag."""
    req = DNSRecord.question(domain)
    reply = req.reply()
    reply.add_answer(RR(domain, QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
    reply.header.ad = ad
    return reply.pack()


class TestDNSSEC:
    def test_prepare_adds_edns0_do(self):
        """prepare_dnssec_request should add an OPT record with DO bit."""
        request = DNSRecord.question("example.com")
        raw = request.pack()
        prepared = prepare_dnssec_request(raw)
        parsed = DNSRecord.parse(prepared)
        # Should have an additional record (EDNS0 OPT)
        opt_records = [r for r in parsed.ar if r.rtype == QTYPE.OPT]
        assert len(opt_records) >= 1

    def test_check_response_ad_set(self):
        """Response with AD=1 should pass through in any mode."""
        response_data = _make_dns_response(ad=True)
        result = check_dnssec_response(response_data, strict=True)
        assert result == response_data

    def test_check_response_ad_unset_permissive(self):
        """Response with AD=0 should pass through in non-strict mode."""
        response_data = _make_dns_response(ad=False)
        result = check_dnssec_response(response_data, strict=False)
        assert result == response_data

    def test_check_response_ad_unset_strict(self):
        """Response with AD=0 should raise DNSSECError in strict mode."""
        response_data = _make_dns_response(ad=False)
        with pytest.raises(DNSSECError, match="AD bit not set"):
            check_dnssec_response(response_data, strict=True)

    @patch("coreguard.upstream.resolve_doh")
    def test_resolve_upstream_with_dnssec(self, mock_doh):
        """DNSSEC enabled: DO bit should be added and response checked."""
        mock_doh.return_value = _make_dns_response(ad=True)
        config = _make_config()
        config.dnssec_enabled = True
        config.dnssec_strict = False

        result = resolve_upstream(DNSRecord.question("example.com").pack(), config)
        assert result == mock_doh.return_value
        # The request sent to DoH should have been modified (EDNS0 added)
        sent_data = mock_doh.call_args[0][0]
        parsed = DNSRecord.parse(sent_data)
        opt_records = [r for r in parsed.ar if r.rtype == QTYPE.OPT]
        assert len(opt_records) >= 1

    @patch("coreguard.upstream.resolve_doh")
    def test_dnssec_strict_raises_on_ad_unset(self, mock_doh):
        """Strict DNSSEC should raise when upstream returns AD=0."""
        mock_doh.return_value = _make_dns_response(ad=False)
        config = _make_config()
        config.dnssec_enabled = True
        config.dnssec_strict = True

        with pytest.raises(DNSSECError):
            resolve_upstream(DNSRecord.question("example.com").pack(), config)


class TestDoQ:
    @patch("coreguard.upstream.resolve_doq")
    def test_doq_mode_uses_doq_field(self, mock_doq):
        mock_doq.return_value = b"\x00\x01"
        providers = [UpstreamProvider("test", "", "", "doq.example.com", "1.1.1.1")]
        config = _make_config(providers=providers, mode="doq")

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x01"
        assert mock_doq.call_args[0][1] == "doq.example.com"

    @patch("coreguard.upstream.resolve_plain")
    @patch("coreguard.upstream.resolve_doq")
    def test_doq_fallback_to_plain(self, mock_doq, mock_plain):
        """All DoQ fail -> plain succeeds."""
        mock_doq.side_effect = Exception("DoQ down")
        mock_plain.return_value = b"\x00\x02"
        providers = [UpstreamProvider("test", "", "", "doq.example.com", "1.1.1.1")]
        config = _make_config(providers=providers, mode="doq")

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x02"
        assert mock_plain.call_count == 1

    @patch("coreguard.upstream.resolve_plain")
    def test_doq_provider_no_endpoint(self, mock_plain):
        """Provider with empty doq field should skip and try next / fallback."""
        mock_plain.return_value = b"\x00\x03"
        providers = [UpstreamProvider("no-doq", "", "", "", "1.1.1.1")]
        config = _make_config(providers=providers, mode="doq")

        result = resolve_upstream(b"\x00", config)
        assert result == b"\x00\x03"

    @patch("coreguard.upstream.resolve_plain")
    @patch("coreguard.upstream.resolve_doq")
    def test_doq_all_fail(self, mock_doq, mock_plain):
        """All DoQ + plain fail -> exception raised."""
        mock_doq.side_effect = Exception("DoQ down")
        mock_plain.side_effect = Exception("Plain down")
        providers = [UpstreamProvider("test", "", "", "doq.example.com", "1.1.1.1")]
        config = _make_config(providers=providers, mode="doq")

        with pytest.raises(Exception, match="Plain down"):
            resolve_upstream(b"\x00", config)


class TestDoHClientLocking:
    def test_concurrent_get_creates_single_client(self):
        """Multiple concurrent calls to _get_doh_client should create only one client."""
        close_doh_client()  # Ensure clean state
        clients = []
        errors = []

        def get_client():
            try:
                client = _get_doh_client(timeout=5.0)
                clients.append(id(client))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_client) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # All threads should have gotten the same client instance
        assert len(set(clients)) == 1
        close_doh_client()  # Clean up
