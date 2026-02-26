from unittest.mock import patch, MagicMock

from coreguard.config import Config, UpstreamProvider
from coreguard.upstream import resolve_upstream

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
        provider = UpstreamProvider("custom", "https://custom.dns/query", "custom.dns", "10.0.0.1")
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
