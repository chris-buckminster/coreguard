"""Integration tests — modules interact with each other, mocking only at the OS boundary."""

from unittest.mock import MagicMock, patch

from dnslib import DNSRecord, QTYPE, RR, A

from coreguard.cache import DNSCache
from coreguard.config import Config
from coreguard.dns_server import BlockingResolver
from coreguard.filtering import DomainFilter
from coreguard.stats import Stats


def _make_upstream_response(domain: str, ip: str = "93.184.216.34") -> bytes:
    req = DNSRecord.question(domain)
    reply = req.reply()
    reply.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))
    return reply.pack()


class TestBlockAndResolveFlow:
    """Tests the full flow: config → filter → DNS server → cache → stats."""

    def setup_method(self):
        self.config = Config()
        self.config.cache_enabled = True
        self.config.cname_check_enabled = True
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.domain_filter = DomainFilter()
        self.cache = DNSCache(max_entries=100, max_ttl=3600, min_ttl=0)
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger, self.cache
        )

    @patch("coreguard.dns_server.resolve_upstream")
    def test_full_block_and_allow_flow(self, mock_upstream):
        """Load blocklist → block a query → allow a different query → verify stats."""
        mock_upstream.return_value = _make_upstream_response("github.com")

        # Load a blocklist
        self.domain_filter.load_blocklist(["ads.example.com", "tracker.net"])

        # Blocked query
        request = DNSRecord.question("ads.example.com")
        response = self.resolver.resolve(request, None)
        assert str(response.rr[0].rdata) == "0.0.0.0"

        # Allowed query (goes to upstream)
        request = DNSRecord.question("github.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.total_queries == 2
        assert self.stats.blocked_queries == 1
        mock_upstream.assert_called_once()

        # Second allowed query hits cache
        request = DNSRecord.question("github.com")
        self.resolver.resolve(request, None)
        assert self.stats.cache_hits == 1
        assert mock_upstream.call_count == 1  # Not called again

        # Verify logging
        assert self.query_logger.log_query.call_count == 3

    @patch("coreguard.dns_server.resolve_upstream")
    def test_allowlist_overrides_blocklist(self, mock_upstream):
        """A domain on both lists should be allowed (allowlist wins)."""
        mock_upstream.return_value = _make_upstream_response("example.com")

        self.domain_filter.load_blocklist(["example.com"])
        self.domain_filter.load_allowlist(["example.com"])

        request = DNSRecord.question("example.com")
        response = self.resolver.resolve(request, None)

        assert self.stats.blocked_queries == 0
        mock_upstream.assert_called_once()


class TestReloadFlow:
    """Tests that reloading filter lists correctly updates blocking behavior."""

    def setup_method(self):
        self.config = Config()
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.domain_filter = DomainFilter()
        self.cache = DNSCache(max_entries=100, max_ttl=3600, min_ttl=0)
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger, self.cache
        )

    @patch("coreguard.dns_server.resolve_upstream")
    def test_new_domains_blocked_after_reload(self, mock_upstream):
        """After reloading with new domains, previously-allowed domains get blocked."""
        mock_upstream.return_value = _make_upstream_response("new-tracker.com")

        # Initially allowed
        self.domain_filter.load_blocklist(["old-ads.com"])
        request = DNSRecord.question("new-tracker.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.blocked_queries == 0

        # Simulate reload: clear and load new list
        self.domain_filter.clear()
        self.domain_filter.load_blocklist(["old-ads.com", "new-tracker.com"])
        self.cache.clear()

        # Now blocked
        request = DNSRecord.question("new-tracker.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.blocked_queries == 1
        assert str(response.rr[0].rdata) == "0.0.0.0"
