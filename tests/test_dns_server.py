from unittest.mock import MagicMock, patch

from dnslib import DNSRecord, QTYPE

from coreguard.config import Config
from coreguard.dns_server import BlockingResolver
from coreguard.filtering import DomainFilter
from coreguard.stats import Stats


def _make_request(domain: str, qtype: str = "A") -> DNSRecord:
    """Build a DNS query for testing."""
    return DNSRecord.question(domain, qtype)


class TestBlockingResolver:
    def setup_method(self):
        self.domain_filter = DomainFilter()
        self.domain_filter.load_blocklist(["ads.example.com", "tracker.bad.org"])
        self.config = Config()
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger
        )

    def test_blocks_known_domain(self):
        request = _make_request("ads.example.com")
        response = self.resolver.resolve(request, None)
        # Should have an answer with 0.0.0.0
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "0.0.0.0"
        assert self.stats.blocked_queries == 1

    def test_blocks_subdomain(self):
        request = _make_request("sub.ads.example.com")
        response = self.resolver.resolve(request, None)
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "0.0.0.0"

    def test_blocks_aaaa(self):
        request = _make_request("ads.example.com", "AAAA")
        response = self.resolver.resolve(request, None)
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "::"

    @patch("coreguard.dns_server.resolve_upstream")
    def test_forwards_clean_domain(self, mock_upstream):
        # Build a fake upstream response
        upstream_request = _make_request("github.com")
        upstream_reply = upstream_request.reply()
        from dnslib import RR, A
        upstream_reply.add_answer(RR("github.com", QTYPE.A, rdata=A("140.82.121.4"), ttl=300))
        mock_upstream.return_value = upstream_reply.pack()

        request = _make_request("github.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.blocked_queries == 0
        assert self.stats.total_queries == 1
        mock_upstream.assert_called_once()

    @patch("coreguard.dns_server.resolve_upstream")
    def test_returns_servfail_on_upstream_error(self, mock_upstream):
        mock_upstream.side_effect = Exception("connection timeout")
        request = _make_request("github.com")
        response = self.resolver.resolve(request, None)
        assert response.header.rcode == 2  # SERVFAIL
        assert self.stats.error_queries == 1

    def test_logs_blocked_query(self):
        request = _make_request("ads.example.com")
        self.resolver.resolve(request, None)
        self.query_logger.log_query.assert_called_once()
        args = self.query_logger.log_query.call_args
        assert args[1]["blocked"] is True or args[0][2] is True
