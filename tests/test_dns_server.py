from unittest.mock import MagicMock, patch

from dnslib import DNSRecord, QTYPE, RR, A, CNAME

from coreguard.cache import DNSCache
from coreguard.config import Config
from coreguard.dns_server import BlockingResolver
from coreguard.filtering import DomainFilter
from coreguard.stats import Stats


def _make_request(domain: str, qtype: str = "A") -> DNSRecord:
    """Build a DNS query for testing."""
    return DNSRecord.question(domain, qtype)


def _make_upstream_response(domain: str, ip: str = "1.2.3.4", ttl: int = 300) -> bytes:
    """Build a packed upstream response for mocking."""
    req = DNSRecord.question(domain)
    reply = req.reply()
    reply.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=ttl))
    return reply.pack()


def _make_cname_response(domain: str, cname_target: str, final_ip: str = "1.2.3.4") -> bytes:
    """Build a packed upstream response with a CNAME chain."""
    req = DNSRecord.question(domain)
    reply = req.reply()
    reply.add_answer(RR(domain, QTYPE.CNAME, rdata=CNAME(cname_target), ttl=300))
    reply.add_answer(RR(cname_target, QTYPE.A, rdata=A(final_ip), ttl=300))
    return reply.pack()


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
        mock_upstream.return_value = _make_upstream_response("github.com", "140.82.121.4")

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


class TestCNAMEFlattening:
    def setup_method(self):
        self.domain_filter = DomainFilter()
        self.domain_filter.load_blocklist(["tracker.bad.org", "ads.network.com"])
        self.config = Config()
        self.config.cname_check_enabled = True
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger
        )

    @patch("coreguard.dns_server.resolve_upstream")
    def test_cname_target_blocked(self, mock_upstream):
        """A clean domain that CNAMEs to a blocked domain should be blocked."""
        mock_upstream.return_value = _make_cname_response(
            "innocent.com", "tracker.bad.org"
        )
        request = _make_request("innocent.com")
        response = self.resolver.resolve(request, None)
        assert str(response.rr[0].rdata) == "0.0.0.0"
        assert self.stats.blocked_queries == 1
        assert self.stats.cname_blocks == 1

    @patch("coreguard.dns_server.resolve_upstream")
    def test_clean_cname_chain(self, mock_upstream):
        """A CNAME chain to a clean target should be allowed."""
        mock_upstream.return_value = _make_cname_response(
            "cdn.example.com", "safe.cdn.net", "93.184.216.34"
        )
        request = _make_request("cdn.example.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.blocked_queries == 0
        assert self.stats.cname_blocks == 0

    @patch("coreguard.dns_server.resolve_upstream")
    def test_cname_check_disabled(self, mock_upstream):
        """When cname_check_enabled=False, CNAME targets are not checked."""
        self.config.cname_check_enabled = False
        mock_upstream.return_value = _make_cname_response(
            "innocent.com", "tracker.bad.org"
        )
        request = _make_request("innocent.com")
        response = self.resolver.resolve(request, None)
        # Should pass through — not blocked
        assert self.stats.blocked_queries == 0
        assert self.stats.cname_blocks == 0

    @patch("coreguard.dns_server.resolve_upstream")
    def test_cname_depth_cap(self, mock_upstream):
        """CNAME checking stops after cname_max_depth."""
        self.config.cname_max_depth = 1
        # Build response with 2 CNAME records, second one is blocked
        req = DNSRecord.question("deep.com")
        reply = req.reply()
        reply.add_answer(RR("deep.com", QTYPE.CNAME, rdata=CNAME("hop1.com"), ttl=300))
        reply.add_answer(RR("hop1.com", QTYPE.CNAME, rdata=CNAME("tracker.bad.org"), ttl=300))
        reply.add_answer(RR("tracker.bad.org", QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        mock_upstream.return_value = reply.pack()

        request = _make_request("deep.com")
        response = self.resolver.resolve(request, None)
        # Only 1 CNAME checked (hop1.com is clean), tracker.bad.org is beyond depth
        assert self.stats.cname_blocks == 0


class TestCacheIntegration:
    def setup_method(self):
        self.domain_filter = DomainFilter()
        self.domain_filter.load_blocklist(["ads.example.com"])
        self.config = Config()
        self.config.cache_enabled = True
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.cache = DNSCache(max_entries=100, max_ttl=3600, min_ttl=0)
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger, self.cache
        )

    @patch("coreguard.dns_server.resolve_upstream")
    def test_cache_hit_skips_upstream(self, mock_upstream):
        """Second query for same domain should hit cache, not upstream."""
        mock_upstream.return_value = _make_upstream_response("github.com")

        request1 = _make_request("github.com")
        self.resolver.resolve(request1, None)
        assert mock_upstream.call_count == 1

        request2 = _make_request("github.com")
        self.resolver.resolve(request2, None)
        # Upstream should NOT be called again
        assert mock_upstream.call_count == 1
        assert self.stats.cache_hits == 1

    @patch("coreguard.dns_server.resolve_upstream")
    def test_cache_miss_calls_upstream(self, mock_upstream):
        """First query should miss cache and call upstream."""
        mock_upstream.return_value = _make_upstream_response("github.com")

        request = _make_request("github.com")
        self.resolver.resolve(request, None)
        mock_upstream.assert_called_once()
        assert self.stats.cache_misses == 1

    @patch("coreguard.dns_server.resolve_upstream")
    def test_servfail_not_cached(self, mock_upstream):
        """SERVFAIL responses should not be cached."""
        mock_upstream.side_effect = Exception("timeout")

        request = _make_request("github.com")
        self.resolver.resolve(request, None)
        assert self.cache.size == 0

    def test_blocklist_checked_before_cache(self):
        """A newly-blocked domain should be blocked even if cached."""
        # Pre-populate cache with a clean response for a domain
        from coreguard.cache import DNSCache

        resp = DNSRecord.question("new-blocked.com").reply()
        resp.add_answer(RR("new-blocked.com", QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
        self.cache.put("new-blocked.com", QTYPE.A, resp)

        # Now add it to the blocklist
        self.domain_filter.load_blocklist(["ads.example.com", "new-blocked.com"])

        request = _make_request("new-blocked.com")
        response = self.resolver.resolve(request, None)
        # Should be blocked, not served from cache
        assert str(response.rr[0].rdata) == "0.0.0.0"
        assert self.stats.blocked_queries == 1

    @patch("coreguard.dns_server.resolve_upstream")
    def test_blocked_response_cached(self, mock_upstream):
        """Blocked responses should be cached."""
        request = _make_request("ads.example.com")
        self.resolver.resolve(request, None)
        assert self.cache.size == 1

    @patch("coreguard.dns_server.resolve_upstream")
    def test_no_cache_resolver_works(self, mock_upstream):
        """Resolver works fine without a cache (cache=None)."""
        resolver_no_cache = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger, cache=None
        )
        mock_upstream.return_value = _make_upstream_response("github.com")

        request = _make_request("github.com")
        response = resolver_no_cache.resolve(request, None)
        assert self.stats.total_queries == 1
        assert self.stats.cache_hits == 0


class TestSafeSearch:
    def setup_method(self):
        self.domain_filter = DomainFilter()
        self.config = Config()
        self.config.safe_search_enabled = True
        self.stats = Stats()
        self.query_logger = MagicMock()
        self.resolver = BlockingResolver(
            self.domain_filter, self.config, self.stats, self.query_logger
        )

    def test_google_rewritten(self):
        """Google queries should be rewritten to forcesafesearch.google.com."""
        request = _make_request("www.google.com")
        response = self.resolver.resolve(request, None)
        assert len(response.rr) == 1
        assert response.rr[0].rtype == QTYPE.CNAME
        assert str(response.rr[0].rdata) == "forcesafesearch.google.com."
        assert self.stats.total_queries == 1
        assert self.stats.blocked_queries == 0

    @patch("coreguard.dns_server.resolve_upstream")
    def test_non_search_forwarded_normally(self, mock_upstream):
        """Non-search domains should be forwarded normally."""
        mock_upstream.return_value = _make_upstream_response("github.com", "140.82.121.4")
        request = _make_request("github.com")
        response = self.resolver.resolve(request, None)
        assert self.stats.blocked_queries == 0
        mock_upstream.assert_called_once()

    @patch("coreguard.dns_server.resolve_upstream")
    def test_safe_search_disabled_no_rewrite(self, mock_upstream):
        """When safe_search_enabled=False, Google should not be rewritten."""
        self.config.safe_search_enabled = False
        mock_upstream.return_value = _make_upstream_response("www.google.com", "142.250.80.4")
        request = _make_request("www.google.com")
        response = self.resolver.resolve(request, None)
        # Should go to upstream, not rewritten
        mock_upstream.assert_called_once()

    def test_youtube_moderate(self):
        """YouTube should be rewritten to restrict.youtube.com by default."""
        self.config.safe_search_youtube_restrict = "moderate"
        request = _make_request("www.youtube.com")
        response = self.resolver.resolve(request, None)
        assert str(response.rr[0].rdata) == "restrict.youtube.com."

    def test_youtube_strict(self):
        """YouTube strict mode should use restrictmoderate.youtube.com."""
        self.config.safe_search_youtube_restrict = "strict"
        request = _make_request("www.youtube.com")
        response = self.resolver.resolve(request, None)
        assert str(response.rr[0].rdata) == "restrictmoderate.youtube.com."

    def test_bing_rewritten(self):
        request = _make_request("www.bing.com")
        response = self.resolver.resolve(request, None)
        assert str(response.rr[0].rdata) == "strict.bing.com."
