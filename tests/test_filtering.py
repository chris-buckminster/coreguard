from coreguard.filtering import DomainFilter


class TestDomainFilter:
    def setup_method(self):
        self.f = DomainFilter()
        self.f.load_blocklist([
            "ads.example.com",
            "tracker.example.com",
            "malware.bad-site.org",
        ])

    def test_exact_match_blocked(self):
        assert self.f.is_blocked("ads.example.com") is True
        assert self.f.is_blocked("tracker.example.com") is True

    def test_subdomain_blocked(self):
        assert self.f.is_blocked("foo.ads.example.com") is True
        assert self.f.is_blocked("deep.nested.tracker.example.com") is True

    def test_parent_domain_not_blocked(self):
        assert self.f.is_blocked("example.com") is False

    def test_unrelated_domain_not_blocked(self):
        assert self.f.is_blocked("github.com") is False
        assert self.f.is_blocked("google.com") is False

    def test_case_insensitive(self):
        assert self.f.is_blocked("ADS.EXAMPLE.COM") is True
        assert self.f.is_blocked("Ads.Example.Com") is True

    def test_trailing_dot_stripped(self):
        assert self.f.is_blocked("ads.example.com.") is True

    def test_empty_domain(self):
        assert self.f.is_blocked("") is False

    def test_allowlist_overrides_blocklist(self):
        self.f.load_allowlist(["ads.example.com"])
        assert self.f.is_blocked("ads.example.com") is False

    def test_allowlist_subdomain_override(self):
        # Allow parent domain, should allow subdomains too
        self.f.load_allowlist(["tracker.example.com"])
        assert self.f.is_blocked("tracker.example.com") is False
        assert self.f.is_blocked("sub.tracker.example.com") is False

    def test_blocked_count(self):
        assert self.f.blocked_count == 3

    def test_clear(self):
        self.f.clear()
        assert self.f.blocked_count == 0
        assert self.f.is_blocked("ads.example.com") is False


class TestWildcardRules:
    def setup_method(self):
        self.f = DomainFilter()

    def test_star_dot_prefix(self):
        """*.ads.com matches subdomains but not ads.com itself."""
        self.f.load_blocklist_wildcards(["*.ads.com"])
        assert self.f.is_blocked("foo.ads.com") is True
        assert self.f.is_blocked("bar.baz.ads.com") is True
        assert self.f.is_blocked("ads.com") is False

    def test_prefix_pattern(self):
        """ad*.example.com matches ad-prefixed subdomains."""
        self.f.load_blocklist_wildcards(["ad*.example.com"])
        assert self.f.is_blocked("ads.example.com") is True
        assert self.f.is_blocked("adserver.example.com") is True
        assert self.f.is_blocked("tracker.example.com") is False

    def test_mid_pattern(self):
        """tracking.*.example.com matches any label in the middle."""
        self.f.load_blocklist_wildcards(["tracking.*.example.com"])
        assert self.f.is_blocked("tracking.cdn.example.com") is True
        assert self.f.is_blocked("tracking.us.example.com") is True
        assert self.f.is_blocked("tracking.example.com") is False

    def test_wildcard_allowlist_overrides(self):
        """Wildcard allowlist takes priority over wildcard blocklist."""
        self.f.load_blocklist_wildcards(["*.ads.com"])
        self.f.load_allowlist_wildcards(["safe.*.com"])
        assert self.f.is_blocked("foo.ads.com") is True
        assert self.f.is_blocked("safe.ads.com") is False

    def test_wildcard_clear(self):
        """clear() removes wildcards too."""
        self.f.load_blocklist_wildcards(["*.ads.com"])
        assert self.f.is_blocked("foo.ads.com") is True
        self.f.clear()
        assert self.f.is_blocked("foo.ads.com") is False

    def test_mixed_plain_and_wildcard(self):
        """Plain blocklist and wildcard patterns work together."""
        self.f.load_blocklist(["tracker.example.com"])
        self.f.load_blocklist_wildcards(["ad*.example.com"])
        assert self.f.is_blocked("tracker.example.com") is True
        assert self.f.is_blocked("ads.example.com") is True
        assert self.f.is_blocked("clean.example.com") is False

    def test_wildcard_case_insensitive(self):
        """Wildcard matching is case-insensitive."""
        self.f.load_blocklist_wildcards(["*.ADS.COM"])
        assert self.f.is_blocked("foo.ads.com") is True
        assert self.f.is_blocked("FOO.ADS.COM") is True
