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
