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


class TestRegexRules:
    def setup_method(self):
        self.f = DomainFilter()

    def test_basic_regex_match(self):
        """Regex patterns match domains."""
        self.f.load_blocklist_regex([r"^ads\..*\.com$"])
        assert self.f.is_blocked("ads.example.com") is True
        assert self.f.is_blocked("ads.foo.com") is True
        assert self.f.is_blocked("notads.example.com") is False

    def test_regex_allow_overrides_block(self):
        """Regex allowlist takes priority over regex blocklist."""
        self.f.load_blocklist_regex([r"track(er|ing)\.\w+\.net$"])
        self.f.load_allowlist_regex([r"tracker\.safe\.net$"])
        assert self.f.is_blocked("tracker.bad.net") is True
        assert self.f.is_blocked("tracking.spy.net") is True
        assert self.f.is_blocked("tracker.safe.net") is False

    def test_invalid_regex_skipped(self):
        """Invalid regex patterns are silently skipped."""
        self.f.load_blocklist_regex([r"[invalid", r"^valid\.com$"])
        assert self.f.is_blocked("valid.com") is True
        assert self.f.regex_count == 1  # only the valid one

    def test_regex_case_insensitive(self):
        """Regex matching is case-insensitive."""
        self.f.load_blocklist_regex([r"^ADS\.EXAMPLE\.COM$"])
        assert self.f.is_blocked("ads.example.com") is True
        assert self.f.is_blocked("ADS.EXAMPLE.COM") is True

    def test_clear_resets_regex(self):
        """clear() removes regex patterns too."""
        self.f.load_blocklist_regex([r"^ads\..*\.com$"])
        assert self.f.is_blocked("ads.foo.com") is True
        self.f.clear()
        assert self.f.is_blocked("ads.foo.com") is False
        assert self.f.regex_count == 0

    def test_regex_with_plain_and_wildcard(self):
        """Regex, plain, and wildcard rules work together."""
        self.f.load_blocklist(["exact.com"])
        self.f.load_blocklist_wildcards(["*.wild.com"])
        self.f.load_blocklist_regex([r"^regex\d+\.com$"])
        assert self.f.is_blocked("exact.com") is True
        assert self.f.is_blocked("foo.wild.com") is True
        assert self.f.is_blocked("regex123.com") is True
        assert self.f.is_blocked("clean.com") is False

    def test_regex_count_property(self):
        """regex_count returns total of blocked + allowed regex patterns."""
        self.f.load_blocklist_regex([r"^a\.com$", r"^b\.com$"])
        self.f.load_allowlist_regex([r"^c\.com$"])
        assert self.f.regex_count == 3


class TestScheduleOverlay:
    def setup_method(self):
        self.f = DomainFilter()

    def test_snapshot_restore_preserves_base(self):
        """snapshot_base() and restore_base() preserve the original state."""
        self.f.load_blocklist(["base.com"])
        self.f.load_blocklist_wildcards(["*.base-wild.com"])
        self.f.load_blocklist_regex([r"^base-regex\.com$"])
        self.f.snapshot_base()

        # Add overlay
        self.f.load_blocklist(["overlay.com"])
        assert self.f.is_blocked("overlay.com") is True

        # Restore should remove overlay
        self.f.restore_base()
        assert self.f.is_blocked("base.com") is True
        assert self.f.is_blocked("foo.base-wild.com") is True
        assert self.f.is_blocked("base-regex.com") is True
        assert self.f.is_blocked("overlay.com") is False

    def test_apply_schedule_overlay_adds_blocks(self):
        """apply_schedule_overlay adds domains on top of base."""
        self.f.load_blocklist(["base.com"])
        self.f.snapshot_base()

        self.f.apply_schedule_overlay(
            ["schedule-block.com"],
            ["*.schedule-wild.com"],
            [r"^schedule-regex\.com$"],
        )
        assert self.f.is_blocked("base.com") is True
        assert self.f.is_blocked("schedule-block.com") is True
        assert self.f.is_blocked("foo.schedule-wild.com") is True
        assert self.f.is_blocked("schedule-regex.com") is True

    def test_restore_removes_overlay(self):
        """restore_base() removes schedule overlay blocks."""
        self.f.load_blocklist(["base.com"])
        self.f.snapshot_base()

        self.f.apply_schedule_overlay(["overlay.com"], [], [])
        assert self.f.is_blocked("overlay.com") is True

        self.f.restore_base()
        assert self.f.is_blocked("overlay.com") is False
        assert self.f.is_blocked("base.com") is True


class TestConcurrency:
    def test_concurrent_reads_during_mutation(self):
        """Multiple threads calling is_blocked() while main thread mutates should not crash."""
        import threading

        f = DomainFilter()
        f.load_blocklist([f"d{i}.com" for i in range(1000)])
        errors = []

        def reader():
            try:
                for _ in range(200):
                    f.is_blocked("d500.com")
                    f.is_blocked("unknown.com")
                    f.is_blocked("sub.d100.com")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()

        # Mutate while readers are running
        for i in range(50):
            f.clear()
            f.load_blocklist([f"new{i}-{j}.com" for j in range(100)])

        for t in threads:
            t.join()

        assert not errors, f"Concurrent access errors: {errors}"
