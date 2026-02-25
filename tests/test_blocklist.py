from pathlib import Path

from coreguard.blocklist import (
    detect_and_parse,
    parse_adblock_list,
    parse_hosts_file,
    parse_domain_list,
    load_custom_list,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseHostsFile:
    def test_basic_parsing(self):
        content = FIXTURES.joinpath("sample_hosts.txt").read_text()
        domains = parse_hosts_file(content)
        assert "ads.example.com" in domains
        assert "tracker.example.com" in domains
        assert "malware.bad-site.org" in domains
        assert "analytics.spyware.net" in domains
        assert "popup.adnetwork.com" in domains
        assert "banner.ads.co" in domains

    def test_skips_localhost(self):
        content = FIXTURES.joinpath("sample_hosts.txt").read_text()
        domains = parse_hosts_file(content)
        assert "localhost" not in domains
        assert "localhost.localdomain" not in domains

    def test_skips_comments_and_blanks(self):
        content = "# comment\n\n0.0.0.0 blocked.com\n"
        domains = parse_hosts_file(content)
        assert domains == {"blocked.com"}

    def test_handles_127(self):
        content = "127.0.0.1 trackme.com\n"
        domains = parse_hosts_file(content)
        assert "trackme.com" in domains


class TestParseAdblockList:
    def test_basic_parsing(self):
        content = FIXTURES.joinpath("sample_adblock.txt").read_text()
        blocked, allowed = parse_adblock_list(content)
        assert "ads.example.com" in blocked
        assert "tracker.example.com" in blocked
        assert "safe.ads.example.com" in allowed
        assert "analytics.mysite.com" in allowed

    def test_skips_modifier_lines(self):
        content = FIXTURES.joinpath("sample_adblock.txt").read_text()
        blocked, allowed = parse_adblock_list(content)
        assert "complex.example.com" not in blocked

    def test_skips_comments(self):
        content = "! comment\n||blocked.com^\n"
        blocked, _ = parse_adblock_list(content)
        assert blocked == {"blocked.com"}


class TestParseDomainList:
    def test_plain_domains(self):
        content = "foo.com\nbar.org\n# comment\nbaz.net\n"
        domains = parse_domain_list(content)
        assert domains == {"foo.com", "bar.org", "baz.net"}


class TestDetectAndParse:
    def test_detects_hosts_format(self):
        content = "# comment\n0.0.0.0 ads.com\n0.0.0.0 track.com\n"
        blocked, allowed = detect_and_parse(content)
        assert "ads.com" in blocked
        assert len(allowed) == 0

    def test_detects_adblock_format(self):
        content = "! comment\n||ads.com^\n@@||safe.com^\n"
        blocked, allowed = detect_and_parse(content)
        assert "ads.com" in blocked
        assert "safe.com" in allowed

    def test_detects_domain_list(self):
        content = "ads.com\ntrack.com\n"
        blocked, allowed = detect_and_parse(content)
        assert "ads.com" in blocked
        assert "track.com" in blocked


class TestLoadCustomList:
    def test_loads_domains(self, tmp_path):
        f = tmp_path / "custom.txt"
        f.write_text("foo.com\nbar.org\n# comment\n")
        domains = load_custom_list(f)
        assert domains == {"foo.com", "bar.org"}

    def test_missing_file(self, tmp_path):
        f = tmp_path / "missing.txt"
        domains = load_custom_list(f)
        assert domains == set()
