from dnslib import DNSRecord, QTYPE

from coreguard.safesearch import get_safe_search_target, make_safe_search_response


class TestGetSafeSearchTarget:
    def test_google_com(self):
        assert get_safe_search_target("www.google.com") == "forcesafesearch.google.com"

    def test_google_country_variant_uk(self):
        assert get_safe_search_target("www.google.co.uk") == "forcesafesearch.google.com"

    def test_google_country_variant_de(self):
        assert get_safe_search_target("www.google.de") == "forcesafesearch.google.com"

    def test_google_country_variant_com_au(self):
        assert get_safe_search_target("www.google.com.au") == "forcesafesearch.google.com"

    def test_youtube_moderate(self):
        assert get_safe_search_target("www.youtube.com", "moderate") == "restrict.youtube.com"

    def test_youtube_strict(self):
        assert get_safe_search_target("www.youtube.com", "strict") == "restrictmoderate.youtube.com"

    def test_bing(self):
        assert get_safe_search_target("www.bing.com") == "strict.bing.com"

    def test_duckduckgo(self):
        assert get_safe_search_target("duckduckgo.com") == "safe.duckduckgo.com"

    def test_non_search_domain_returns_none(self):
        assert get_safe_search_target("github.com") is None
        assert get_safe_search_target("example.com") is None
        assert get_safe_search_target("google.com") is None  # without www.

    def test_case_insensitive(self):
        assert get_safe_search_target("WWW.GOOGLE.COM") == "forcesafesearch.google.com"
        assert get_safe_search_target("Www.Bing.Com") == "strict.bing.com"

    def test_trailing_dot_stripped(self):
        assert get_safe_search_target("www.google.com.") == "forcesafesearch.google.com"


class TestMakeSafeSearchResponse:
    def test_response_contains_cname(self):
        request = DNSRecord.question("www.google.com")
        response = make_safe_search_response(request, "forcesafesearch.google.com")
        assert len(response.rr) == 1
        assert response.rr[0].rtype == QTYPE.CNAME
        assert str(response.rr[0].rdata) == "forcesafesearch.google.com."

    def test_response_preserves_query_name(self):
        request = DNSRecord.question("www.bing.com")
        response = make_safe_search_response(request, "strict.bing.com")
        assert str(response.q.qname) == "www.bing.com."
