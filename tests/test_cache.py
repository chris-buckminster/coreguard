import threading
from unittest.mock import patch

from dnslib import QTYPE, RR, A, AAAA, DNSRecord

from coreguard.cache import DNSCache


def _make_response(domain="example.com", qtype=QTYPE.A, ip="1.2.3.4", ttl=300):
    """Build a simple DNS response for testing."""
    q = DNSRecord.question(domain)
    reply = q.reply()
    if qtype == QTYPE.A:
        reply.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=ttl))
    elif qtype == QTYPE.AAAA:
        reply.add_answer(RR(domain, QTYPE.AAAA, rdata=AAAA("::1"), ttl=ttl))
    return reply


class TestDNSCache:
    def setup_method(self):
        self.cache = DNSCache(max_entries=100, max_ttl=3600, min_ttl=0)

    def test_put_and_get(self):
        resp = _make_response()
        self.cache.put("example.com", QTYPE.A, resp)
        cached = self.cache.get("example.com", QTYPE.A)
        assert cached is not None
        assert len(cached.rr) == 1
        assert str(cached.rr[0].rdata) == "1.2.3.4"

    def test_miss_returns_none(self):
        assert self.cache.get("missing.com", QTYPE.A) is None

    def test_expired_entry_returns_none(self):
        resp = _make_response(ttl=300)
        self.cache.put("example.com", QTYPE.A, resp)
        # Simulate time passing beyond TTL
        with patch("coreguard.cache.time.monotonic", return_value=1e9):
            assert self.cache.get("example.com", QTYPE.A) is None

    def test_ttl_adjustment(self):
        resp = _make_response(ttl=300)
        base_time = 1000.0
        with patch("coreguard.cache.time.monotonic", return_value=base_time):
            self.cache.put("example.com", QTYPE.A, resp)
        # 100 seconds later
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 100):
            cached = self.cache.get("example.com", QTYPE.A)
            assert cached is not None
            assert cached.rr[0].ttl == 200  # 300 - 100

    def test_max_ttl_cap(self):
        cache = DNSCache(max_ttl=60)
        resp = _make_response(ttl=7200)
        base_time = 1000.0
        with patch("coreguard.cache.time.monotonic", return_value=base_time):
            cache.put("example.com", QTYPE.A, resp)
        # After 60 seconds it should be expired (capped to 60)
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 61):
            assert cache.get("example.com", QTYPE.A) is None

    def test_min_ttl_floor(self):
        cache = DNSCache(min_ttl=60)
        resp = _make_response(ttl=5)
        base_time = 1000.0
        with patch("coreguard.cache.time.monotonic", return_value=base_time):
            cache.put("example.com", QTYPE.A, resp)
        # After 30 seconds it should still be cached (floor is 60)
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 30):
            assert cache.get("example.com", QTYPE.A) is not None

    def test_max_entries_eviction(self):
        cache = DNSCache(max_entries=5)
        for i in range(10):
            resp = _make_response(domain=f"d{i}.com", ip=f"1.2.3.{i}")
            cache.put(f"d{i}.com", QTYPE.A, resp)
        assert cache.size == 5

    def test_sweep_expired(self):
        base_time = 1000.0
        with patch("coreguard.cache.time.monotonic", return_value=base_time):
            self.cache.put("short.com", QTYPE.A, _make_response(domain="short.com", ttl=10))
            self.cache.put("long.com", QTYPE.A, _make_response(domain="long.com", ttl=600))
        assert self.cache.size == 2
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 20):
            removed = self.cache.sweep_expired()
            assert removed == 1
            assert self.cache.size == 1

    def test_clear(self):
        self.cache.put("a.com", QTYPE.A, _make_response(domain="a.com"))
        self.cache.put("b.com", QTYPE.A, _make_response(domain="b.com"))
        assert self.cache.size == 2
        self.cache.clear()
        assert self.cache.size == 0

    def test_case_insensitive_key(self):
        self.cache.put("Example.COM", QTYPE.A, _make_response())
        assert self.cache.get("example.com", QTYPE.A) is not None

    def test_defensive_copy_on_get(self):
        self.cache.put("example.com", QTYPE.A, _make_response())
        cached1 = self.cache.get("example.com", QTYPE.A)
        cached1.header.id = 9999
        cached2 = self.cache.get("example.com", QTYPE.A)
        assert cached2.header.id != 9999

    def test_defensive_copy_on_put(self):
        resp = _make_response()
        self.cache.put("example.com", QTYPE.A, resp)
        resp.header.id = 9999
        cached = self.cache.get("example.com", QTYPE.A)
        assert cached.header.id != 9999

    def test_blocked_response_ttl(self):
        resp = _make_response(ttl=300)
        base_time = 1000.0
        with patch("coreguard.cache.time.monotonic", return_value=base_time):
            self.cache.put("blocked.com", QTYPE.A, resp, is_blocked=True)
        # Should be cached with TTL=300 regardless of response TTL
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 299):
            assert self.cache.get("blocked.com", QTYPE.A) is not None
        with patch("coreguard.cache.time.monotonic", return_value=base_time + 301):
            assert self.cache.get("blocked.com", QTYPE.A) is None

    def test_zero_ttl_not_cached(self):
        # Response with no answer records and no SOA → TTL=0 → not cached
        q = DNSRecord.question("empty.com")
        reply = q.reply()  # no answer records
        self.cache.put("empty.com", QTYPE.A, reply)
        assert self.cache.size == 0

    def test_separate_qtypes(self):
        self.cache.put("example.com", QTYPE.A, _make_response())
        self.cache.put("example.com", QTYPE.AAAA, _make_response(qtype=QTYPE.AAAA))
        assert self.cache.get("example.com", QTYPE.A) is not None
        assert self.cache.get("example.com", QTYPE.AAAA) is not None
        assert self.cache.size == 2

    def test_thread_safety(self):
        errors = []

        def worker(n):
            try:
                for i in range(50):
                    domain = f"t{n}-{i}.com"
                    self.cache.put(domain, QTYPE.A, _make_response(domain=domain))
                    self.cache.get(domain, QTYPE.A)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
