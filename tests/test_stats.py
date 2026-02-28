"""Tests for stats.py — query statistics tracking."""

import json
import threading
from pathlib import Path

from coreguard.stats import Stats, MAX_TRACKED_DOMAINS


class TestRecordQuery:
    def test_basic_counting(self):
        stats = Stats()
        stats.record_query("a.com", blocked=False)
        stats.record_query("b.com", blocked=True)
        stats.record_query("c.com", blocked=False, error=True)
        assert stats.total_queries == 3
        assert stats.blocked_queries == 1
        assert stats.error_queries == 1

    def test_top_blocked_tracked(self):
        stats = Stats()
        stats.record_query("ads.com", blocked=True)
        stats.record_query("ads.com", blocked=True)
        stats.record_query("tracker.com", blocked=True)
        assert stats.top_blocked["ads.com"] == 2
        assert stats.top_blocked["tracker.com"] == 1

    def test_top_queried_tracked(self):
        stats = Stats()
        stats.record_query("google.com", blocked=False)
        stats.record_query("google.com", blocked=False)
        stats.record_query("github.com", blocked=False)
        assert stats.top_queried["google.com"] == 2
        assert stats.top_queried["github.com"] == 1

    def test_query_types(self):
        stats = Stats()
        stats.record_query("a.com", blocked=False, qtype="A")
        stats.record_query("a.com", blocked=False, qtype="A")
        stats.record_query("a.com", blocked=False, qtype="AAAA")
        assert stats.query_types["A"] == 2
        assert stats.query_types["AAAA"] == 1

    def test_client_tracking(self):
        stats = Stats()
        stats.record_query("a.com", blocked=False, client_ip="10.0.0.1")
        stats.record_query("b.com", blocked=False, client_ip="10.0.0.1")
        stats.record_query("c.com", blocked=False, client_ip="10.0.0.2")
        assert stats.top_clients["10.0.0.1"] == 2
        assert stats.top_clients["10.0.0.2"] == 1

    def test_none_qtype_and_client_ignored(self):
        stats = Stats()
        stats.record_query("a.com", blocked=False, qtype=None, client_ip=None)
        assert len(stats.query_types) == 0
        assert len(stats.top_clients) == 0


class TestCacheAndDnssec:
    def test_cache_hit_miss(self):
        stats = Stats()
        stats.record_cache_hit()
        stats.record_cache_hit()
        stats.record_cache_miss()
        assert stats.cache_hits == 2
        assert stats.cache_misses == 1

    def test_cname_block(self):
        stats = Stats()
        stats.record_cname_block()
        stats.record_cname_block()
        assert stats.cname_blocks == 2

    def test_dnssec_validated(self):
        stats = Stats()
        stats.record_dnssec(validated=True)
        stats.record_dnssec(validated=False)
        assert stats.dnssec_validated == 1
        assert stats.dnssec_failed == 1


class TestUpstreamLatency:
    def test_basic_recording(self):
        stats = Stats()
        stats.record_upstream_latency(0.05)
        snap = stats.latency_snapshot()
        assert snap["count"] == 1
        assert snap["sum"] == 0.05

    def test_bucket_boundaries(self):
        stats = Stats()
        # 0.005 bucket — value at boundary
        stats.record_upstream_latency(0.005)
        snap = stats.latency_snapshot()
        assert snap["counts"][0] == 1  # <= 0.005

    def test_small_latency_in_first_bucket(self):
        stats = Stats()
        stats.record_upstream_latency(0.001)
        snap = stats.latency_snapshot()
        assert snap["counts"][0] == 1

    def test_large_latency_in_last_bucket(self):
        stats = Stats()
        stats.record_upstream_latency(9.0)
        snap = stats.latency_snapshot()
        # 9.0 <= 10.0 (last bucket)
        assert snap["counts"][-1] == 1

    def test_beyond_all_buckets(self):
        stats = Stats()
        stats.record_upstream_latency(100.0)
        snap = stats.latency_snapshot()
        # Beyond all buckets — total should be recorded but no bucket incremented
        assert snap["count"] == 1
        assert snap["sum"] == 100.0
        assert sum(snap["counts"]) == 0

    def test_multiple_recordings(self):
        stats = Stats()
        stats.record_upstream_latency(0.01)
        stats.record_upstream_latency(0.1)
        stats.record_upstream_latency(1.0)
        snap = stats.latency_snapshot()
        assert snap["count"] == 3
        assert abs(snap["sum"] - 1.11) < 0.001


class TestTrim:
    def test_trim_caps_counters(self):
        stats = Stats()
        # Exceed MAX_TRACKED_DOMAINS
        for i in range(MAX_TRACKED_DOMAINS + 100):
            stats.record_query(f"d{i}.com", blocked=True)
        assert len(stats.top_queried) == MAX_TRACKED_DOMAINS + 100
        stats.trim()
        assert len(stats.top_queried) == MAX_TRACKED_DOMAINS
        assert len(stats.top_blocked) == MAX_TRACKED_DOMAINS

    def test_trim_below_threshold_noop(self):
        stats = Stats()
        for i in range(10):
            stats.record_query(f"d{i}.com", blocked=False)
        stats.trim()
        assert len(stats.top_queried) == 10


class TestToDict:
    def test_empty_stats(self):
        stats = Stats()
        d = stats.to_dict()
        assert d["total_queries"] == 0
        assert d["blocked_queries"] == 0
        assert d["blocked_percent"] == 0.0
        assert d["cache_hit_rate"] == 0.0

    def test_blocked_percent(self):
        stats = Stats()
        for i in range(10):
            stats.record_query(f"d{i}.com", blocked=(i < 3))
        d = stats.to_dict()
        assert d["total_queries"] == 10
        assert d["blocked_queries"] == 3
        assert d["blocked_percent"] == 30.0

    def test_cache_hit_rate(self):
        stats = Stats()
        for _ in range(7):
            stats.record_cache_hit()
        for _ in range(3):
            stats.record_cache_miss()
        d = stats.to_dict()
        assert d["cache_hit_rate"] == 70.0

    def test_top_blocked_limited_to_10(self):
        stats = Stats()
        for i in range(20):
            stats.record_query(f"d{i}.com", blocked=True)
        d = stats.to_dict()
        assert len(d["top_blocked"]) == 10

    def test_top_queried_limited_to_10(self):
        stats = Stats()
        for i in range(20):
            stats.record_query(f"d{i}.com", blocked=False)
        d = stats.to_dict()
        assert len(d["top_queried"]) == 10


class TestSaveAndLoad:
    def test_save_creates_file(self, tmp_path):
        stats = Stats()
        stats.record_query("a.com", blocked=True)
        path = tmp_path / "stats.json"
        stats.save(path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["total_queries"] == 1

    def test_load_from_file(self, tmp_path):
        path = tmp_path / "stats.json"
        path.write_text(json.dumps({"total_queries": 42, "blocked_queries": 10}))
        data = Stats.load_from_file(path)
        assert data["total_queries"] == 42
        assert data["blocked_queries"] == 10

    def test_load_missing_file(self, tmp_path):
        data = Stats.load_from_file(tmp_path / "nonexistent.json")
        assert data["total_queries"] == 0

    def test_load_corrupt_file(self, tmp_path):
        path = tmp_path / "stats.json"
        path.write_text("not valid json{{{")
        data = Stats.load_from_file(path)
        assert data["total_queries"] == 0

    def test_save_roundtrip(self, tmp_path):
        stats = Stats()
        stats.record_query("a.com", blocked=True, qtype="A", client_ip="10.0.0.1")
        stats.record_cache_hit()
        path = tmp_path / "stats.json"
        stats.save(path)
        loaded = Stats.load_from_file(path)
        assert loaded["total_queries"] == 1
        assert loaded["blocked_queries"] == 1
        assert loaded["cache_hits"] == 1


class TestConcurrentAccess:
    def test_concurrent_record_query(self):
        stats = Stats()
        errors = []

        def worker(n):
            try:
                for i in range(100):
                    stats.record_query(f"d{n}-{i}.com", blocked=(i % 2 == 0), qtype="A")
                    stats.record_cache_hit()
                    stats.record_cache_miss()
                    stats.record_upstream_latency(0.01 * n)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert stats.total_queries == 500
        assert stats.blocked_queries == 250
        assert stats.cache_hits == 500
        assert stats.cache_misses == 500
