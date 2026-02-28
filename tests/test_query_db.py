"""Tests for SQLite-backed query logging."""

import sqlite3
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from coreguard.query_db import QueryDB


class TestQueryDBSchema:
    def test_creates_database(self, tmp_path):
        db_path = tmp_path / "queries.db"
        db = QueryDB(db_path)
        assert db_path.exists()
        db.close()

    def test_creates_tables(self, tmp_path):
        db_path = tmp_path / "queries.db"
        db = QueryDB(db_path)
        # Check schema by inserting and querying
        db.log_query("example.com", "A", blocked=False, client_ip="127.0.0.1")
        db.flush()
        rows, total = db.get_recent_queries(10)
        assert total == 1
        assert rows[0]["domain"] == "example.com"
        db.close()


class TestQueryDBCRUD:
    def setup_method(self, method, tmp_path=None):
        pass  # Use tmp_path in each test

    def test_log_and_retrieve(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db.log_query("a.com", "A", blocked=True, client_ip="10.0.0.1")
        db.log_query("b.com", "AAAA", blocked=False, client_ip="10.0.0.2")
        db.flush()

        rows, total = db.get_recent_queries(10)
        assert total == 2
        # Most recent first
        assert rows[0]["domain"] == "b.com"
        assert rows[0]["status"] == "ALLOWED"
        assert rows[0]["type"] == "AAAA"
        assert rows[0]["client"] == "10.0.0.2"
        assert rows[1]["domain"] == "a.com"
        assert rows[1]["status"] == "BLOCKED"
        db.close()

    def test_batch_auto_flush(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db._batch_size = 5
        for i in range(5):
            db.log_query(f"d{i}.com", "A", blocked=False)
        # Batch should have auto-flushed at 5
        assert len(db._batch) == 0
        assert db.get_total_count() == 5
        db.close()

    def test_pagination(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        for i in range(10):
            db.log_query(f"d{i}.com", "A", blocked=False)
        db.flush()

        rows, total = db.get_recent_queries(limit=3, offset=0)
        assert len(rows) == 3
        assert total == 10

        rows2, _ = db.get_recent_queries(limit=3, offset=3)
        assert len(rows2) == 3
        assert rows[0]["domain"] != rows2[0]["domain"]
        db.close()

    def test_filter_by_status(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db.log_query("blocked.com", "A", blocked=True)
        db.log_query("allowed.com", "A", blocked=False)
        db.flush()

        rows, total = db.get_recent_queries(10, status="BLOCKED")
        assert total == 1
        assert rows[0]["domain"] == "blocked.com"
        db.close()

    def test_filter_by_domain(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db.log_query("ads.example.com", "A", blocked=True)
        db.log_query("good.example.com", "A", blocked=False)
        db.log_query("other.net", "A", blocked=False)
        db.flush()

        rows, total = db.get_recent_queries(10, domain="example")
        assert total == 2
        db.close()

    def test_filter_by_client(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db.log_query("a.com", "A", blocked=False, client_ip="10.0.0.1")
        db.log_query("b.com", "A", blocked=False, client_ip="10.0.0.2")
        db.flush()

        rows, total = db.get_recent_queries(10, client_ip="10.0.0.1")
        assert total == 1
        assert rows[0]["domain"] == "a.com"
        db.close()

    def test_time_range_queries(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        now = time.time()
        # Insert with specific timestamps
        db._batch.append((now - 7200, "old.com", "A", "ALLOWED", ""))
        db._batch.append((now - 3600, "mid.com", "A", "ALLOWED", ""))
        db._batch.append((now - 60, "recent.com", "A", "ALLOWED", ""))
        db.flush()

        rows, total = db.get_recent_queries(10, start=now - 4000, end=now - 100)
        assert total == 1
        assert rows[0]["domain"] == "mid.com"
        db.close()


class TestQueryDBHistoryBuckets:
    def test_history_buckets(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        now = time.time()
        # Insert queries at known times
        for i in range(10):
            db._batch.append((now - 300 + i, f"d{i}.com", "A", "ALLOWED", ""))
        for i in range(5):
            db._batch.append((now - 300 + i, f"b{i}.com", "A", "BLOCKED", ""))
        db.flush()

        buckets = db.get_history_buckets(hours=1, bucket_minutes=10)
        total_allowed = sum(b["allowed"] for b in buckets)
        total_blocked = sum(b["blocked"] for b in buckets)
        assert total_allowed == 10
        assert total_blocked == 5
        db.close()

    def test_empty_buckets(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        buckets = db.get_history_buckets(hours=1, bucket_minutes=10)
        assert len(buckets) == 6  # 60min / 10min
        assert all(b["allowed"] == 0 and b["blocked"] == 0 for b in buckets)
        db.close()


class TestQueryDBDistributions:
    def test_query_type_distribution(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        db.log_query("a.com", "A", blocked=False)
        db.log_query("b.com", "A", blocked=False)
        db.log_query("c.com", "AAAA", blocked=False)
        db.log_query("d.com", "CNAME", blocked=False)
        db.flush()

        dist = db.get_query_type_distribution()
        assert dist["A"] == 2
        assert dist["AAAA"] == 1
        assert dist["CNAME"] == 1
        db.close()

    def test_top_clients(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        for i in range(5):
            db.log_query(f"d{i}.com", "A", blocked=False, client_ip="10.0.0.1")
        for i in range(3):
            db.log_query(f"e{i}.com", "A", blocked=False, client_ip="10.0.0.2")
        db.flush()

        clients = db.get_top_clients(limit=5)
        assert clients["10.0.0.1"] == 5
        assert clients["10.0.0.2"] == 3
        db.close()


class TestQueryDBRotation:
    def test_rotate_deletes_old_entries(self, tmp_path):
        db = QueryDB(tmp_path / "q.db", retention_days=1)
        now = time.time()
        # Insert old entry (2 days ago)
        db._batch.append((now - 2 * 86400, "old.com", "A", "ALLOWED", ""))
        # Insert recent entry (1 hour ago)
        db._batch.append((now - 3600, "recent.com", "A", "ALLOWED", ""))
        db.flush()

        assert db.get_total_count() == 2
        deleted = db.rotate()
        assert deleted == 1
        assert db.get_total_count() == 1

        rows, _ = db.get_recent_queries(10)
        assert rows[0]["domain"] == "recent.com"
        db.close()

    def test_rotate_nothing_to_delete(self, tmp_path):
        db = QueryDB(tmp_path / "q.db", retention_days=7)
        db.log_query("new.com", "A", blocked=False)
        db.flush()
        deleted = db.rotate()
        assert deleted == 0
        db.close()


class TestQueryDBImport:
    def test_import_from_log(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO ALLOWED A github.com\n"
            "2026-02-26 14:30:03 [coreguard.queries] INFO BLOCKED AAAA tracker.net\n"
        )
        count = db.import_from_log(log_file)
        assert count == 3
        assert db.get_total_count() == 3

        rows, _ = db.get_recent_queries(10)
        domains = [r["domain"] for r in rows]
        assert "ads.example.com" in domains
        assert "github.com" in domains
        assert "tracker.net" in domains
        db.close()

    def test_import_missing_file(self, tmp_path):
        db = QueryDB(tmp_path / "q.db")
        count = db.import_from_log(tmp_path / "nonexistent.log")
        assert count == 0
        db.close()


class TestQueryDBFlushRetention:
    def test_batch_retained_on_write_failure(self, tmp_path):
        """If executemany fails, the batch should be retained for retry."""
        db = QueryDB(tmp_path / "q.db")
        db.log_query("a.com", "A", blocked=False)
        db.log_query("b.com", "A", blocked=True)

        # Replace the connection with a mock that raises on executemany
        real_conn = db._conn
        mock_conn = MagicMock()
        mock_conn.executemany.side_effect = sqlite3.OperationalError("disk full")
        db._conn = mock_conn
        db.flush()

        # Batch should still have the entries
        assert len(db._batch) == 2

        # Restore real connection and verify retry works
        db._conn = real_conn
        db.flush()
        assert len(db._batch) == 0
        assert db.get_total_count() == 2
        db.close()

    def test_batch_cleared_on_success(self, tmp_path):
        """Batch should be cleared after successful flush."""
        db = QueryDB(tmp_path / "q.db")
        db.log_query("a.com", "A", blocked=False)
        db.flush()
        assert len(db._batch) == 0
        db.close()


class TestQueryDBCorruptRecovery:
    def test_corrupt_db_creates_fresh(self, tmp_path):
        """A corrupt database file should be renamed and a fresh DB created."""
        db_path = tmp_path / "queries.db"
        db_path.write_bytes(b"this is not a valid sqlite database")

        db = QueryDB(db_path)
        # Should be able to use the fresh DB
        db.log_query("test.com", "A", blocked=False)
        db.flush()
        rows, total = db.get_recent_queries(10)
        assert total == 1

        # Corrupt file should have been renamed
        corrupt_files = list(tmp_path.glob("*.corrupt.*"))
        assert len(corrupt_files) == 1
        db.close()

    def test_valid_db_works_normally(self, tmp_path):
        """A valid existing database should be opened normally."""
        db_path = tmp_path / "queries.db"
        # Create a valid DB first
        db1 = QueryDB(db_path)
        db1.log_query("existing.com", "A", blocked=False)
        db1.flush()
        db1.close()

        # Re-open should find the existing data
        db2 = QueryDB(db_path)
        rows, total = db2.get_recent_queries(10)
        assert total == 1
        assert rows[0]["domain"] == "existing.com"
        db2.close()


class TestQueryDBConcurrency:
    def test_concurrent_log_and_flush(self, tmp_path):
        """Multiple threads logging and flushing should not corrupt data."""
        import threading

        db = QueryDB(tmp_path / "q.db")
        db._batch_size = 10
        errors = []

        def writer(n):
            try:
                for i in range(50):
                    db.log_query(f"t{n}-{i}.com", "A", blocked=(i % 2 == 0))
                    if i % 20 == 0:
                        db.flush()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        db.flush()
        assert not errors
        total = db.get_total_count()
        assert total == 250  # 5 threads * 50 queries
        db.close()

    def test_concurrent_log_and_read(self, tmp_path):
        """Reading while writing should not cause errors."""
        import threading

        db = QueryDB(tmp_path / "q.db")
        errors = []

        def writer():
            try:
                for i in range(100):
                    db.log_query(f"w{i}.com", "A", blocked=False)
                db.flush()
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(20):
                    db.get_recent_queries(10)
                    db.get_total_count()
            except Exception as e:
                errors.append(e)

        wt = threading.Thread(target=writer)
        rt = threading.Thread(target=reader)
        wt.start()
        rt.start()
        wt.join()
        rt.join()

        assert not errors
        db.close()
