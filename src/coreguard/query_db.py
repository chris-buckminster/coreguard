"""SQLite-backed query logging with batched writes and retention management."""

import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("coreguard.query_db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL,
    status TEXT NOT NULL,
    client_ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_client_ip ON queries(client_ip);
"""


class QueryDB:
    """Thread-safe SQLite query log with batched inserts and auto-rotation."""

    def __init__(self, db_path: Path, retention_days: int = 7) -> None:
        self.db_path = db_path
        self.retention_days = retention_days
        self._batch: list[tuple] = []
        self._lock = threading.Lock()
        self._batch_size = 50
        self._conn = self._open_db(db_path)

    def _open_db(self, db_path: Path) -> sqlite3.Connection:
        """Open or create the SQLite database, recovering from corruption."""
        try:
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.commit()
            return conn
        except sqlite3.DatabaseError as e:
            logger.warning("Corrupt database %s: %s — creating fresh DB", db_path, e)
            # Rename corrupt file to preserve evidence
            corrupt_suffix = f".corrupt.{int(time.time())}"
            corrupt_path = db_path.with_suffix(corrupt_suffix)
            try:
                db_path.rename(corrupt_path)
            except OSError:
                db_path.unlink(missing_ok=True)
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.commit()
            return conn

    def log_query(
        self,
        domain: str,
        qtype: str,
        blocked: bool,
        client_ip: str | None = None,
    ) -> None:
        """Add a query to the batch. Flushes when batch is full."""
        row = (time.time(), domain, qtype, "BLOCKED" if blocked else "ALLOWED", client_ip or "")
        with self._lock:
            self._batch.append(row)
            if len(self._batch) >= self._batch_size:
                self._flush_locked()

    def flush(self) -> None:
        """Force-flush the current batch to disk."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._batch:
            return
        try:
            self._conn.executemany(
                "INSERT INTO queries (timestamp, domain, qtype, status, client_ip) VALUES (?, ?, ?, ?, ?)",
                self._batch,
            )
            self._conn.commit()
            self._batch.clear()
        except sqlite3.Error as e:
            logger.warning("Failed to flush query batch (%d entries retained): %s", len(self._batch), e)

    def get_recent_queries(
        self,
        limit: int = 100,
        offset: int = 0,
        start: float | None = None,
        end: float | None = None,
        domain: str | None = None,
        client_ip: str | None = None,
        status: str | None = None,
    ) -> tuple[list[dict], int]:
        """Retrieve recent queries with filtering. Returns (rows, total_count)."""
        self.flush()
        conditions = []
        params: list = []
        if start is not None:
            conditions.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            conditions.append("timestamp <= ?")
            params.append(end)
        if domain:
            conditions.append("domain LIKE ?")
            params.append(f"%{domain}%")
        if client_ip:
            conditions.append("client_ip = ?")
            params.append(client_ip)
        if status and status != "all":
            conditions.append("status = ?")
            params.append(status)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""

        with self._lock:
            cur = self._conn.execute(f"SELECT COUNT(*) FROM queries{where}", params)
            total = cur.fetchone()[0]

            cur = self._conn.execute(
                f"SELECT timestamp, domain, qtype, status, client_ip FROM queries{where} "
                f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            )
            rows = []
            for row in cur:
                rows.append({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0])),
                    "domain": row[1],
                    "type": row[2],
                    "status": row[3],
                    "client": row[4],
                })
        return rows, total

    def get_history_buckets(self, hours: int = 24, bucket_minutes: int = 10) -> list[dict]:
        """Return query counts in time buckets for the last N hours."""
        self.flush()
        now = time.time()
        cutoff = now - hours * 3600
        bucket_seconds = bucket_minutes * 60
        num_buckets = (hours * 60) // bucket_minutes

        # Initialize empty buckets
        base = cutoff
        buckets = []
        for i in range(num_buckets):
            t = base + i * bucket_seconds
            buckets.append({
                "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)),
                "allowed": 0,
                "blocked": 0,
            })

        with self._lock:
            cur = self._conn.execute(
                "SELECT timestamp, status FROM queries WHERE timestamp >= ? ORDER BY timestamp",
                (cutoff,),
            )
            for ts, status in cur:
                idx = int((ts - cutoff) / bucket_seconds)
                if 0 <= idx < num_buckets:
                    if status == "BLOCKED":
                        buckets[idx]["blocked"] += 1
                    else:
                        buckets[idx]["allowed"] += 1

        return buckets

    def get_query_type_distribution(self) -> dict[str, int]:
        """Return query counts grouped by type."""
        self.flush()
        with self._lock:
            cur = self._conn.execute("SELECT qtype, COUNT(*) FROM queries GROUP BY qtype")
            return dict(cur.fetchall())

    def get_top_clients(self, limit: int = 10) -> dict[str, int]:
        """Return top clients by query count."""
        self.flush()
        with self._lock:
            cur = self._conn.execute(
                "SELECT client_ip, COUNT(*) as cnt FROM queries WHERE client_ip != '' "
                "GROUP BY client_ip ORDER BY cnt DESC LIMIT ?",
                (limit,),
            )
            return dict(cur.fetchall())

    def get_total_count(self) -> int:
        """Return total number of stored queries."""
        self.flush()
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM queries")
            return cur.fetchone()[0]

    def rotate(self) -> int:
        """Delete entries older than retention_days. Returns number deleted."""
        cutoff = time.time() - self.retention_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM queries WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
            deleted = cur.rowcount
        if deleted > 0:
            logger.info("Rotated %d old query log entries", deleted)
        return deleted

    def import_from_log(self, log_path: Path) -> int:
        """Import queries from a flat log file into the database. Returns count imported."""
        import re
        pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(BLOCKED|ALLOWED)\s+(\S+)\s+(\S+)"
        )
        if not log_path.exists():
            return 0

        count = 0
        batch = []
        try:
            with open(log_path) as f:
                for line in f:
                    m = pattern.match(line.strip())
                    if not m:
                        continue
                    ts_str, status, qtype, domain = m.group(1), m.group(2), m.group(3), m.group(4)
                    try:
                        ts = time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
                    except ValueError:
                        continue
                    batch.append((ts, domain, qtype, status, ""))
                    count += 1
                    if len(batch) >= 500:
                        with self._lock:
                            self._conn.executemany(
                                "INSERT INTO queries (timestamp, domain, qtype, status, client_ip) VALUES (?, ?, ?, ?, ?)",
                                batch,
                            )
                            self._conn.commit()
                        batch.clear()
        except OSError as e:
            logger.warning("Failed to import log file: %s", e)

        if batch:
            with self._lock:
                self._conn.executemany(
                    "INSERT INTO queries (timestamp, domain, qtype, status, client_ip) VALUES (?, ?, ?, ?, ?)",
                    batch,
                )
                self._conn.commit()

        logger.info("Imported %d queries from log file", count)
        return count

    def close(self) -> None:
        """Flush pending writes and close the connection."""
        self.flush()
        self._conn.close()
