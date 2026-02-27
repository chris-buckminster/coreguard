import json
import logging
import threading
from collections import Counter
from pathlib import Path

logger = logging.getLogger("coreguard.stats")

MAX_TRACKED_DOMAINS = 10_000


class Stats:
    """Thread-safe query statistics tracker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_queries = 0
        self.blocked_queries = 0
        self.error_queries = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cname_blocks = 0
        self.top_blocked: Counter[str] = Counter()
        self.top_queried: Counter[str] = Counter()
        self.query_types: Counter[str] = Counter()
        self.top_clients: Counter[str] = Counter()

    def record_query(
        self, domain: str, blocked: bool, error: bool = False,
        qtype: str | None = None, client_ip: str | None = None,
    ) -> None:
        with self._lock:
            self.total_queries += 1
            self.top_queried[domain] += 1
            if blocked:
                self.blocked_queries += 1
                self.top_blocked[domain] += 1
            if error:
                self.error_queries += 1
            if qtype:
                self.query_types[qtype] += 1
            if client_ip:
                self.top_clients[client_ip] += 1

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses += 1

    def record_cname_block(self) -> None:
        with self._lock:
            self.cname_blocks += 1

    def trim(self) -> None:
        """Trim counters to prevent unbounded memory growth."""
        with self._lock:
            if len(self.top_queried) > MAX_TRACKED_DOMAINS:
                self.top_queried = Counter(dict(self.top_queried.most_common(MAX_TRACKED_DOMAINS)))
            if len(self.top_blocked) > MAX_TRACKED_DOMAINS:
                self.top_blocked = Counter(dict(self.top_blocked.most_common(MAX_TRACKED_DOMAINS)))
            if len(self.top_clients) > MAX_TRACKED_DOMAINS:
                self.top_clients = Counter(dict(self.top_clients.most_common(MAX_TRACKED_DOMAINS)))

    def to_dict(self) -> dict:
        with self._lock:
            total = max(self.total_queries, 1)
            cache_total = max(self.cache_hits + self.cache_misses, 1)
            return {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "blocked_percent": round((self.blocked_queries / total) * 100, 1),
                "error_queries": self.error_queries,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": round((self.cache_hits / cache_total) * 100, 1),
                "cname_blocks": self.cname_blocks,
                "top_blocked": dict(self.top_blocked.most_common(10)),
                "top_queried": dict(self.top_queried.most_common(10)),
                "query_types": dict(self.query_types),
                "top_clients": dict(self.top_clients.most_common(10)),
            }

    def save(self, path: Path) -> None:
        """Persist stats to a JSON file."""
        try:
            path.write_text(json.dumps(self.to_dict(), indent=2))
        except Exception as e:
            logger.debug("Failed to save stats: %s", e)

    @staticmethod
    def load_from_file(path: Path) -> dict:
        """Load stats from a JSON file (for status display)."""
        defaults = {
            "total_queries": 0,
            "blocked_queries": 0,
            "blocked_percent": 0.0,
            "error_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_hit_rate": 0.0,
            "cname_blocks": 0,
            "top_blocked": {},
            "top_queried": {},
        }
        if not path.exists():
            return defaults
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return defaults
