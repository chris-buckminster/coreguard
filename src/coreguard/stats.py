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
        self.top_blocked: Counter[str] = Counter()
        self.top_queried: Counter[str] = Counter()

    def record_query(self, domain: str, blocked: bool, error: bool = False) -> None:
        with self._lock:
            self.total_queries += 1
            self.top_queried[domain] += 1
            if blocked:
                self.blocked_queries += 1
                self.top_blocked[domain] += 1
            if error:
                self.error_queries += 1

    def trim(self) -> None:
        """Trim counters to prevent unbounded memory growth."""
        with self._lock:
            if len(self.top_queried) > MAX_TRACKED_DOMAINS:
                self.top_queried = Counter(dict(self.top_queried.most_common(MAX_TRACKED_DOMAINS)))
            if len(self.top_blocked) > MAX_TRACKED_DOMAINS:
                self.top_blocked = Counter(dict(self.top_blocked.most_common(MAX_TRACKED_DOMAINS)))

    def to_dict(self) -> dict:
        with self._lock:
            total = max(self.total_queries, 1)
            return {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "blocked_percent": round((self.blocked_queries / total) * 100, 1),
                "error_queries": self.error_queries,
                "top_blocked": dict(self.top_blocked.most_common(10)),
                "top_queried": dict(self.top_queried.most_common(10)),
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
            "top_blocked": {},
            "top_queried": {},
        }
        if not path.exists():
            return defaults
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return defaults
