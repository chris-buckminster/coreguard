import json
import threading
from collections import Counter
from pathlib import Path


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
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @staticmethod
    def load_from_file(path: Path) -> dict:
        """Load stats from a JSON file (for status display)."""
        if not path.exists():
            return {
                "total_queries": 0,
                "blocked_queries": 0,
                "blocked_percent": 0.0,
                "error_queries": 0,
                "top_blocked": {},
                "top_queried": {},
            }
        return json.loads(path.read_text())
