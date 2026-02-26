import logging
import threading
import time
from dataclasses import dataclass

from dnslib import DNSRecord

logger = logging.getLogger("coreguard.cache")


@dataclass(slots=True)
class _CacheEntry:
    response: DNSRecord
    expires_at: float  # time.monotonic() + ttl
    original_ttl: int
    is_blocked: bool


class DNSCache:
    """Thread-safe, memory-bounded DNS response cache with TTL expiration."""

    def __init__(
        self,
        max_entries: int = 10_000,
        max_ttl: int = 3600,
        min_ttl: int = 0,
    ) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, int], _CacheEntry] = {}
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.min_ttl = min_ttl

    def get(self, domain: str, qtype: int) -> DNSRecord | None:
        """Look up a cached response. Returns None on miss or expiry.

        Returns a clone with TTLs adjusted to reflect remaining time.
        """
        key = (domain.lower().rstrip("."), qtype)
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if now >= entry.expires_at:
                del self._store[key]
                return None
            # Clone so callers don't mutate the cached copy
            response = DNSRecord.parse(entry.response.pack())
            remaining = max(1, int(entry.expires_at - now))
            for rr in response.rr + response.auth + response.ar:
                rr.ttl = remaining
            return response

    def put(
        self,
        domain: str,
        qtype: int,
        response: DNSRecord,
        is_blocked: bool = False,
    ) -> None:
        """Cache a response. TTL derived from minimum across answer records."""
        ttl = self._extract_ttl(response, is_blocked)
        if ttl <= 0:
            return
        ttl = max(self.min_ttl, min(ttl, self.max_ttl))

        key = (domain.lower().rstrip("."), qtype)
        now = time.monotonic()
        entry = _CacheEntry(
            response=DNSRecord.parse(response.pack()),  # defensive copy
            expires_at=now + ttl,
            original_ttl=ttl,
            is_blocked=is_blocked,
        )
        with self._lock:
            self._store[key] = entry
            if len(self._store) > self.max_entries:
                self._evict_one()

    def sweep_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, v in self._store.items() if now >= v.expires_at]
            for k in expired:
                del self._store[k]
        if expired:
            logger.debug("Cache sweep: removed %d expired entries", len(expired))
        return len(expired)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)

    def _extract_ttl(self, response: DNSRecord, is_blocked: bool) -> int:
        if is_blocked:
            return 300
        if response.rr:
            return min(rr.ttl for rr in response.rr)
        # No answer records — check authority section for SOA
        for rr in response.auth:
            if rr.rtype == 6:  # SOA
                return rr.ttl
        return 0

    def _evict_one(self) -> None:
        """Evict the entry closest to expiration. Must hold self._lock."""
        if not self._store:
            return
        victim = min(self._store, key=lambda k: self._store[k].expires_at)
        del self._store[victim]
