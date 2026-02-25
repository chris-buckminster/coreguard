from typing import Iterable


class DomainFilter:
    """Fast domain matching engine using set lookups with subdomain walk."""

    def __init__(self) -> None:
        self._blocked: set[str] = set()
        self._allowed: set[str] = set()

    def load_blocklist(self, domains: Iterable[str]) -> None:
        """Add domains to the block set."""
        self._blocked.update(d.lower().strip(".") for d in domains if d.strip())

    def load_allowlist(self, domains: Iterable[str]) -> None:
        """Add domains to the allow set."""
        self._allowed.update(d.lower().strip(".") for d in domains if d.strip())

    def clear(self) -> None:
        """Clear all loaded domains."""
        self._blocked.clear()
        self._allowed.clear()

    def is_blocked(self, domain: str) -> bool:
        """Check if domain should be blocked.

        Walks up the domain hierarchy (e.g. a.b.example.com -> b.example.com
        -> example.com) checking allowlist first, then blocklist.
        """
        domain = domain.lower().rstrip(".")
        if not domain:
            return False
        # Allowlist takes priority
        if self._check_set(domain, self._allowed):
            return False
        return self._check_set(domain, self._blocked)

    def _check_set(self, domain: str, domain_set: set[str]) -> bool:
        """Walk up the domain hierarchy checking against a set."""
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in domain_set:
                return True
        return False

    @property
    def blocked_count(self) -> int:
        return len(self._blocked)

    @property
    def allowed_count(self) -> int:
        return len(self._allowed)
