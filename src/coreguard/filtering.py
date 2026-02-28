import re
from typing import Iterable


class DomainFilter:
    """Fast domain matching engine using set lookups with subdomain walk."""

    def __init__(self) -> None:
        self._blocked: set[str] = set()
        self._allowed: set[str] = set()
        self._blocked_wildcards: list[re.Pattern] = []
        self._allowed_wildcards: list[re.Pattern] = []
        self._blocked_regex: list[re.Pattern] = []
        self._allowed_regex: list[re.Pattern] = []

    def load_blocklist(self, domains: Iterable[str]) -> None:
        """Add domains to the block set."""
        self._blocked.update(d.lower().strip(".") for d in domains if d.strip())

    def load_allowlist(self, domains: Iterable[str]) -> None:
        """Add domains to the allow set."""
        self._allowed.update(d.lower().strip(".") for d in domains if d.strip())

    def load_blocklist_wildcards(self, patterns: Iterable[str]) -> None:
        """Add wildcard patterns to the block list."""
        for p in patterns:
            compiled = self._compile_wildcard(p)
            if compiled:
                self._blocked_wildcards.append(compiled)

    def load_allowlist_wildcards(self, patterns: Iterable[str]) -> None:
        """Add wildcard patterns to the allow list."""
        for p in patterns:
            compiled = self._compile_wildcard(p)
            if compiled:
                self._allowed_wildcards.append(compiled)

    def load_blocklist_regex(self, patterns: Iterable[str]) -> None:
        """Add regex patterns to the block list."""
        for p in patterns:
            compiled = self._compile_regex(p)
            if compiled:
                self._blocked_regex.append(compiled)

    def load_allowlist_regex(self, patterns: Iterable[str]) -> None:
        """Add regex patterns to the allow list."""
        for p in patterns:
            compiled = self._compile_regex(p)
            if compiled:
                self._allowed_regex.append(compiled)

    def clear(self) -> None:
        """Clear all loaded domains, wildcard patterns, and regex patterns."""
        self._blocked.clear()
        self._allowed.clear()
        self._blocked_wildcards.clear()
        self._allowed_wildcards.clear()
        self._blocked_regex.clear()
        self._allowed_regex.clear()

    def is_blocked(self, domain: str) -> bool:
        """Check if domain should be blocked.

        Walks up the domain hierarchy (e.g. a.b.example.com -> b.example.com
        -> example.com) checking allowlist first, then blocklist. Falls back
        to wildcard pattern matching if no exact/subdomain match is found.
        """
        domain = domain.lower().rstrip(".")
        if not domain:
            return False
        # Allowlist takes priority (exact + wildcard + regex)
        if self._check_set(domain, self._allowed):
            return False
        if self._check_wildcards(domain, self._allowed_wildcards):
            return False
        if self._check_regex(domain, self._allowed_regex):
            return False
        if self._check_set(domain, self._blocked):
            return True
        if self._check_wildcards(domain, self._blocked_wildcards):
            return True
        return self._check_regex(domain, self._blocked_regex)

    def _check_set(self, domain: str, domain_set: set[str]) -> bool:
        """Walk up the domain hierarchy checking against a set."""
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in domain_set:
                return True
        return False

    @staticmethod
    def _check_wildcards(domain: str, patterns: list[re.Pattern]) -> bool:
        """Check domain against compiled wildcard patterns."""
        return any(p.match(domain) for p in patterns)

    @staticmethod
    def _compile_wildcard(pattern: str) -> re.Pattern | None:
        """Convert a wildcard pattern to a compiled regex.

        Leading *. matches one or more subdomain labels (e.g. *.ads.com
        matches foo.ads.com and a.b.ads.com but not ads.com).
        A * elsewhere matches within a single DNS label (no dots).
        """
        pattern = pattern.lower().strip(".")
        if not pattern:
            return None
        if pattern.startswith("*."):
            rest = re.escape(pattern[2:]).replace(r"\*", "[^.]*")
            return re.compile(f"^(.+\\.){rest}$")
        regex = re.escape(pattern).replace(r"\*", "[^.]*")
        return re.compile(f"^{regex}$")

    @staticmethod
    def _compile_regex(pattern: str) -> re.Pattern | None:
        """Compile a regex pattern, returning None on invalid syntax."""
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            return None

    @staticmethod
    def _check_regex(domain: str, patterns: list[re.Pattern]) -> bool:
        """Check domain against compiled regex patterns."""
        return any(p.search(domain) for p in patterns)

    def snapshot_base(self) -> None:
        """Save current filter state as the base (before schedule overlays)."""
        self._base_blocked = set(self._blocked)
        self._base_allowed = set(self._allowed)
        self._base_blocked_wildcards = list(self._blocked_wildcards)
        self._base_allowed_wildcards = list(self._allowed_wildcards)
        self._base_blocked_regex = list(self._blocked_regex)
        self._base_allowed_regex = list(self._allowed_regex)

    def restore_base(self) -> None:
        """Restore the base filter state, removing any schedule overlay."""
        if not hasattr(self, "_base_blocked"):
            return
        self._blocked = set(self._base_blocked)
        self._allowed = set(self._base_allowed)
        self._blocked_wildcards = list(self._base_blocked_wildcards)
        self._allowed_wildcards = list(self._base_allowed_wildcards)
        self._blocked_regex = list(self._base_blocked_regex)
        self._allowed_regex = list(self._base_allowed_regex)

    def apply_schedule_overlay(
        self,
        domains: Iterable[str],
        wildcards: Iterable[str],
        regexes: Iterable[str],
    ) -> None:
        """Add schedule-specific blocks on top of the base state."""
        self.load_blocklist(domains)
        self.load_blocklist_wildcards(wildcards)
        self.load_blocklist_regex(regexes)

    @property
    def blocked_count(self) -> int:
        return len(self._blocked)

    @property
    def allowed_count(self) -> int:
        return len(self._allowed)

    @property
    def regex_count(self) -> int:
        return len(self._blocked_regex) + len(self._allowed_regex)
