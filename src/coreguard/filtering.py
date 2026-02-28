import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class _FilterState:
    """Immutable snapshot of all filter collections.

    Assigned atomically to DomainFilter._state so reader threads always
    see a consistent view without locks.
    """
    blocked: frozenset
    allowed: frozenset
    blocked_wildcards: tuple
    allowed_wildcards: tuple
    blocked_regex: tuple
    allowed_regex: tuple


_EMPTY_STATE = _FilterState(
    blocked=frozenset(),
    allowed=frozenset(),
    blocked_wildcards=(),
    allowed_wildcards=(),
    blocked_regex=(),
    allowed_regex=(),
)


class DomainFilter:
    """Fast domain matching engine using set lookups with subdomain walk.

    Thread-safe via snapshot-swap: all reads grab a local reference to
    the immutable _FilterState; all mutations build a new state and
    assign in a single reference write.
    """

    def __init__(self) -> None:
        self._state: _FilterState = _EMPTY_STATE

    def load_blocklist(self, domains: Iterable[str]) -> None:
        """Add domains to the block set."""
        new = frozenset(d.lower().strip(".") for d in domains if d.strip())
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked | new,
            allowed=state.allowed,
            blocked_wildcards=state.blocked_wildcards,
            allowed_wildcards=state.allowed_wildcards,
            blocked_regex=state.blocked_regex,
            allowed_regex=state.allowed_regex,
        )

    def load_allowlist(self, domains: Iterable[str]) -> None:
        """Add domains to the allow set."""
        new = frozenset(d.lower().strip(".") for d in domains if d.strip())
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked,
            allowed=state.allowed | new,
            blocked_wildcards=state.blocked_wildcards,
            allowed_wildcards=state.allowed_wildcards,
            blocked_regex=state.blocked_regex,
            allowed_regex=state.allowed_regex,
        )

    def load_blocklist_wildcards(self, patterns: Iterable[str]) -> None:
        """Add wildcard patterns to the block list."""
        compiled = []
        for p in patterns:
            c = self._compile_wildcard(p)
            if c:
                compiled.append(c)
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked,
            allowed=state.allowed,
            blocked_wildcards=state.blocked_wildcards + tuple(compiled),
            allowed_wildcards=state.allowed_wildcards,
            blocked_regex=state.blocked_regex,
            allowed_regex=state.allowed_regex,
        )

    def load_allowlist_wildcards(self, patterns: Iterable[str]) -> None:
        """Add wildcard patterns to the allow list."""
        compiled = []
        for p in patterns:
            c = self._compile_wildcard(p)
            if c:
                compiled.append(c)
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked,
            allowed=state.allowed,
            blocked_wildcards=state.blocked_wildcards,
            allowed_wildcards=state.allowed_wildcards + tuple(compiled),
            blocked_regex=state.blocked_regex,
            allowed_regex=state.allowed_regex,
        )

    def load_blocklist_regex(self, patterns: Iterable[str]) -> None:
        """Add regex patterns to the block list."""
        compiled = []
        for p in patterns:
            c = self._compile_regex(p)
            if c:
                compiled.append(c)
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked,
            allowed=state.allowed,
            blocked_wildcards=state.blocked_wildcards,
            allowed_wildcards=state.allowed_wildcards,
            blocked_regex=state.blocked_regex + tuple(compiled),
            allowed_regex=state.allowed_regex,
        )

    def load_allowlist_regex(self, patterns: Iterable[str]) -> None:
        """Add regex patterns to the allow list."""
        compiled = []
        for p in patterns:
            c = self._compile_regex(p)
            if c:
                compiled.append(c)
        state = self._state
        self._state = _FilterState(
            blocked=state.blocked,
            allowed=state.allowed,
            blocked_wildcards=state.blocked_wildcards,
            allowed_wildcards=state.allowed_wildcards,
            blocked_regex=state.blocked_regex,
            allowed_regex=state.allowed_regex + tuple(compiled),
        )

    def clear(self) -> None:
        """Clear all loaded domains, wildcard patterns, and regex patterns."""
        self._state = _EMPTY_STATE

    def is_blocked(self, domain: str) -> bool:
        """Check if domain should be blocked.

        Walks up the domain hierarchy (e.g. a.b.example.com -> b.example.com
        -> example.com) checking allowlist first, then blocklist. Falls back
        to wildcard pattern matching if no exact/subdomain match is found.
        """
        domain = domain.lower().rstrip(".")
        if not domain:
            return False
        # Grab a local reference — atomic, consistent snapshot
        state = self._state
        # Allowlist takes priority (exact + wildcard + regex)
        if self._check_set(domain, state.allowed):
            return False
        if self._check_wildcards(domain, state.allowed_wildcards):
            return False
        if self._check_regex(domain, state.allowed_regex):
            return False
        if self._check_set(domain, state.blocked):
            return True
        if self._check_wildcards(domain, state.blocked_wildcards):
            return True
        return self._check_regex(domain, state.blocked_regex)

    def _check_set(self, domain: str, domain_set: frozenset) -> bool:
        """Walk up the domain hierarchy checking against a set."""
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in domain_set:
                return True
        return False

    @staticmethod
    def _check_wildcards(domain: str, patterns: tuple) -> bool:
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
    def _check_regex(domain: str, patterns: tuple) -> bool:
        """Check domain against compiled regex patterns."""
        return any(p.search(domain) for p in patterns)

    def snapshot_base(self) -> None:
        """Save current filter state as the base (before schedule overlays)."""
        self._base_state = self._state

    def restore_base(self) -> None:
        """Restore the base filter state, removing any schedule overlay."""
        if not hasattr(self, "_base_state"):
            return
        self._state = self._base_state

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
        return len(self._state.blocked)

    @property
    def allowed_count(self) -> int:
        return len(self._state.allowed)

    @property
    def regex_count(self) -> int:
        state = self._state
        return len(state.blocked_regex) + len(state.allowed_regex)
