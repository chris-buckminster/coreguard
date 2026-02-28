"""Safe search DNS CNAME rewrite engine.

Redirects search engine queries to their safe/restricted variants via CNAME.
"""

import re

from dnslib import CNAME, QTYPE, RR, DNSRecord

# Google country-code variants: www.google.XX or www.google.co.XX
GOOGLE_CC_PATTERN = re.compile(
    r"^www\.google\.(com|[a-z]{2}|com?\.[a-z]{2}|co\.[a-z]{2})$", re.IGNORECASE
)

# Static CNAME mapping for non-Google search engines
SAFE_SEARCH_CNAME_MAP: dict[str, str] = {
    "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
}

# YouTube restriction targets
_YOUTUBE_TARGETS = {
    "moderate": "restrict.youtube.com",
    "strict": "restrictmoderate.youtube.com",
}

# Content category list URLs (StevenBlack host file variants)
CONTENT_CATEGORY_LISTS: dict[str, str] = {
    "adult": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
    "gambling": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
    "social": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
}


def get_safe_search_target(domain: str, youtube_restrict: str = "moderate") -> str | None:
    """Return the safe CNAME target for a domain, or None if not a search engine.

    Args:
        domain: The queried domain (lowercase, no trailing dot).
        youtube_restrict: YouTube restriction level ("moderate" or "strict").

    Returns:
        The CNAME target to rewrite to, or None.
    """
    domain = domain.lower().rstrip(".")

    # Google (including country variants)
    if GOOGLE_CC_PATTERN.match(domain):
        return "forcesafesearch.google.com"

    # YouTube
    if domain == "www.youtube.com":
        return _YOUTUBE_TARGETS.get(youtube_restrict, "restrict.youtube.com")

    # Static map (Bing, DuckDuckGo)
    return SAFE_SEARCH_CNAME_MAP.get(domain)


def make_safe_search_response(request: DNSRecord, target: str) -> DNSRecord:
    """Build a DNS response with a CNAME pointing to the safe search target."""
    qname = str(request.q.qname)
    reply = request.reply()
    reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(target), ttl=300))
    return reply
