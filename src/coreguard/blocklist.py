import logging
import re
from pathlib import Path

import httpx

from coreguard.config import BLOCKLISTS_DIR, CUSTOM_ALLOW_FILE, CUSTOM_BLOCK_FILE, Config
from coreguard.filtering import DomainFilter

logger = logging.getLogger("coreguard.blocklist")

# Domains to never block (essential infrastructure)
NEVER_BLOCK = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
}


def _sanitize_filename(name: str) -> str:
    """Convert a list name to a safe filename."""
    return re.sub(r"[^\w\-.]", "_", name) + ".txt"


def parse_hosts_file(content: str) -> set[str]:
    """Parse hosts-file format (0.0.0.0/127.0.0.1 domain)."""
    domains: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].lower().strip(".")
            if domain and domain not in NEVER_BLOCK:
                domains.add(domain)
    return domains


def parse_adblock_list(content: str) -> tuple[set[str], set[str]]:
    """Parse adblock-style domain list (||domain^ format).

    Returns (blocked_domains, allowed_domains).
    """
    blocked: set[str] = set()
    allowed: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        # Skip lines with unsupported modifiers
        if "$" in line:
            continue
        if line.startswith("@@||") and line.endswith("^"):
            domain = line[4:-1].lower().strip(".")
            if domain:
                allowed.add(domain)
        elif line.startswith("||") and line.endswith("^"):
            domain = line[2:-1].lower().strip(".")
            if domain and domain not in NEVER_BLOCK:
                blocked.add(domain)
    return blocked, allowed


def parse_domain_list(content: str) -> set[str]:
    """Parse a plain list of domains (one per line)."""
    domains: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        domain = line.lower().strip(".")
        if domain and domain not in NEVER_BLOCK:
            domains.add(domain)
    return domains


def detect_and_parse(content: str) -> tuple[set[str], set[str]]:
    """Auto-detect format and parse. Returns (blocked, allowed)."""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!") or line.startswith("["):
            continue
        # First non-comment line determines format
        if line.startswith(("0.0.0.0", "127.0.0.1")):
            return parse_hosts_file(content), set()
        if line.startswith("||") or line.startswith("@@||"):
            return parse_adblock_list(content)
        # Assume plain domain list
        return parse_domain_list(content), set()
    return set(), set()


def download_list(url: str, timeout: float = 30.0) -> str:
    """Download a filter list from a URL."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def load_custom_list(path: Path) -> set[str]:
    """Load a custom allow/block list (one domain per line)."""
    if not path.exists():
        return set()
    content = path.read_text()
    domains: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.add(line.lower().strip("."))
    return domains


def update_all_lists(config: Config, domain_filter: DomainFilter) -> int:
    """Download and parse all enabled filter lists, rebuild the domain filter.

    Returns the total number of blocked domains loaded.
    """
    all_blocked: set[str] = set()
    all_allowed: set[str] = set()

    for flist in config.filter_lists:
        if not flist.get("enabled", True):
            continue
        name = flist["name"]
        url = flist["url"]
        cache_path = BLOCKLISTS_DIR / _sanitize_filename(name)

        try:
            logger.info("Downloading filter list: %s", name)
            content = download_list(url)
            cache_path.write_text(content)
        except Exception as e:
            logger.warning("Failed to download %s: %s", name, e)
            # Fall back to cached version
            if cache_path.exists():
                logger.info("Using cached version of %s", name)
                content = cache_path.read_text()
            else:
                logger.warning("No cached version of %s, skipping", name)
                continue

        blocked, allowed = detect_and_parse(content)
        all_blocked.update(blocked)
        all_allowed.update(allowed)
        logger.info("Parsed %s: %d blocked, %d allowed", name, len(blocked), len(allowed))

    # Load custom user lists
    custom_blocked = load_custom_list(CUSTOM_BLOCK_FILE)
    custom_allowed = load_custom_list(CUSTOM_ALLOW_FILE)
    all_blocked.update(custom_blocked)
    all_allowed.update(custom_allowed)

    # Rebuild the filter
    domain_filter.clear()
    domain_filter.load_blocklist(all_blocked)
    domain_filter.load_allowlist(all_allowed)

    logger.info(
        "Filter loaded: %d blocked domains, %d allowed domains",
        domain_filter.blocked_count,
        domain_filter.allowed_count,
    )
    return domain_filter.blocked_count
