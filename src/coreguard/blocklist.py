import json
import logging
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from coreguard.config import BLOCKLISTS_DIR, CUSTOM_ALLOW_FILE, CUSTOM_BLOCK_FILE, TEMP_ALLOW_FILE, Config
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


def _resolve_via_upstream(hostname: str, upstream: str = "1.1.1.1") -> str:
    """Resolve a hostname using a specific DNS server, bypassing system DNS."""
    import os
    import struct

    # Build a minimal DNS query
    tx_id = os.urandom(2)
    flags = b'\x01\x00'  # Standard query, recursion desired
    counts = struct.pack('!4H', 1, 0, 0, 0)  # 1 question
    qname = b''
    for label in hostname.encode().split(b'.'):
        qname += bytes([len(label)]) + label
    qname += b'\x00'
    qtype_qclass = struct.pack('!2H', 1, 1)  # A record, IN class
    query = tx_id + flags + counts + qname + qtype_qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(query, (upstream, 53))
        data, _ = sock.recvfrom(4096)
        data_len = len(data)

        if data_len < 12:
            raise RuntimeError("DNS response too short")

        # Parse header
        answer_count = struct.unpack('!H', data[6:8])[0]

        # Skip question section (after 12-byte header)
        offset = 12
        while offset < data_len and data[offset] != 0:
            label_len = data[offset]
            offset += label_len + 1
        offset += 5  # null byte + qtype (2) + qclass (2)

        # Parse answer records
        for _ in range(min(answer_count, 64)):  # Cap iterations
            if offset + 2 > data_len:
                break
            # Skip name (may be pointer-compressed)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < data_len and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1  # null terminator

            if offset + 10 > data_len:
                break
            rtype, rclass, ttl, rdlength = struct.unpack('!HHiH', data[offset:offset + 10])
            offset += 10

            if offset + rdlength > data_len:
                break
            if rtype == 1 and rdlength == 4:  # A record
                ip = '.'.join(str(b) for b in data[offset:offset + 4])
                return ip
            offset += rdlength
    finally:
        sock.close()
    raise RuntimeError(f"Could not resolve {hostname} via {upstream}")


class _DirectDNSTransport(httpx.HTTPTransport):
    """HTTP transport that resolves hostnames via a specific DNS server (1.1.1.1)
    instead of system DNS, avoiding circular dependency when system DNS points to coreguard."""

    def __init__(self, upstream_dns: str = "1.1.1.1", **kwargs):
        self._upstream_dns = upstream_dns
        self._resolve_cache: dict[str, str] = {}
        super().__init__(**kwargs)

    def _resolve(self, hostname: str) -> str:
        if hostname in self._resolve_cache:
            return self._resolve_cache[hostname]
        ip = _resolve_via_upstream(hostname, self._upstream_dns)
        self._resolve_cache[hostname] = ip
        return ip

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.url.host
        # Only override for non-IP hostnames
        if hostname and not _is_ip(hostname):
            ip = self._resolve(hostname)
            # Swap the host in the URL to the resolved IP, keep everything else
            request.url = request.url.copy_with(host=ip)
            # Ensure the original hostname is used for TLS SNI and Host header
            request.headers["Host"] = hostname
        return super().handle_request(request)


def _is_ip(hostname: str) -> bool:
    """Check if a string is an IP address."""
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


def download_list(url: str, timeout: float = 30.0) -> str:
    """Download a filter list, resolving DNS directly via 1.1.1.1 to bypass system DNS."""
    try:
        transport = _DirectDNSTransport(verify=True)
        with httpx.Client(timeout=timeout, follow_redirects=True, transport=transport) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text
    except Exception as e:
        logger.debug("Direct DNS download failed (%s), trying system DNS", e)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text


def load_custom_list(path: Path) -> tuple[set[str], list[str]]:
    """Load a custom allow/block list (one domain per line).

    Returns (plain_domains, wildcard_patterns). Entries containing '*'
    are treated as wildcard patterns.
    """
    if not path.exists():
        return set(), []
    domains: set[str] = set()
    wildcards: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entry = line.lower().strip(".")
            if "*" in entry:
                wildcards.append(entry)
            else:
                domains.add(entry)
    return domains, wildcards


def load_temp_allow_list(path: Path) -> set[str]:
    """Load temporarily allowed domains from JSON file.

    Returns domains whose expiry timestamp is still in the future.
    """
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    now = time.time()
    return {domain for domain, expires in data.items() if expires > now}


def update_all_lists(config: Config, domain_filter: DomainFilter) -> int:
    """Download and parse all enabled filter lists, rebuild the domain filter.

    Returns the total number of blocked domains loaded.
    """
    all_blocked: set[str] = set()
    all_allowed: set[str] = set()
    download_failures = 0
    enabled_count = sum(1 for f in config.filter_lists if f.get("enabled", True))

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
            download_failures += 1
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
    custom_blocked, blocked_wildcards = load_custom_list(CUSTOM_BLOCK_FILE)
    custom_allowed, allowed_wildcards = load_custom_list(CUSTOM_ALLOW_FILE)
    all_blocked.update(custom_blocked)
    all_allowed.update(custom_allowed)

    # Load temporarily allowed domains
    temp_allowed = load_temp_allow_list(TEMP_ALLOW_FILE)
    all_allowed.update(temp_allowed)

    # Rebuild the filter
    domain_filter.clear()
    domain_filter.load_blocklist(all_blocked)
    domain_filter.load_allowlist(all_allowed)
    domain_filter.load_blocklist_wildcards(blocked_wildcards)
    domain_filter.load_allowlist_wildcards(allowed_wildcards)

    logger.info(
        "Filter loaded: %d blocked domains, %d allowed domains",
        domain_filter.blocked_count,
        domain_filter.allowed_count,
    )

    # Send notification if most downloads failed
    if download_failures > 0 and download_failures >= enabled_count:
        try:
            from coreguard.notify import notify_lists_update_failed
            notify_lists_update_failed()
        except Exception:
            pass

    return domain_filter.blocked_count
