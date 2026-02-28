import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_DIR = Path("/usr/local/etc/coreguard")
PID_FILE = CONFIG_DIR / "coreguard.pid"
LOG_FILE = CONFIG_DIR / "coreguard.log"
STATS_FILE = CONFIG_DIR / "stats.json"
DNS_BACKUP_FILE = CONFIG_DIR / "dns-backup.json"
BLOCKLISTS_DIR = CONFIG_DIR / "blocklists"
CUSTOM_ALLOW_FILE = CONFIG_DIR / "custom-allow.txt"
CUSTOM_BLOCK_FILE = CONFIG_DIR / "custom-block.txt"
TEMP_ALLOW_FILE = CONFIG_DIR / "temp-allow.json"
CONFIG_FILE = CONFIG_DIR / "config.toml"

DEFAULT_FILTER_LISTS = [
    {
        "name": "stevenblack-unified",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "enabled": True,
    },
    {
        "name": "adguard-dns",
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "enabled": True,
    },
    {
        "name": "oisd-small",
        "url": "https://small.oisd.nl/domainswild",
        "enabled": True,
    },
    {
        "name": "pete-lowe",
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        "enabled": True,
    },
    {
        "name": "malware-domains",
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
        "enabled": True,
    },
    {
        "name": "energized-ultimate",
        "url": "https://energized.pro/ultimate/formats/hosts.txt",
        "enabled": False,  # Disabled by default — very aggressive, may cause false positives
    },
    {
        "name": "hagezi-multi-pro",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
        "enabled": True,
    },
    {
        "name": "1hosts-lite",
        "url": "https://o0.pages.dev/Lite/hosts.txt",
        "enabled": True,
    },
    {
        "name": "notracking",
        "url": "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
        "enabled": True,
    },
    {
        "name": "dan-pollock",
        "url": "https://someonewhocares.org/hosts/hosts",
        "enabled": True,
    },
    {
        "name": "phishing-army",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "enabled": True,
    },
]


@dataclass
class Schedule:
    name: str = ""
    start: str = "00:00"       # HH:MM 24h
    end: str = "23:59"         # HH:MM 24h
    days: list[str] = field(default_factory=lambda: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
    block_domains: list[str] = field(default_factory=list)
    block_patterns: list[str] = field(default_factory=list)  # wildcards or regex: prefixed
    enabled: bool = True


@dataclass
class UpstreamProvider:
    name: str = "cloudflare"
    doh: str = "https://1.1.1.1/dns-query"
    dot: str = "1.1.1.1"
    plain: str = "1.1.1.1"


DEFAULT_UPSTREAM_PROVIDERS = [
    UpstreamProvider("cloudflare", "https://1.1.1.1/dns-query", "1.1.1.1", "1.1.1.1"),
    UpstreamProvider("google", "https://8.8.8.8/dns-query", "8.8.8.8", "8.8.8.8"),
    UpstreamProvider("quad9", "https://9.9.9.9:5053/dns-query", "9.9.9.9", "9.9.9.9"),
]


@dataclass
class Config:
    # Upstream DNS
    upstream_providers: list = field(default_factory=lambda: list(DEFAULT_UPSTREAM_PROVIDERS))
    upstream_mode: str = "doh"  # "doh", "dot", "plain"
    upstream_timeout: float = 5.0

    # Server
    listen_address: str = "127.0.0.1"
    listen_port: int = 53

    # Filter lists
    filter_lists: list = field(default_factory=lambda: list(DEFAULT_FILTER_LISTS))

    # Auto-update interval in hours (0 = disabled)
    update_interval_hours: int = 24

    # Logging
    log_queries: bool = True
    log_max_size_mb: int = 50

    # Cache
    cache_enabled: bool = True
    cache_max_entries: int = 10_000
    cache_max_ttl: int = 3600
    cache_min_ttl: int = 0

    # CNAME checking
    cname_check_enabled: bool = True
    cname_max_depth: int = 16

    # Dashboard
    dashboard_enabled: bool = True
    dashboard_port: int = 8080
    dashboard_token: str = ""

    # Query database
    query_db_retention_days: int = 7

    # Schedules
    schedules: list = field(default_factory=list)

    # Parental controls
    safe_search_enabled: bool = False
    safe_search_youtube_restrict: str = "moderate"  # "moderate" or "strict"
    content_categories: list[str] = field(default_factory=list)


def ensure_dirs() -> None:
    """Create all required directories and files."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    BLOCKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    for f in (CUSTOM_ALLOW_FILE, CUSTOM_BLOCK_FILE):
        if not f.exists():
            f.touch()


def _config_to_dict(config: Config) -> dict[str, Any]:
    return {
        "upstream": {
            "mode": config.upstream_mode,
            "timeout": config.upstream_timeout,
            "providers": [
                {"name": p.name, "doh": p.doh, "dot": p.dot, "plain": p.plain}
                for p in config.upstream_providers
            ],
        },
        "server": {
            "listen_address": config.listen_address,
            "listen_port": config.listen_port,
        },
        "filter_lists": config.filter_lists,
        "updates": {
            "interval_hours": config.update_interval_hours,
        },
        "logging": {
            "log_queries": config.log_queries,
            "log_max_size_mb": config.log_max_size_mb,
        },
        "cache": {
            "enabled": config.cache_enabled,
            "max_entries": config.cache_max_entries,
            "max_ttl": config.cache_max_ttl,
            "min_ttl": config.cache_min_ttl,
        },
        "cname": {
            "check_enabled": config.cname_check_enabled,
            "max_depth": config.cname_max_depth,
        },
        "dashboard": {
            "enabled": config.dashboard_enabled,
            "port": config.dashboard_port,
            "token": config.dashboard_token,
        },
        "schedules": [
            {
                "name": s.name,
                "start": s.start,
                "end": s.end,
                "days": s.days,
                "block_domains": s.block_domains,
                "block_patterns": s.block_patterns,
                "enabled": s.enabled,
            }
            for s in config.schedules
        ],
        "parental": {
            "safe_search_enabled": config.safe_search_enabled,
            "safe_search_youtube_restrict": config.safe_search_youtube_restrict,
            "content_categories": config.content_categories,
        },
    }


def _dict_to_config(data: dict[str, Any]) -> Config:
    config = Config()
    if "upstream" in data:
        u = data["upstream"]
        config.upstream_mode = u.get("mode", config.upstream_mode)
        config.upstream_timeout = u.get("timeout", config.upstream_timeout)
        if "providers" in u:
            config.upstream_providers = [
                UpstreamProvider(
                    name=p.get("name", "custom"),
                    doh=p.get("doh", ""),
                    dot=p.get("dot", ""),
                    plain=p.get("plain", ""),
                )
                for p in u["providers"]
            ]
        elif "dns" in u:
            # Backward compat: old single-provider format
            config.upstream_providers = [
                UpstreamProvider(
                    name="primary",
                    doh=u.get("dns", "https://1.1.1.1/dns-query"),
                    dot=u.get("dot_server", "1.1.1.1"),
                    plain=u.get("fallback", "1.1.1.1"),
                )
            ]
    if "server" in data:
        s = data["server"]
        config.listen_address = s.get("listen_address", config.listen_address)
        config.listen_port = s.get("listen_port", config.listen_port)
    if "filter_lists" in data:
        config.filter_lists = data["filter_lists"]
    if "updates" in data:
        config.update_interval_hours = data["updates"].get(
            "interval_hours", config.update_interval_hours
        )
    if "logging" in data:
        lg = data["logging"]
        config.log_queries = lg.get("log_queries", config.log_queries)
        config.log_max_size_mb = lg.get("log_max_size_mb", config.log_max_size_mb)
    if "cache" in data:
        c = data["cache"]
        config.cache_enabled = c.get("enabled", config.cache_enabled)
        config.cache_max_entries = c.get("max_entries", config.cache_max_entries)
        config.cache_max_ttl = c.get("max_ttl", config.cache_max_ttl)
        config.cache_min_ttl = c.get("min_ttl", config.cache_min_ttl)
    if "cname" in data:
        cn = data["cname"]
        config.cname_check_enabled = cn.get("check_enabled", config.cname_check_enabled)
        config.cname_max_depth = cn.get("max_depth", config.cname_max_depth)
    if "dashboard" in data:
        db = data["dashboard"]
        config.dashboard_enabled = db.get("enabled", config.dashboard_enabled)
        config.dashboard_port = db.get("port", config.dashboard_port)
        config.dashboard_token = db.get("token", config.dashboard_token)
    if "schedules" in data:
        config.schedules = [
            Schedule(
                name=s.get("name", ""),
                start=s.get("start", "00:00"),
                end=s.get("end", "23:59"),
                days=s.get("days", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]),
                block_domains=s.get("block_domains", []),
                block_patterns=s.get("block_patterns", []),
                enabled=s.get("enabled", True),
            )
            for s in data["schedules"]
        ]
    if "parental" in data:
        p = data["parental"]
        config.safe_search_enabled = p.get("safe_search_enabled", config.safe_search_enabled)
        config.safe_search_youtube_restrict = p.get(
            "safe_search_youtube_restrict", config.safe_search_youtube_restrict
        )
        config.content_categories = p.get("content_categories", config.content_categories)
    return config


def load_config() -> Config:
    """Load config from disk, creating defaults if it doesn't exist."""
    ensure_dirs()
    if not CONFIG_FILE.exists():
        config = Config()
        save_config(config)
        return config
    data = tomllib.loads(CONFIG_FILE.read_text())
    config = _dict_to_config(data)

    # Auto-migrate old config format to current format
    upstream = data.get("upstream", {})
    if "providers" not in upstream or "dashboard" not in data:
        save_config(config)

    return config


def save_config(config: Config) -> None:
    """Save config to disk."""
    ensure_dirs()
    CONFIG_FILE.write_bytes(tomli_w.dumps(_config_to_dict(config)).encode())
