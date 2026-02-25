import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_DIR = Path.home() / ".config" / "coreguard"
PID_FILE = CONFIG_DIR / "coreguard.pid"
LOG_FILE = CONFIG_DIR / "coreguard.log"
STATS_FILE = CONFIG_DIR / "stats.json"
DNS_BACKUP_FILE = CONFIG_DIR / "dns-backup.json"
BLOCKLISTS_DIR = CONFIG_DIR / "blocklists"
CUSTOM_ALLOW_FILE = CONFIG_DIR / "custom-allow.txt"
CUSTOM_BLOCK_FILE = CONFIG_DIR / "custom-block.txt"
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
]


@dataclass
class Config:
    # Upstream DNS
    upstream_dns: str = "https://cloudflare-dns.com/dns-query"
    upstream_fallback: str = "1.1.1.1"
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
            "dns": config.upstream_dns,
            "fallback": config.upstream_fallback,
            "mode": config.upstream_mode,
            "timeout": config.upstream_timeout,
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
    }


def _dict_to_config(data: dict[str, Any]) -> Config:
    config = Config()
    if "upstream" in data:
        u = data["upstream"]
        config.upstream_dns = u.get("dns", config.upstream_dns)
        config.upstream_fallback = u.get("fallback", config.upstream_fallback)
        config.upstream_mode = u.get("mode", config.upstream_mode)
        config.upstream_timeout = u.get("timeout", config.upstream_timeout)
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
    return config


def load_config() -> Config:
    """Load config from disk, creating defaults if it doesn't exist."""
    ensure_dirs()
    if not CONFIG_FILE.exists():
        config = Config()
        save_config(config)
        return config
    data = tomllib.loads(CONFIG_FILE.read_text())
    return _dict_to_config(data)


def save_config(config: Config) -> None:
    """Save config to disk."""
    ensure_dirs()
    CONFIG_FILE.write_bytes(tomli_w.dumps(_config_to_dict(config)).encode())
