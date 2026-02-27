# Coreguard

[![CI](https://github.com/chris-buckminster/coreguard/actions/workflows/ci.yml/badge.svg)](https://github.com/chris-buckminster/coreguard/actions/workflows/ci.yml)

A lightweight, privacy-focused DNS-based ad and tracker blocker for macOS. Coreguard runs a local DNS server that intercepts queries, blocks known advertising and tracking domains, and forwards legitimate requests through encrypted DNS-over-HTTPS — all from the command line.

## How It Works

Coreguard operates as a local DNS resolver on `127.0.0.1:53`. When any application on your Mac makes a DNS request:

1. The query is checked against a merged blocklist of known ad, tracking, and malware domains.
2. **Blocked domains** receive an immediate `0.0.0.0` response, preventing the connection entirely.
3. **Allowed domains** are forwarded to an upstream resolver via DNS-over-HTTPS (Cloudflare by default), keeping your DNS traffic encrypted and private.

This approach blocks ads and trackers system-wide — across every browser and application — without installing browser extensions or configuring a proxy.

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────────┐
│  Browser /   │──DNS──▶  Coreguard       │──DoH──▶  Cloudflare     │
│  Application │       │  127.0.0.1:53    │       │  1.1.1.1 (HTTPS) │
└──────────────┘       └────────┬─────────┘       └──────────────────┘
                                │
                         Is it blocked?
                           ╱        ╲
                         Yes         No
                          │           │
                     Return 0.0.0.0   Forward upstream
                     (connection      (encrypted, private)
                      fails silently)
```

## Features

- **System-wide blocking** — covers all browsers and applications, not just one
- **Encrypted upstream DNS** — queries forwarded via DNS-over-HTTPS (DoH) by default, with DoT and plain DNS options
- **Multiple upstream providers** — automatic failover across Cloudflare, Google, and Quad9
- **DNS response caching** — local TTL-aware cache makes repeat queries near-instant
- **CNAME flattening** — detects and blocks trackers that hide behind CNAME cloaking
- **Wildcard rules** — pattern matching in custom lists (`*.ads.com`, `ad*.example.com`)
- **11 filter list sources** — ships with curated lists covering ads, trackers, malware, and phishing
- **Automatic updates** — filter lists refresh every 24 hours (configurable)
- **Allowlist and blocklist** — per-domain overrides with a single command
- **One-step unblock** — `unblock` command adds to allowlist and triggers immediate reload
- **Temporary unblock** — `unblock --for 5m` auto-reverts after the specified duration so you never forget to re-block
- **Menubar status agent** — at-a-glance `●`/`○` icon showing daemon health, blocked count, recent blocked domains, and one-click temporary unblock
- **Auto-start on boot** — install as a macOS launchd service with a single command; menubar agent starts automatically at login
- **Health monitoring** — macOS notifications for failures, plus a `doctor` command for diagnostics
- **VPN-safe** — only modifies DNS on physical interfaces (Wi-Fi, Ethernet, USB), leaving VPN tunnels untouched
- **Self-healing DNS** — automatically re-applies DNS settings after sleep/wake or network changes (checked every 60 seconds)
- **Live query logging** — see exactly what's being blocked in real time
- **Web dashboard** — full management UI at `http://127.0.0.1:8080` — view stats, manage domains, toggle filter lists, trigger updates, and stop the daemon from the browser
- **JSON output** — `--json` flag on every command for scripting and automation (`coreguard status --json | jq`)
- **Statistics** — track total queries, block rate, cache hit rate, and top blocked domains
- **Graceful DNS restore** — original DNS settings are backed up and restored on stop
- **Foreground mode** — run interactively for debugging and testing
- **Minimal footprint** — pure Python, no background services beyond the daemon itself

## Requirements

- macOS 10.15 (Catalina) or later
- Python 3.10+
- Root privileges (required for binding port 53 and configuring system DNS)

## Installation

### Homebrew (recommended)

```bash
brew tap chris-buckminster/coreguard
brew install coreguard
```

The `coreguard` command is added to your PATH automatically. Upgrades are handled by `brew upgrade`.

### From Source

```bash
git clone https://github.com/chris-buckminster/coreguard.git
cd coreguard
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

When installed from source, reference the venv binary with sudo:

```bash
sudo .venv/bin/coreguard <command>
```

## Quick Start

```bash
# Start blocking (requires sudo)
sudo coreguard start

# Verify it's working
dig @127.0.0.1 ads.doubleclick.net   # Should return 0.0.0.0
dig @127.0.0.1 github.com            # Should return the real IP

# Check status
coreguard status

# Stop and restore original DNS settings
sudo coreguard stop
```

## Usage

### Starting and Stopping

```bash
# Start as a background daemon
sudo coreguard start

# Start in the foreground (useful for debugging)
sudo coreguard start --foreground

# Stop the daemon and restore DNS
sudo coreguard stop

# Check if coreguard is running (no sudo required)
coreguard status
```

### Auto-Start on Boot

```bash
# Install as a macOS launchd service
sudo coreguard install

# Or use Homebrew services (if installed via brew)
sudo brew services start coreguard

# Remove the service
sudo coreguard uninstall
```

Once installed, coreguard starts automatically when your Mac boots and will restart itself if it crashes. A menubar status agent is also installed and starts at login, showing daemon health at a glance.

### Menubar Status Agent

When you start or install coreguard, a lightweight menubar agent launches automatically. It shows:

- **`●`** when the daemon is running, **`○`** when stopped
- Blocked query count
- **Recent Blocked** submenu — the last 5 unique blocked domains, each clickable to temporarily unblock for 5 minutes (triggers a standard macOS admin password prompt)
- Quick "Open Dashboard" link

The agent polls every 5 seconds and runs as a separate user-level process. It auto-starts at login via a LaunchAgent — no extra setup required.

### Managing Domains

```bash
# Allow a domain (prevents it from being blocked)
sudo coreguard allow example.com

# Block a domain manually
sudo coreguard block annoying-site.com

# Unblock a domain (adds to allowlist + triggers immediate reload)
sudo coreguard unblock broken-site.com

# Temporarily unblock a domain (auto-reverts after duration)
sudo coreguard unblock broken-site.com --for 5m   # 5 minutes
sudo coreguard unblock broken-site.com --for 1h   # 1 hour
sudo coreguard unblock broken-site.com --for 30s  # 30 seconds

# Apply changes to a running instance
sudo coreguard update
```

Allowlist entries cover the domain and all of its subdomains. For example, allowing `example.com` will also allow `cdn.example.com`, `api.example.com`, and so on.

### Wildcard Rules

Custom block and allow lists support wildcard patterns using `*`:

```
# In custom-block.txt or custom-allow.txt
*.ads.com              # Matches foo.ads.com, a.b.ads.com (not ads.com itself)
ad*.example.com        # Matches ads.example.com, adserver.example.com
tracking.*.cdn.net     # Matches tracking.us.cdn.net, tracking.eu.cdn.net
```

Leading `*.` matches any number of subdomain labels. A `*` elsewhere matches within a single DNS label (no dots). Plain entries without `*` work exactly as before.

### Filter Lists

```bash
# View all configured filter lists
coreguard lists

# Add a new filter list
sudo coreguard add-list https://example.com/blocklist.txt --name my-list

# Remove a filter list
sudo coreguard remove-list my-list

# Force an immediate update of all lists
sudo coreguard update
```

### Health Check

```bash
# Run diagnostics (no sudo required)
coreguard doctor
```

The `doctor` command checks:
- Whether the daemon is running (detected via port 53 probe — works without sudo)
- Whether system DNS is correctly pointing to coreguard
- Whether port 53 is responding
- Whether filter lists are cached and up to date
- Whether the launchd service is installed
- Log file status

### Dashboard

When coreguard is running, a web dashboard is available at `http://127.0.0.1:8080`. It provides a full management UI with five tabs:

- **Overview** — stat cards (total queries, blocked count, block rate, cache hit rate, cache size, CNAME blocks), top blocked/queried domain tables
- **Queries** — searchable, filterable query log with status badges
- **Domains** — add/remove allowlist and blocklist entries, create temporary allows with a duration
- **Lists** — enable/disable filter lists, add/remove list sources, trigger updates
- **Settings** — view configuration, clear DNS cache, copy dashboard token, stop daemon

The dashboard auto-refreshes every 5 seconds and runs on localhost only.

#### Authentication

All read-only views (stats, queries, config) work without authentication. Mutating actions (adding domains, toggling lists, stopping the daemon) require a token. This prevents other apps or malicious websites from silently modifying your configuration.

A token is auto-generated on first start and saved to `config.toml`. To retrieve it:

```bash
grep token /usr/local/etc/coreguard/config.toml
```

It's also printed when starting in foreground mode:

```bash
sudo coreguard start --foreground
# Dashboard: http://127.0.0.1:8080 (token: a1b2c3d4...)
```

Open the dashboard, paste the token into the login prompt, and click Login. The token is stored in your browser's localStorage so you only need to enter it once.

#### Configuration

Disable the dashboard or change the port in `config.toml`:

```toml
[dashboard]
enabled = true
port = 8080
```

### JSON Output

Every command supports a `--json` flag that emits a single JSON object instead of human-readable text. This enables scripting, automation, and integration with tools like `jq`:

```bash
# Check status programmatically
coreguard status --json | jq '.stats.blocked_queries'

# List filter list names
coreguard lists --json | jq '.filter_lists[].name'

# Find failing health checks
coreguard doctor --json | jq '.checks[] | select(.status != "ok")'

# Read recent log entries as JSON
coreguard log --json -n 100 | jq '.lines[]'

# All action commands work too
sudo coreguard allow example.com --json
sudo coreguard block evil.com --json
sudo coreguard unblock site.com --for 5m --json
```

Every JSON response includes a `"status"` field (`"ok"` or `"error"`) plus command-specific fields. Exit codes are set appropriately for machine consumption.

> **Note:** `--json` is incompatible with `log --follow` since follow mode is inherently streaming.

### Logs and Statistics

```bash
# View the last 20 log entries
coreguard log

# Follow the log in real time
coreguard log -f

# Show the last 50 entries
coreguard log -n 50

# View blocking statistics
coreguard status
```

Log entries follow this format:

```
2026-02-24 14:30:01 BLOCKED A ads.doubleclick.net
2026-02-24 14:30:01 ALLOWED A github.com
2026-02-24 14:30:02 BLOCKED AAAA analytics.google.com
```

## Default Filter Lists

Coreguard ships with 11 filter list sources. Ten are enabled by default:

| List | Domains | Focus | Default |
|------|---------|-------|---------|
| **Steven Black Unified** | ~130K | Ads, malware, fakenews, gambling | Enabled |
| **HaGeZi Multi Pro** | ~150K | Comprehensive ads, trackers, malware | Enabled |
| **1Hosts Lite** | ~90K | Balanced ad and tracker blocking | Enabled |
| **AdGuard DNS Filter** | ~50K | Ads and trackers | Enabled |
| **NoTracking** | ~40K | Tracking and telemetry | Enabled |
| **OISD Small** | ~30K | Tracking and telemetry | Enabled |
| **Dan Pollock's Hosts** | ~15K | Long-running, conservative ad list | Enabled |
| **Phishing Army** | ~10K | Known phishing domains | Enabled |
| **Pete Lowe's Blocklist** | ~3K | Conservative ad blocking | Enabled |
| **URLhaus Malware Filter** | ~1.5K | Known malware domains | Enabled |
| **Energized Ultimate** | ~500K+ | Aggressive, broad blocking | Disabled |

The Energized Ultimate list is disabled by default because its aggressive scope may cause false positives on some websites. Enable it in `/usr/local/etc/coreguard/config.toml` if you prefer maximum coverage.

All lists are deduplicated and merged at load time. Adding more lists does not affect query performance — domain lookups are O(1) hash table checks regardless of list size.

## Notifications

Coreguard sends macOS notification center alerts when critical issues occur:

- **Startup failure** — if the DNS server can't bind to port 53 or otherwise fails to start
- **DNS misconfiguration** — if system DNS stops pointing to coreguard and automatic re-apply fails
- **Filter list update failure** — if all filter list downloads fail during an update cycle

Notifications appear as standard macOS banners. No additional software is required.

## Configuration

Coreguard stores its configuration and runtime data in `/usr/local/etc/coreguard/`:

```
/usr/local/etc/coreguard/
├── config.toml          # Main configuration file
├── blocklists/          # Cached filter list downloads
├── custom-allow.txt     # Your allowlisted domains
├── custom-block.txt     # Your manually blocked domains
├── temp-allow.json      # Temporarily unblocked domains (auto-expiring)
├── coreguard.log        # Query log
├── coreguard.pid        # Daemon PID file
├── dns-backup.json      # Original DNS settings (for restore)
└── stats.json           # Query statistics
```

### Configuration Options

The `config.toml` file is created automatically on first run with sensible defaults. Key options:

```toml
[upstream]
mode = "doh"                          # "doh", "dot", or "plain"
timeout = 5.0                         # Upstream query timeout (seconds)

# Providers are tried in order; if one fails, the next is used automatically.
[[upstream.providers]]
name = "cloudflare"
doh = "https://1.1.1.1/dns-query"
dot = "1.1.1.1"
plain = "1.1.1.1"

[[upstream.providers]]
name = "google"
doh = "https://8.8.8.8/dns-query"
dot = "8.8.8.8"
plain = "8.8.8.8"

[[upstream.providers]]
name = "quad9"
doh = "https://9.9.9.9:5053/dns-query"
dot = "9.9.9.9"
plain = "9.9.9.9"

[server]
listen_address = "127.0.0.1"
listen_port = 53

[updates]
interval_hours = 24    # Auto-update interval (0 to disable)

[cache]
enabled = true
max_entries = 10000     # Maximum cached responses
max_ttl = 3600          # Cap TTL at 1 hour
min_ttl = 0             # Minimum TTL floor

[cname]
check_enabled = true    # Inspect CNAME chains for blocked targets
max_depth = 16          # Maximum CNAME hops to check

[logging]
log_queries = true
log_max_size_mb = 50

[dashboard]
enabled = true
port = 8080              # Web dashboard port
```

### Upstream DNS Options

| Mode | Description | Privacy | Compatibility |
|------|-------------|---------|---------------|
| `doh` | DNS-over-HTTPS (default) | Encrypted, blends with HTTPS traffic | Best |
| `dot` | DNS-over-TLS on port 853 | Encrypted | May be blocked by some networks |
| `plain` | Traditional unencrypted DNS | None | Universal |

Coreguard ships with three upstream providers (Cloudflare, Google, Quad9) and tries them in order. If all providers fail with the primary mode (DoH/DoT), it falls back to plain DNS with each provider before giving up. You can add, remove, or reorder providers in `config.toml`.

## How Blocking Works

When a blocked domain is queried:

- **A records** (IPv4): Returns `0.0.0.0`
- **AAAA records** (IPv6): Returns `::`
- **Other record types**: Returns an empty response with `NOERROR` status

This approach is more compatible than returning `NXDOMAIN`, which can cause aggressive retries in some applications. The `0.0.0.0` response causes connections to fail silently and quickly.

Domain matching checks the full hierarchy — blocking `ads.example.com` also blocks `sub.ads.example.com` and any deeper subdomains, without blocking `example.com` itself.

### CNAME Flattening

Some trackers use CNAME cloaking to evade DNS-level blocking. For example, `tracker.example.com` might CNAME to `t.ads.net`, which is on the blocklist. Coreguard inspects the full CNAME chain in upstream responses and blocks queries whose targets resolve to blocked domains. This is enabled by default and configurable via `config.toml`.

### DNS Response Caching

Coreguard maintains a local cache of DNS responses, making repeat queries near-instant. The cache is TTL-aware, thread-safe, and automatically sweeps expired entries. Cache is cleared on blocklist reload to prevent serving stale data for newly-blocked domains. Cache statistics are visible via `coreguard status`.

### DNS-Level vs. Browser-Level Blocking

Coreguard blocks at the DNS level, which means it prevents connections to ad-serving domains across your entire system. However, DNS blocking cannot remove the empty HTML containers left behind on web pages where ads would have appeared, or hide cookie consent banners. For cosmetic cleanup, pair coreguard with a lightweight browser extension like uBlock Origin. The two complement each other — coreguard handles system-wide network-level blocking, while the extension handles in-page visual cleanup.

## Troubleshooting

### Run the doctor

The fastest way to diagnose issues:

```bash
coreguard doctor
```

This checks all critical components and reports any problems with suggested fixes.

### Port 53 is already in use

```bash
sudo lsof -i :53
```

On macOS, `mDNSResponder` may occupy port 53. Coreguard is designed to coexist with it by binding specifically to `127.0.0.1:53`.

### DNS not restoring after a crash

If coreguard exits uncleanly, your DNS may still point to `127.0.0.1`. When installed as a launchd service, coreguard will automatically restart within 10 seconds and resume normal operation. For manual installations, run:

```bash
sudo coreguard stop
```

This will detect the backup file and restore your original DNS settings even if the daemon isn't running. Coreguard also automatically restores stale DNS settings on the next startup.

### A website is broken

The site may be on a blocklist. The quickest fix is the **menubar**: click the `●` icon, open **Recent Blocked**, and click the domain — it's unblocked for 5 minutes with a single click.

From the terminal:

```bash
sudo coreguard unblock broken-site.com   # Adds to allowlist + reloads immediately
```

If you only need temporary access (e.g. completing a purchase), use `--for` so it auto-reverts:

```bash
sudo coreguard unblock broken-site.com --for 5m
```

To investigate first:

```bash
coreguard log -n 50                    # Look for the domain being blocked
sudo coreguard unblock the-domain      # Unblock it
```

### Verifying coreguard is active

```bash
# Should return 0.0.0.0 (blocked)
dig @127.0.0.1 ads.doubleclick.net +short

# Should return a real IP (allowed)
dig @127.0.0.1 google.com +short

# Check system DNS configuration
networksetup -getdnsservers Wi-Fi
```

## Uninstalling

To completely remove coreguard and undo all changes it made to your system:

### 1. Stop the daemon and restore DNS settings

```bash
sudo coreguard stop
```

This stops the DNS server and restores your original DNS settings. Verify with:

```bash
networksetup -getdnsservers Wi-Fi
# Should show your original DNS servers (e.g. your router's IP), not 127.0.0.1
```

### 2. Remove the launchd service (if installed)

```bash
sudo coreguard uninstall
```

This unloads and deletes `/Library/LaunchDaemons/com.coreguard.daemon.plist`.

### 3. Remove the menubar agent

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.coreguard.status.plist 2>/dev/null
rm -f ~/Library/LaunchAgents/com.coreguard.status.plist
```

### 4. Remove configuration and data

```bash
sudo rm -rf /usr/local/etc/coreguard
```

This deletes the config file, blocklists, custom allow/block lists, query log, SQLite database, PID file, DNS backup, and stats.

### 5. Uninstall the package

**Homebrew:**

```bash
brew uninstall coreguard
brew untap chris-buckminster/coreguard
```

**From source:**

```bash
rm -rf /path/to/coreguard  # wherever you cloned it
```

## Development

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## License

MIT
