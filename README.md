# Coreguard

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
- **11 filter list sources** — ships with curated lists covering ads, trackers, malware, and phishing
- **Automatic updates** — filter lists refresh every 24 hours (configurable)
- **Allowlist and blocklist** — per-domain overrides with a single command
- **Auto-start on boot** — install as a macOS launchd service with a single command
- **Health monitoring** — macOS notifications for failures, plus a `doctor` command for diagnostics
- **Live query logging** — see exactly what's being blocked in real time
- **Statistics** — track total queries, block rate, and top blocked domains
- **Graceful DNS restore** — original DNS settings are backed up and restored on stop
- **Foreground mode** — run interactively for debugging and testing
- **Minimal footprint** — pure Python, no background services beyond the daemon itself

## Requirements

- macOS 10.15 (Catalina) or later
- Python 3.9+
- Root privileges (required for binding port 53 and configuring system DNS)

## Installation

```bash
# Clone the repository
git clone https://github.com/chris-buckminster/coreguard.git
cd coreguard

# Create a virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After installation, the `coreguard` command is available in your shell. When using `sudo`, reference the venv binary directly:

```bash
sudo .venv/bin/coreguard <command>
```

## Quick Start

```bash
# Start blocking (requires sudo)
sudo .venv/bin/coreguard start

# Verify it's working
dig @127.0.0.1 ads.doubleclick.net   # Should return 0.0.0.0
dig @127.0.0.1 github.com            # Should return the real IP

# Check status
coreguard status

# Stop and restore original DNS settings
sudo .venv/bin/coreguard stop
```

## Usage

### Starting and Stopping

```bash
# Start as a background daemon
sudo .venv/bin/coreguard start

# Start in the foreground (useful for debugging)
sudo .venv/bin/coreguard start --foreground

# Stop the daemon and restore DNS
sudo .venv/bin/coreguard stop

# Check if coreguard is running
coreguard status
```

### Auto-Start on Boot

```bash
# Install as a macOS launchd service
sudo .venv/bin/coreguard install

# Remove the service
sudo .venv/bin/coreguard uninstall
```

Once installed, coreguard starts automatically when your Mac boots and will restart itself if it crashes.

### Managing Domains

```bash
# Allow a domain (prevents it from being blocked)
coreguard allow example.com

# Block a domain manually
coreguard block annoying-site.com

# Apply changes to a running instance
sudo .venv/bin/coreguard update
```

Allowlist entries cover the domain and all of its subdomains. For example, `coreguard allow example.com` will also allow `cdn.example.com`, `api.example.com`, and so on.

### Filter Lists

```bash
# View all configured filter lists
coreguard lists

# Add a new filter list
coreguard add-list https://example.com/blocklist.txt --name my-list

# Remove a filter list
coreguard remove-list my-list

# Force an immediate update of all lists
sudo .venv/bin/coreguard update
```

### Health Check

```bash
# Run diagnostics
coreguard doctor
```

The `doctor` command checks:
- Whether the daemon is running
- Whether system DNS is correctly pointing to coreguard
- Whether port 53 is responding
- Whether filter lists are cached and up to date
- Whether the launchd service is installed
- Log file status

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

The Energized Ultimate list is disabled by default because its aggressive scope may cause false positives on some websites. Enable it in `~/.config/coreguard/config.toml` if you prefer maximum coverage.

All lists are deduplicated and merged at load time. Adding more lists does not affect query performance — domain lookups are O(1) hash table checks regardless of list size.

## Notifications

Coreguard sends macOS notification center alerts when critical issues occur:

- **Startup failure** — if the DNS server can't bind to port 53 or otherwise fails to start
- **DNS misconfiguration** — if system DNS stops pointing to coreguard while the daemon is running (checked every 5 minutes)
- **Filter list update failure** — if all filter list downloads fail during an update cycle

Notifications appear as standard macOS banners. No additional software is required.

## Configuration

Coreguard stores its configuration and runtime data in `~/.config/coreguard/`:

```
~/.config/coreguard/
├── config.toml          # Main configuration file
├── blocklists/          # Cached filter list downloads
├── custom-allow.txt     # Your allowlisted domains
├── custom-block.txt     # Your manually blocked domains
├── coreguard.log        # Query log
├── coreguard.pid        # Daemon PID file
├── dns-backup.json      # Original DNS settings (for restore)
└── stats.json           # Query statistics
```

### Configuration Options

The `config.toml` file is created automatically on first run with sensible defaults. Key options:

```toml
[upstream]
dns = "https://1.1.1.1/dns-query"    # DoH endpoint (IP-based to avoid circular DNS)
fallback = "1.1.1.1"                  # Plain DNS fallback
mode = "doh"                          # "doh", "dot", or "plain"
timeout = 5.0                         # Upstream query timeout (seconds)

[server]
listen_address = "127.0.0.1"
listen_port = 53

[updates]
interval_hours = 24    # Auto-update interval (0 to disable)

[logging]
log_queries = true
log_max_size_mb = 50
```

### Upstream DNS Options

| Mode | Description | Privacy | Compatibility |
|------|-------------|---------|---------------|
| `doh` | DNS-over-HTTPS (default) | Encrypted, blends with HTTPS traffic | Best |
| `dot` | DNS-over-TLS on port 853 | Encrypted | May be blocked by some networks |
| `plain` | Traditional unencrypted DNS | None | Universal |

If DoH or DoT fails, Coreguard automatically falls back to plain DNS to avoid connectivity loss.

## How Blocking Works

When a blocked domain is queried:

- **A records** (IPv4): Returns `0.0.0.0`
- **AAAA records** (IPv6): Returns `::`
- **Other record types**: Returns an empty response with `NOERROR` status

This approach is more compatible than returning `NXDOMAIN`, which can cause aggressive retries in some applications. The `0.0.0.0` response causes connections to fail silently and quickly.

Domain matching checks the full hierarchy — blocking `ads.example.com` also blocks `sub.ads.example.com` and any deeper subdomains, without blocking `example.com` itself.

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

If coreguard exits uncleanly, your DNS may still point to `127.0.0.1`. Run:

```bash
sudo .venv/bin/coreguard stop
```

This will detect the backup file and restore your original DNS settings even if the daemon isn't running. Coreguard also automatically restores stale DNS settings on the next startup.

### A website is broken

The site may be on a blocklist. Check the log and add it to your allowlist:

```bash
coreguard log -n 50                          # Look for the domain being blocked
coreguard allow broken-site.com              # Allowlist it
sudo .venv/bin/coreguard update              # Apply the change
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

## Development

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## License

MIT
