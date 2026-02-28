# Coreguard Roadmap

## Phase 1 — Strengthen the foundation

**Test coverage** *(done)*
- [x] Add tests for `daemon.py` (fork/daemonize, PID management, signal handling, main loop)
- [x] Add tests for `notify.py` and `logging_config.py`
- [x] Add integration tests for the full start→block→stop flow

**Release automation** *(done)*
- [x] GitHub Actions workflow triggered on `v*` tag push
- [x] Creates a GitHub release, computes tarball SHA256, opens a PR against the Homebrew tap to update the formula

**CI** *(done)*
- [x] GitHub Actions CI workflow (Python 3.10–3.12, macOS)
- [x] CI status badge in README

---

## Phase 2 — Differentiate from competitors

**Menubar status agent** *(done)*
- [x] Lightweight macOS menubar icon using `rumps` (~100 lines MVP)
- [x] Unicode dot icon showing daemon health (● running / ○ stopped)
- [x] Menu: status, blocked count, "Open Dashboard", quit
- [x] Separate process from daemon, auto-started via LaunchAgent plist
- [x] Ships as `coreguard-status` in the Homebrew formula

**Temporary allowlisting with auto-revert** *(done)*
- [x] `coreguard unblock example.com --for 5m`
- [x] Timer-based auto-revert so users never forget to re-block

**JSON output on all CLI commands** *(done)*
- [x] `--json` flag on `status`, `lists`, `log`, `doctor`, etc.
- [x] Enables scripting and automation (`coreguard status --json | jq`)
- [x] Proper exit codes for machine consumption

---

## Phase 3 — Smart blocking & management UI

**Breakage quick-unblock (menubar integration)** *(done)*
- [x] "Last 5 blocked domains" submenu in the menubar agent
- [x] One-click temporary allowlist from the menu

**Web dashboard with full management** *(done)*
- [x] Evolve the current read-only dashboard into a control panel
- [x] Allow/block domains, enable/disable filter lists, trigger updates, start/stop daemon
- [x] Aimed at users who aren't comfortable with CLI tooling
- [x] Authentication required (no longer read-only)

**Dashboard query history graph** *(done)*
- [x] "Queries over last 24 hours" stacked bar chart on the Overview tab
- [x] Canvas-based, dark-themed, responsive with hover tooltips
- [x] `/api/history` endpoint — log-parsed, 10-minute buckets, 60-second cache

**Comprehensive dashboard improvements** *(done)*
- [x] Query type breakdown donut chart (A, AAAA, CNAME, etc.)
- [x] Live counter animation on stat cards (ease-out, 500ms)
- [x] Dynamic favicon reflecting block rate
- [x] Click-to-filter from history chart to queries tab
- [x] Per-domain drill-down (clickable domains throughout UI)
- [x] Sparklines on stat cards (last 12 buckets / 2 hours)
- [x] Query log pagination with offset/limit/has_more
- [x] CSV/JSON export of query log (`/api/queries/export`)
- [x] Client tracking (client IP in stats, top clients table, filter by client)
- [x] Server-Sent Events for real-time query streaming (`/api/stream`)
- [x] SQLite-backed query logging (`query_db.py`) with batched writes, retention, log import

**Regex-based blocking rules** *(done)*
- [x] Custom rules beyond wildcards (`regex:` prefix in custom list files)
- [x] `--regex` flag on `block` and `allow` CLI commands
- [x] Dashboard support for regex entries

**Time-based / scheduled filtering** *(done)*
- [x] `Schedule` config with time windows, day-of-week, and block rules
- [x] Overnight schedule support (e.g. 21:00–06:00)
- [x] Snapshot/restore filter state with schedule overlay
- [x] Automatic schedule transitions in daemon main loop

**Parental controls / safe search** *(done)*
- [x] Enforce SafeSearch on Google, YouTube, Bing, DuckDuckGo via DNS CNAME rewrites
- [x] YouTube moderate/strict restriction modes
- [x] Google country variant support (www.google.co.uk, www.google.de, etc.)
- [x] Optional content category blocking (adult, gambling, social)
- [x] `coreguard parental safesearch --enable/--disable` CLI command
- [x] `coreguard parental categories --add/--remove` CLI command
- [x] Dashboard `/api/parental` endpoint for toggling settings

---

## Phase 4 — Observability & data

**Database-backed query logging** *(done)*
- [x] SQLite (fits the single-machine, self-contained philosophy — no external DB server)
- [x] Enables richer dashboard queries: search, filter by time range, per-domain history
- [x] Migration path from current flat-file logging

**Prometheus / metrics export** *(done)*
- [x] `/metrics` endpoint in Prometheus exposition format
- [x] Query rates, block rates, cache hit ratio, upstream latency, list sizes
- [x] Enables Grafana dashboards and alerting for power users

---

## Phase 5 — Advanced protocol & security

**DNSSEC validation** *(done)*
- [x] Set DO (DNSSEC OK) bit on outgoing queries via EDNS0
- [x] Check AD (Authenticated Data) flag on upstream responses
- [x] Strict mode: reject AD=0 responses as SERVFAIL
- [x] DNSSEC stats (validated/failed counters) and Prometheus metrics
- [x] `coreguard dnssec --enable/--disable --strict/--no-strict` CLI command

**DNS-over-QUIC (DoQ)** *(done)*
- [x] DNS-over-QUIC transport via `aioquic` (RFC 9250)
- [x] `doq` field on upstream providers, `upstream_mode = "doq"` support
- [x] Multi-provider failover with DoQ, plain DNS fallback

---

## Phase 5.5 — Dashboard polish *(done)*

**Live updates** *(done)*
- [x] Stat cards and query feed refresh every 1 second
- [x] Charts refresh every 5 seconds
- [x] Use existing SSE stream and periodic fetch

**Dark / light mode** *(done)*
- [x] Auto-detect system preference via `prefers-color-scheme`
- [x] Manual toggle with localStorage persistence
- [x] Full theme coverage across all dashboard elements

**Visual refresh** *(done)*
- [x] Clean, modern design pass (typography, spacing, color palette, card layout)
- [x] Single-file architecture preserved (all HTML/CSS/JS inline)

**Built-in Help tab** *(done)*
- [x] User-friendly guide inside the dashboard for non-power users
- [x] Explains what coreguard does and how to use each feature

---

## Phase 5.6 — Hardening & reliability audit *(done)*

**Full codebase audit** *(done)*
- [x] Review all source files for reliability concerns (race conditions, resource leaks, crash scenarios)
- [x] Identify and fix error handling gaps (swallowed exceptions, missing timeouts, unhandled edge cases)
- [x] Harden against network failures, disk full, permission errors, and malformed DNS input
- [x] Audit for security concerns (input validation, injection points, unsafe defaults)

**Test coverage** *(done)*
- [x] Identify important code paths without tests and add coverage
- [x] Add stress/edge-case tests (truncated responses, large payloads, concurrent queries)

**Performance review** *(done)*
- [x] Check for blocking I/O in hot paths, lock contention, and unbounded growth
- [x] Profile and optimize where needed

---

## Phase 6 — Polish & hardening

**Configurable block response IP**
- [ ] Allow users to choose `127.0.0.1` instead of `0.0.0.0` for blocked domains
- [ ] Config option in `config.toml`

**Dashboard token rotation**
- [ ] "Regenerate Token" button in the dashboard Settings tab
- [ ] Invalidates old token immediately, displays new one

**DNS label length validation**
- [ ] Validate domain labels during blocklist parsing (max 63 chars per label, 253 total)
- [ ] Log and skip malformed entries instead of loading them

**Per-provider DNSSEC policy**
- [ ] Allow DNSSEC strict/relaxed mode per upstream provider
- [ ] Useful when some providers support DNSSEC better than others

---

## Phase 7 — Feature additions

**LAN-mode (network-wide blocking)**
- [ ] Listen on `0.0.0.0` to serve other devices on the local network
- [ ] Makes Coreguard usable as a household DNS blocker (Pi-hole territory)
- [ ] Requires firewall/access control considerations

**CLI query log search**
- [ ] `coreguard log --grep reddit.com` — search query history from the command line
- [ ] Filter by status (blocked/allowed), time range, query type

**Blocklist hit attribution**
- [ ] Show which filter list blocked a given domain
- [ ] Displayed in dashboard query log and CLI output
- [ ] Helps users debug false positives and tune lists

**Dashboard HTTPS**
- [ ] Self-signed certificate generation for local TLS
- [ ] Required if dashboard is exposed to LAN in network-wide mode
- [ ] Config option to enable/disable

**Config backup & export**
- [ ] `coreguard config export` / `coreguard config import` commands
- [ ] One-command snapshot and restore of all settings, custom lists, and schedules

---

## Phase 8 — Per-app firewall

**Per-application network rules**
- [ ] Block or allow network access on a per-app basis (like Little Snitch / LuLu)
- [ ] Requires a macOS Network Extension — native Swift/ObjC, not Python
- [ ] Requires an Apple Developer account ($99/yr) for Network Extension entitlements
- [ ] Requires code signing and notarization for distribution
- [ ] Architecturally separate component that integrates with the coreguard daemon

---

## Phase 9 — Platform expansion

**iOS companion app**
- [ ] DNS profile + on-device filtering for iPhone/iPad
- [ ] Shared blocklist configuration with macOS Coreguard
- [ ] Huge market opportunity (1Blocker charges $15/yr for this)

**Network-wide mode with per-device profiles**
- [ ] Serve as the DNS server for all household devices
- [ ] Per-device blocking profiles (e.g. kids vs. adults)
- [ ] Moves beyond single-machine into Pi-hole / AdGuard Home territory

**Browser extensions (cosmetic filtering)**
- [ ] Companion extensions for Safari, Chrome, and Firefox
- [ ] Remove empty containers, placeholders, and layout gaps left behind by DNS-blocked ads
- [ ] Communicate with the local Coreguard daemon to stay in sync with blocklist state
- [ ] Completes the blocking story — Coreguard handles network-level blocking, the extension handles visual cleanup

---

## Not planned

| Feature | Why not |
|---------|---------|
| Built-in DHCP server | Out of scope — coreguard is a DNS blocker, not a router |
| Browser-level HTTPS filtering | Requires invasive TLS interception — against the privacy-first ethos |
