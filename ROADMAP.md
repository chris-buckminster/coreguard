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

**Breakage quick-unblock (menubar integration)**
- [ ] "Last 5 blocked domains" submenu in the menubar agent
- [ ] One-click temporary allowlist from the menu

**Web dashboard with full management**
- [ ] Evolve the current read-only dashboard into a control panel
- [ ] Allow/block domains, enable/disable filter lists, trigger updates, start/stop daemon
- [ ] Aimed at users who aren't comfortable with CLI tooling
- [ ] Authentication required (no longer read-only)

**Regex-based blocking rules**
- [ ] Custom rules beyond wildcards

**Time-based / scheduled filtering**
- [ ] Stricter or looser blocking on a schedule

**Parental controls / safe search**
- [ ] Enforce SafeSearch on Google, YouTube, Bing via DNS-level rewrites
- [ ] Optional content category blocking (adult, gambling, etc.)
- [ ] Configurable per-profile if device profiles are added later

---

## Phase 4 — Observability & data

**Database-backed query logging**
- [ ] SQLite (fits the single-machine, self-contained philosophy — no external DB server)
- [ ] Enables richer dashboard queries: search, filter by time range, per-domain history
- [ ] Migration path from current flat-file logging

**Prometheus / metrics export**
- [ ] `/metrics` endpoint in Prometheus exposition format
- [ ] Query rates, block rates, cache hit ratio, upstream latency, list sizes
- [ ] Enables Grafana dashboards and alerting for power users

---

## Phase 5 — Advanced protocol & security

**DNSSEC validation**
- [ ] Validate signed DNS responses from upstream

**DNS-over-QUIC (DoQ)**
- [ ] Faster encrypted DNS transport (UDP-based, lower latency than DoH)

---

## Phase 6 — Per-app firewall

**Per-application network rules**
- [ ] Block or allow network access on a per-app basis (like Little Snitch / LuLu)
- [ ] Requires a macOS Network Extension — native Swift/ObjC, not Python
- [ ] Requires an Apple Developer account ($99/yr) for Network Extension entitlements
- [ ] Requires code signing and notarization for distribution
- [ ] Architecturally separate component that integrates with the coreguard daemon

---

## Not planned

| Feature | Why not |
|---------|---------|
| Per-client/device profiles | Coreguard is single-machine, not a network server |
| Built-in DHCP server | Out of scope — coreguard is a DNS blocker, not a router |
| Browser-level HTTPS filtering | Requires invasive TLS interception — against the privacy-first ethos |
