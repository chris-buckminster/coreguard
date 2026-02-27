import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

import click

from coreguard.blocklist import update_all_lists
from coreguard.config import (
    CONFIG_DIR,
    CUSTOM_ALLOW_FILE,
    CUSTOM_BLOCK_FILE,
    DNS_BACKUP_FILE,
    LOG_FILE,
    PID_FILE,
    STATS_FILE,
    TEMP_ALLOW_FILE,
    Config,
    ensure_dirs,
    load_config,
    save_config,
)
from coreguard.daemon import (
    cleanup,
    daemonize,
    is_running,
    main_loop,
    process_exists,
    read_pid,
    setup_signal_handlers,
    write_pid_file,
)
from coreguard.menubar import ensure_menubar_running, remove_menubar
from coreguard.dns_server import start_dns_server
from coreguard.filtering import DomainFilter
from coreguard.logging_config import QueryLogger
from coreguard.network import (
    flush_dns_cache,
    get_active_interfaces,
    get_current_dns,
    restore_dns,
    set_dns_to_local,
)
from coreguard.notify import (
    notify_dns_misconfigured,
    notify_lists_update_failed,
    notify_startup_failure,
)
from coreguard.stats import Stats

LAUNCHD_PLIST_PATH = Path("/Library/LaunchDaemons/com.coreguard.daemon.plist")
LAUNCHD_LABEL = "com.coreguard.daemon"


def _port_53_responding() -> bool:
    """Check if something is responding on 127.0.0.1:53."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(
            b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09localhost\x00\x00\x01\x00\x01",
            ("127.0.0.1", 53),
        )
        sock.recvfrom(512)
        sock.close()
        return True
    except Exception:
        return False


def _setup_logging(foreground: bool) -> None:
    """Configure root logger."""
    log_level = logging.INFO
    handlers: list[logging.Handler] = []

    # Always log to file
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )
    handlers.append(file_handler)

    if foreground:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
        )
        handlers.append(stream_handler)

    logging.basicConfig(level=log_level, handlers=handlers, force=True)


def _is_launchd_loaded() -> bool:
    """Check if the launchd service is currently loaded."""
    result = subprocess.run(
        ["launchctl", "list", LAUNCHD_LABEL],
        capture_output=True,
        timeout=5,
    )
    return result.returncode == 0


def _stop_running_daemon() -> bool:
    """Stop any running coreguard daemon. Returns True if something was stopped."""
    stopped = False

    # Unload launchd service to prevent auto-restart (KeepAlive=true)
    if LAUNCHD_PLIST_PATH.exists() and _is_launchd_loaded():
        subprocess.run(
            ["launchctl", "unload", str(LAUNCHD_PLIST_PATH)],
            capture_output=True,
            timeout=10,
        )
        # Give it a moment to exit
        time.sleep(1)
        stopped = True

    # Also check PID file for manually started daemons
    pid = read_pid()
    if pid and process_exists(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait for process to exit
            for _ in range(10):
                if not process_exists(pid):
                    break
                time.sleep(0.5)
            stopped = True
        except ProcessLookupError:
            pass

    PID_FILE.unlink(missing_ok=True)
    return stopped


@click.group()
@click.version_option(package_name="coreguard")
@click.option("--json", "json_mode", is_flag=True, help="Output in JSON format")
@click.pass_context
def main(ctx, json_mode):
    """Coreguard - DNS-based ad/tracker blocking for macOS."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_mode
    ensure_dirs()


def _require_root(ctx, command_name):
    """Check root privileges, emit JSON-aware error if not root."""
    if os.geteuid() != 0:
        msg = f"requires root privileges. Run with: sudo coreguard {command_name}"
        if ctx.obj.get("json"):
            click.echo(json.dumps({"status": "error", "message": msg}))
        else:
            click.echo(f"Error: {msg}")
        ctx.exit(1)


def _emit(ctx, data, human_lines):
    """Output JSON or human-readable text based on mode."""
    if ctx.obj.get("json"):
        click.echo(json.dumps(data))
    else:
        for line in human_lines:
            click.echo(line)


@main.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (no daemon)")
@click.pass_context
def start(ctx, foreground):
    """Start the DNS blocking server."""
    _require_root(ctx, "start")
    json_mode = ctx.obj.get("json")

    # Start the menubar status agent for the logged-in user.
    ensure_menubar_running()

    # If launchd service exists but is unloaded (after stop), reload it
    if not foreground and LAUNCHD_PLIST_PATH.exists() and not _is_launchd_loaded():
        if not json_mode:
            click.echo("Starting coreguard via launchd service...")
        result = subprocess.run(
            ["launchctl", "load", str(LAUNCHD_PLIST_PATH)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # Wait for daemon to be ready
            for _ in range(30):
                time.sleep(1)
                if _port_53_responding():
                    _emit(ctx,
                        {"status": "ok", "message": "Coreguard started.", "mode": "launchd"},
                        ["Coreguard started."])
                    return
            _emit(ctx,
                {"status": "ok", "message": "Coreguard service loaded but daemon is still starting.", "mode": "launchd"},
                ["Coreguard service loaded but daemon is still starting..."])
            return
        else:
            if not json_mode:
                click.echo(f"Warning: launchctl load failed: {result.stderr.strip()}")
                click.echo("Falling back to manual start...")

    if is_running() or _port_53_responding():
        _emit(ctx,
            {"status": "error", "message": "Coreguard is already running."},
            ["Coreguard is already running."])
        ctx.exit(1)

    _setup_logging(foreground)
    config = load_config()
    domain_filter = DomainFilter()

    # Restore DNS if stuck from a previous run
    if DNS_BACKUP_FILE.exists():
        if not json_mode:
            click.echo("Restoring DNS from previous session...")
        restore_dns()

    if not json_mode:
        click.echo("Loading filter lists...")
    count = update_all_lists(config, domain_filter)
    enabled_count = sum(1 for f in config.filter_lists if f.get("enabled", True))
    if not json_mode:
        click.echo(f"Loaded {count:,} blocked domains from {enabled_count} lists.")

    stats = Stats()
    query_logger = QueryLogger(LOG_FILE, max_bytes=config.log_max_size_mb * 1024 * 1024)

    if not foreground:
        if not json_mode:
            click.echo("Starting coreguard daemon...")
        if json_mode:
            click.echo(json.dumps({"status": "ok", "message": "Daemon starting.", "mode": "daemon"}))
        daemonize()

    # Write PID file (both daemon and foreground mode)
    write_pid_file()

    # Set up signal handlers BEFORE starting DNS server and changing DNS
    # so we can always clean up if interrupted
    # (placeholder cleanup_fn — will be replaced after servers start)
    def early_cleanup():
        restore_dns()
        PID_FILE.unlink(missing_ok=True)

    setup_signal_handlers(early_cleanup)

    # Start DNS server
    try:
        udp_server, tcp_server, cache = start_dns_server(config, domain_filter, stats, query_logger)
    except Exception as e:
        msg = f"Failed to start DNS server: {e}"
        if json_mode:
            click.echo(json.dumps({"status": "error", "message": msg}))
        else:
            click.echo(f"Error: {msg}")
            click.echo("Is port 53 already in use? Check with: sudo lsof -i :53")
        notify_startup_failure(msg)
        PID_FILE.unlink(missing_ok=True)
        sys.exit(1)

    # Start dashboard
    from coreguard.dashboard import start_dashboard

    dashboard_server = start_dashboard(config, stats, cache)

    # Configure macOS DNS
    set_dns_to_local()

    # Replace signal handlers with full cleanup now that servers are running
    cleanup_fn = partial(cleanup, udp_server, tcp_server)
    reload_fn = partial(update_all_lists, config, domain_filter)
    setup_signal_handlers(cleanup_fn)

    if foreground:
        if json_mode:
            data = {"status": "ok", "message": "Coreguard running.", "mode": "foreground"}
            if dashboard_server:
                data["dashboard_url"] = f"http://127.0.0.1:{config.dashboard_port}"
                data["dashboard_token"] = config.dashboard_token
            click.echo(json.dumps(data))
        else:
            click.echo(f"Coreguard running on {config.listen_address}:{config.listen_port}. Press Ctrl+C to stop.")
            if dashboard_server:
                click.echo(f"Dashboard: http://127.0.0.1:{config.dashboard_port} (token: {config.dashboard_token})")

    # Enter main loop (blocks forever)
    try:
        main_loop(config, domain_filter, stats, cache)
    except (KeyboardInterrupt, SystemExit):
        cleanup_fn()


@main.command()
@click.pass_context
def stop(ctx):
    """Stop the DNS blocking server and restore DNS settings."""
    _require_root(ctx, "stop")

    was_running = _stop_running_daemon()

    # Always restore DNS (handles unclean shutdowns too)
    restore_dns()

    if was_running:
        msg = "Coreguard stopped. DNS settings restored."
    else:
        msg = "Coreguard was not running. DNS settings restored."
    _emit(ctx,
        {"status": "ok", "message": msg, "was_running": was_running},
        [msg])


@main.command()
@click.pass_context
def status(ctx):
    """Show coreguard status and statistics."""
    json_mode = ctx.obj.get("json")
    pid = read_pid()
    pid_running = pid is not None and process_exists(pid)
    port_responding = _port_53_responding()

    if not pid_running and not port_responding:
        # Check if launchd service is starting up
        if LAUNCHD_PLIST_PATH.exists() and _is_launchd_loaded():
            if json_mode:
                click.echo(json.dumps({"status": "ok", "running": "starting", "pid": None, "port_53_responding": False, "config_dir": str(CONFIG_DIR), "stats": {}}))
            else:
                click.echo("Coreguard is starting up (launchd service loaded)...")
            return
        if json_mode:
            click.echo(json.dumps({"status": "ok", "running": False, "pid": None, "port_53_responding": False, "config_dir": str(CONFIG_DIR), "stats": {}}))
        else:
            click.echo("Coreguard is not running.")
        return

    stats = Stats.load_from_file(STATS_FILE)

    if json_mode:
        click.echo(json.dumps({
            "status": "ok",
            "running": True,
            "pid": pid if pid_running else None,
            "port_53_responding": port_responding,
            "config_dir": str(CONFIG_DIR),
            "stats": stats,
        }))
        return

    if pid_running:
        click.echo(f"Coreguard is running (PID: {pid})")
    else:
        click.echo("Coreguard is running (port 53 responding)")
    click.echo(f"Config: {CONFIG_DIR}")
    click.echo()

    click.echo(f"  Total queries:   {stats['total_queries']:,}")
    click.echo(f"  Blocked queries: {stats['blocked_queries']:,} ({stats['blocked_percent']}%)")
    click.echo(f"  Cache hits:      {stats.get('cache_hits', 0):,} ({stats.get('cache_hit_rate', 0.0)}%)")
    click.echo(f"  CNAME blocks:    {stats.get('cname_blocks', 0):,}")
    click.echo(f"  Errors:          {stats.get('error_queries', 0):,}")

    top_blocked = stats.get("top_blocked", {})
    if top_blocked:
        click.echo()
        click.echo("  Top blocked domains:")
        for domain, count in list(top_blocked.items())[:10]:
            click.echo(f"    {count:>6,}  {domain}")


@main.command()
@click.pass_context
def update(ctx):
    """Force update all filter lists."""
    json_mode = ctx.obj.get("json")
    config = load_config()
    domain_filter = DomainFilter()

    if not json_mode:
        click.echo("Updating filter lists...")
    count = update_all_lists(config, domain_filter)
    reload_sent = _send_reload_signal()

    human_lines = [f"Updated. {count:,} domains in blocklist."]
    if reload_sent:
        human_lines.append("Sent reload signal to running daemon.")
    _emit(ctx,
        {"status": "ok", "domains_count": count, "reload_signal_sent": reload_sent},
        human_lines)


@main.command()
@click.argument("domain")
@click.pass_context
def allow(ctx, domain):
    """Add a domain to the allowlist."""
    _require_root(ctx, "allow")
    domain = domain.lower().strip(".")
    with open(CUSTOM_ALLOW_FILE, "a") as f:
        f.write(domain + "\n")
    _emit(ctx,
        {"status": "ok", "domain": domain, "action": "added_to_allowlist"},
        [f"Added '{domain}' to allowlist.",
         "Restart coreguard or run 'coreguard update' to apply."])


@main.command()
@click.argument("domain")
@click.pass_context
def block(ctx, domain):
    """Add a domain to the blocklist."""
    _require_root(ctx, "block")
    domain = domain.lower().strip(".")
    with open(CUSTOM_BLOCK_FILE, "a") as f:
        f.write(domain + "\n")
    _emit(ctx,
        {"status": "ok", "domain": domain, "action": "added_to_blocklist"},
        [f"Added '{domain}' to blocklist.",
         "Restart coreguard or run 'coreguard update' to apply."])


def _send_reload_signal() -> bool:
    """Send SIGHUP to the running daemon. Returns True if signal was sent."""
    # Try PID file first
    pid = read_pid()
    if pid and process_exists(pid):
        try:
            os.kill(pid, signal.SIGHUP)
            return True
        except (ProcessLookupError, PermissionError):
            pass

    # Fall back to launchctl for launchd-managed daemons
    if LAUNCHD_PLIST_PATH.exists():
        result = subprocess.run(
            ["launchctl", "kill", "SIGHUP", f"system/{LAUNCHD_LABEL}"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return True

    return False


def _remove_from_file(path: Path, domain: str) -> bool:
    """Remove a domain from a text file. Returns True if found and removed."""
    if not path.exists():
        return False
    lines = path.read_text().splitlines()
    filtered = [l for l in lines if l.strip().lower().strip(".") != domain]
    if len(filtered) < len(lines):
        path.write_text("\n".join(filtered) + "\n" if filtered else "")
        return True
    return False


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def parse_duration(s: str) -> int:
    """Parse a duration string like '5m', '1h', '30s' into seconds."""
    match = re.fullmatch(r"(\d+)([smh])", s)
    if not match:
        raise click.BadParameter(
            f"Invalid duration '{s}'. Use a number followed by s, m, or h (e.g. 5m, 1h, 30s)."
        )
    return int(match.group(1)) * _DURATION_UNITS[match.group(2)]


def _add_temp_allow(domain: str, duration_seconds: int) -> None:
    """Add a domain to temp-allow.json with an expiry timestamp."""
    data = {}
    if TEMP_ALLOW_FILE.exists():
        try:
            data = json.loads(TEMP_ALLOW_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    data[domain] = time.time() + duration_seconds
    TEMP_ALLOW_FILE.write_text(json.dumps(data))


@main.command()
@click.argument("domain")
@click.option("--for", "duration", default=None, help="Temporary duration (e.g. 5m, 1h, 30s)")
@click.pass_context
def unblock(ctx, domain, duration):
    """Unblock a domain — adds to allowlist and triggers immediate reload."""
    _require_root(ctx, "unblock")
    json_mode = ctx.obj.get("json")
    domain = domain.lower().strip(".")

    if duration:
        # Temporary unblock — write to temp-allow.json
        seconds = parse_duration(duration)
        _add_temp_allow(domain, seconds)
        expires_at = time.strftime("%H:%M:%S", time.localtime(time.time() + seconds))
        if not json_mode:
            click.echo(f"Temporarily allowed '{domain}' for {duration} (until {expires_at}).")
        result_data = {"status": "ok", "domain": domain, "action": "temp_allowed",
                       "duration": duration, "expires_at": expires_at}
    else:
        # Permanent unblock — original behavior
        # Remove from custom block file if present
        removed = _remove_from_file(CUSTOM_BLOCK_FILE, domain)
        if removed and not json_mode:
            click.echo(f"Removed '{domain}' from custom blocklist.")

        # Add to allowlist (handles filter-list blocks too)
        existing = set()
        if CUSTOM_ALLOW_FILE.exists():
            existing = {
                line.strip().lower().strip(".")
                for line in CUSTOM_ALLOW_FILE.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
        if domain not in existing:
            with open(CUSTOM_ALLOW_FILE, "a") as f:
                f.write(domain + "\n")
            if not json_mode:
                click.echo(f"Added '{domain}' to allowlist.")
            action = "added_to_allowlist"
        else:
            if not json_mode:
                click.echo(f"'{domain}' is already in allowlist.")
            action = "already_in_allowlist"
        result_data = {"status": "ok", "domain": domain, "action": action}

    # Trigger reload if daemon is running
    reload_sent = _send_reload_signal()
    result_data["reload_signal_sent"] = reload_sent

    if json_mode:
        click.echo(json.dumps(result_data))
    else:
        if reload_sent:
            click.echo("Reload signal sent — takes effect within seconds.")
        else:
            click.echo("Daemon not running. Changes will apply on next start.")


@main.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real time")
@click.option("--lines", "-n", default=20, help="Number of lines to show")
@click.pass_context
def log(ctx, follow, lines):
    """Show the query log."""
    json_mode = ctx.obj.get("json")

    if json_mode and follow:
        click.echo(json.dumps({"status": "error", "message": "--json and --follow are incompatible. Follow mode is streaming and cannot produce a single JSON object."}))
        ctx.exit(1)

    if not LOG_FILE.exists():
        _emit(ctx,
            {"status": "ok", "lines": []},
            ["No log file found. Start coreguard first."])
        return

    if follow:
        try:
            subprocess.run(["tail", "-f", str(LOG_FILE)])
        except KeyboardInterrupt:
            pass
    else:
        result = subprocess.run(
            ["tail", "-n", str(lines), str(LOG_FILE)],
            capture_output=True,
            text=True,
        )
        if json_mode:
            log_lines = [l for l in result.stdout.splitlines() if l]
            click.echo(json.dumps({"status": "ok", "lines": log_lines}))
        else:
            click.echo(result.stdout)


@main.command()
@click.pass_context
def lists(ctx):
    """Show active filter lists."""
    json_mode = ctx.obj.get("json")
    config = load_config()

    if json_mode:
        filter_lists = [
            {"name": f["name"], "url": f["url"], "enabled": f.get("enabled", True)}
            for f in config.filter_lists
        ]
        click.echo(json.dumps({"status": "ok", "filter_lists": filter_lists}))
    else:
        click.echo("Filter lists:")
        for flist in config.filter_lists:
            status_str = (
                click.style("enabled", fg="green")
                if flist.get("enabled", True)
                else click.style("disabled", fg="red")
            )
            click.echo(f"  [{status_str}] {flist['name']}")
            click.echo(f"           {flist['url']}")


@main.command("add-list")
@click.argument("url")
@click.option("--name", default=None, help="Name for the filter list")
@click.pass_context
def add_list(ctx, url, name):
    """Add a new filter list source by URL."""
    if name is None:
        name = url.rstrip("/").split("/")[-1].split(".")[0]

    config = load_config()

    for flist in config.filter_lists:
        if flist["url"] == url:
            _emit(ctx,
                {"status": "ok", "name": flist["name"], "url": url, "action": "already_exists"},
                [f"List already exists: {flist['name']}"])
            return

    config.filter_lists.append({"name": name, "url": url, "enabled": True})
    save_config(config)
    _emit(ctx,
        {"status": "ok", "name": name, "url": url, "action": "added"},
        [f"Added list '{name}'.",
         "Run 'sudo coreguard update' to download and apply."])


@main.command("remove-list")
@click.argument("name")
@click.pass_context
def remove_list(ctx, name):
    """Remove a filter list by name."""
    config = load_config()
    original_count = len(config.filter_lists)
    config.filter_lists = [f for f in config.filter_lists if f["name"] != name]

    if len(config.filter_lists) == original_count:
        _emit(ctx,
            {"status": "error", "name": name, "action": "not_found"},
            [f"No list found with name '{name}'."])
        return

    save_config(config)
    _emit(ctx,
        {"status": "ok", "name": name, "action": "removed"},
        [f"Removed list '{name}'.",
         "Run 'sudo coreguard update' to apply."])


@main.command()
@click.pass_context
def doctor(ctx):
    """Run diagnostics to check coreguard health."""
    json_mode = ctx.obj.get("json")
    checks = []
    issues = []
    config = load_config()

    # 1. Check if daemon is running (PID file or port 53)
    pid = read_pid()
    pid_running = pid is not None and process_exists(pid)
    port_responding = _port_53_responding()

    if pid_running:
        checks.append({"name": "daemon", "status": "ok", "message": f"Daemon is running (PID: {pid})"})
    elif port_responding:
        checks.append({"name": "daemon", "status": "ok", "message": "Daemon is running (port 53 responding)"})
    else:
        checks.append({"name": "daemon", "status": "fail", "message": "Daemon is not running"})
        issues.append("Daemon is not running. Start with: sudo coreguard start")

    # 2. Check DNS configuration
    dns_ok = True
    for service in get_active_interfaces():
        servers = get_current_dns(service)
        if servers and "127.0.0.1" in servers:
            checks.append({"name": f"dns_{service}", "status": "ok", "message": f"DNS for '{service}' points to 127.0.0.1"})
        elif not servers:
            checks.append({"name": f"dns_{service}", "status": "warn", "message": f"DNS for '{service}' uses DHCP defaults (not coreguard)"})
            dns_ok = False
        else:
            checks.append({"name": f"dns_{service}", "status": "fail", "message": f"DNS for '{service}' points to {', '.join(servers)} (not coreguard)"})
            dns_ok = False
    if not dns_ok:
        issues.append("System DNS is not pointing to coreguard. Restart with: sudo coreguard start")

    # 3. Check if port 53 is responding (reuse result from step 1)
    if port_responding:
        checks.append({"name": "port_53", "status": "ok", "message": "Port 53 is responding on 127.0.0.1"})
    else:
        checks.append({"name": "port_53", "status": "fail", "message": "Port 53 is not responding on 127.0.0.1"})
        issues.append("DNS server is not responding on port 53")

    # 4. Check filter lists
    from coreguard.config import BLOCKLISTS_DIR

    cached_lists = list(BLOCKLISTS_DIR.glob("*.txt"))
    enabled_count = sum(1 for f in config.filter_lists if f.get("enabled", True))
    if cached_lists:
        newest = max(cached_lists, key=lambda p: p.stat().st_mtime)
        age_hours = (time.time() - newest.stat().st_mtime) / 3600
        if age_hours < 48:
            checks.append({"name": "filter_lists", "status": "ok",
                           "message": f"{len(cached_lists)} filter lists cached (last update: {age_hours:.0f}h ago)",
                           "cached_count": len(cached_lists), "age_hours": round(age_hours, 1)})
        else:
            checks.append({"name": "filter_lists", "status": "warn",
                           "message": f"Filter lists are stale (last update: {age_hours:.0f}h ago)",
                           "cached_count": len(cached_lists), "age_hours": round(age_hours, 1)})
            issues.append("Filter lists haven't been updated recently. Run: sudo coreguard update")
    else:
        checks.append({"name": "filter_lists", "status": "fail", "message": "No cached filter lists found"})
        issues.append("No filter lists downloaded. Run: sudo coreguard update")

    checks.append({"name": "filter_lists_config", "status": "info",
                   "message": f"{enabled_count} filter lists enabled, {len(config.filter_lists)} total configured",
                   "enabled_count": enabled_count, "total_count": len(config.filter_lists)})

    # 5. Check launchd service (plist existence — launchctl list requires root)
    if LAUNCHD_PLIST_PATH.exists():
        checks.append({"name": "launchd", "status": "ok", "message": "Launchd service installed (auto-start on boot)"})
    else:
        checks.append({"name": "launchd", "status": "info", "message": "Launchd service not installed (no auto-start)"})

    # 6. Check log file
    if LOG_FILE.exists():
        log_size_mb = LOG_FILE.stat().st_size / (1024 * 1024)
        checks.append({"name": "log_file", "status": "ok",
                       "message": f"Log file: {LOG_FILE} ({log_size_mb:.1f} MB)",
                       "path": str(LOG_FILE), "size_mb": round(log_size_mb, 1)})
    else:
        checks.append({"name": "log_file", "status": "info", "message": "No log file yet"})

    # Output
    if json_mode:
        overall = "ok" if not issues else "error"
        click.echo(json.dumps({"status": overall, "checks": checks, "issues": issues}))
    else:
        _STATUS_COLORS = {"ok": "green", "fail": "red", "warn": "yellow", "info": "blue"}
        _STATUS_LABELS = {"ok": "OK", "fail": "FAIL", "warn": "WARN", "info": "INFO"}
        for check in checks:
            color = _STATUS_COLORS.get(check["status"], "white")
            label = _STATUS_LABELS.get(check["status"], check["status"].upper())
            click.echo(click.style(f"[{label}]", fg=color) + f"  {check['message']}")

        click.echo()
        if not issues:
            click.echo(click.style("All checks passed. Coreguard is healthy.", fg="green"))
        else:
            click.echo(click.style(f"{len(issues)} issue(s) found:", fg="red"))
            for issue in issues:
                click.echo(f"  - {issue}")


def _get_coreguard_bin() -> str:
    """Find the coreguard executable path."""
    import shutil

    current_bin = Path(sys.executable).parent / "coreguard"
    if current_bin.exists():
        return str(current_bin)
    found = shutil.which("coreguard")
    if found:
        return found
    raise FileNotFoundError("Could not find coreguard executable")


def _generate_plist(coreguard_bin: str) -> str:
    """Generate the launchd plist XML."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{coreguard_bin}</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_FILE}</string>
</dict>
</plist>
"""


@main.command()
@click.pass_context
def install(ctx):
    """Install coreguard as a system service (auto-start on boot)."""
    _require_root(ctx, "install")
    json_mode = ctx.obj.get("json")

    try:
        coreguard_bin = _get_coreguard_bin()
    except FileNotFoundError as e:
        _emit(ctx,
            {"status": "error", "message": str(e)},
            [f"Error: {e}"])
        ctx.exit(1)

    # Stop any running instance first
    if is_running():
        if not json_mode:
            click.echo("Stopping running instance...")
        _stop_running_daemon()
        restore_dns()

    # Unload existing service if present
    if LAUNCHD_PLIST_PATH.exists():
        subprocess.run(["launchctl", "unload", str(LAUNCHD_PLIST_PATH)], capture_output=True, timeout=10)

    plist_content = _generate_plist(coreguard_bin)
    LAUNCHD_PLIST_PATH.write_text(plist_content)

    subprocess.run(["chown", "root:wheel", str(LAUNCHD_PLIST_PATH)], check=True)
    subprocess.run(["chmod", "644", str(LAUNCHD_PLIST_PATH)], check=True)

    # Load the service
    result = subprocess.run(
        ["launchctl", "load", str(LAUNCHD_PLIST_PATH)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        msg = f"launchctl load failed: {result.stderr.strip()}"
        _emit(ctx,
            {"status": "error", "message": msg},
            [f"Error: {msg}"])
        LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
        ctx.exit(1)

    # Also install the menubar status agent for the logged-in user.
    ensure_menubar_running()

    _emit(ctx,
        {"status": "ok", "message": "Coreguard installed as system service.",
         "executable": coreguard_bin, "plist": str(LAUNCHD_PLIST_PATH)},
        ["Coreguard installed as system service.",
         f"  Executable: {coreguard_bin}",
         f"  Plist: {LAUNCHD_PLIST_PATH}",
         "Coreguard will now start automatically on boot."])


@main.command()
@click.pass_context
def uninstall(ctx):
    """Remove coreguard system service (disable auto-start)."""
    _require_root(ctx, "uninstall")

    if not LAUNCHD_PLIST_PATH.exists():
        _emit(ctx,
            {"status": "ok", "message": "Coreguard is not installed as a system service."},
            ["Coreguard is not installed as a system service."])
        return

    # Unload the service (this stops the process)
    subprocess.run(
        ["launchctl", "unload", str(LAUNCHD_PLIST_PATH)],
        capture_output=True,
        timeout=10,
    )

    # Wait for process to exit
    time.sleep(1)

    # Restore DNS
    restore_dns()

    # Also remove the menubar status agent.
    remove_menubar()

    # Clean up
    LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
    PID_FILE.unlink(missing_ok=True)
    _emit(ctx,
        {"status": "ok", "message": "Coreguard system service removed. It will no longer start on boot."},
        ["Coreguard system service removed. It will no longer start on boot."])
