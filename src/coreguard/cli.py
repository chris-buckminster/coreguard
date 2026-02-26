import logging
import os
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

    # Try launchctl first if service is loaded
    if LAUNCHD_PLIST_PATH.exists() and _is_launchd_loaded():
        subprocess.run(
            ["launchctl", "stop", LAUNCHD_LABEL],
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
def main():
    """Coreguard - DNS-based ad/tracker blocking for macOS."""
    ensure_dirs()


@main.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (no daemon)")
def start(foreground):
    """Start the DNS blocking server."""
    if os.geteuid() != 0:
        click.echo("Error: coreguard requires root privileges. Run with: sudo coreguard start")
        sys.exit(1)

    if is_running():
        click.echo("Coreguard is already running.")
        sys.exit(1)

    _setup_logging(foreground)
    config = load_config()
    domain_filter = DomainFilter()

    # Restore DNS if stuck from a previous run
    if DNS_BACKUP_FILE.exists():
        click.echo("Restoring DNS from previous session...")
        restore_dns()

    click.echo("Loading filter lists...")
    count = update_all_lists(config, domain_filter)
    enabled_count = sum(1 for f in config.filter_lists if f.get("enabled", True))
    click.echo(f"Loaded {count:,} blocked domains from {enabled_count} lists.")

    stats = Stats()
    query_logger = QueryLogger(LOG_FILE, max_bytes=config.log_max_size_mb * 1024 * 1024)

    if not foreground:
        click.echo("Starting coreguard daemon...")
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
        udp_server, tcp_server = start_dns_server(config, domain_filter, stats, query_logger)
    except Exception as e:
        msg = f"Failed to start DNS server: {e}"
        click.echo(f"Error: {msg}")
        click.echo("Is port 53 already in use? Check with: sudo lsof -i :53")
        notify_startup_failure(msg)
        PID_FILE.unlink(missing_ok=True)
        sys.exit(1)

    # Configure macOS DNS
    set_dns_to_local()

    # Replace signal handlers with full cleanup now that servers are running
    cleanup_fn = partial(cleanup, udp_server, tcp_server)
    reload_fn = partial(update_all_lists, config, domain_filter)
    setup_signal_handlers(cleanup_fn)

    if foreground:
        click.echo(f"Coreguard running on {config.listen_address}:{config.listen_port}. Press Ctrl+C to stop.")

    # Enter main loop (blocks forever)
    try:
        main_loop(config, domain_filter, stats)
    except (KeyboardInterrupt, SystemExit):
        cleanup_fn()


@main.command()
def stop():
    """Stop the DNS blocking server and restore DNS settings."""
    if os.geteuid() != 0:
        click.echo("Error: requires root privileges. Run with: sudo coreguard stop")
        sys.exit(1)

    was_running = _stop_running_daemon()

    # Always restore DNS (handles unclean shutdowns too)
    restore_dns()

    if was_running:
        click.echo("Coreguard stopped. DNS settings restored.")
    else:
        click.echo("Coreguard was not running. DNS settings restored.")


@main.command()
def status():
    """Show coreguard status and statistics."""
    pid = read_pid()
    pid_running = pid is not None and process_exists(pid)
    port_responding = _port_53_responding()

    if not pid_running and not port_responding:
        click.echo("Coreguard is not running.")
        return

    if pid_running:
        click.echo(f"Coreguard is running (PID: {pid})")
    else:
        click.echo("Coreguard is running (port 53 responding)")
    click.echo(f"Config: {CONFIG_DIR}")
    click.echo()

    stats = Stats.load_from_file(STATS_FILE)
    click.echo(f"  Total queries:   {stats['total_queries']:,}")
    click.echo(f"  Blocked queries: {stats['blocked_queries']:,} ({stats['blocked_percent']}%)")
    click.echo(f"  Errors:          {stats['error_queries']:,}")

    top_blocked = stats.get("top_blocked", {})
    if top_blocked:
        click.echo()
        click.echo("  Top blocked domains:")
        for domain, count in list(top_blocked.items())[:10]:
            click.echo(f"    {count:>6,}  {domain}")


@main.command()
def update():
    """Force update all filter lists."""
    config = load_config()
    domain_filter = DomainFilter()

    click.echo("Updating filter lists...")
    count = update_all_lists(config, domain_filter)
    click.echo(f"Updated. {count:,} domains in blocklist.")

    # If daemon is running, send SIGHUP to trigger reload
    pid = read_pid()
    if pid and process_exists(pid):
        try:
            os.kill(pid, signal.SIGHUP)
            click.echo("Sent reload signal to running daemon.")
        except (ProcessLookupError, PermissionError):
            pass


@main.command()
@click.argument("domain")
def allow(domain):
    """Add a domain to the allowlist."""
    domain = domain.lower().strip(".")
    with open(CUSTOM_ALLOW_FILE, "a") as f:
        f.write(domain + "\n")
    click.echo(f"Added '{domain}' to allowlist.")
    click.echo("Restart coreguard or run 'coreguard update' to apply.")


@main.command()
@click.argument("domain")
def block(domain):
    """Add a domain to the blocklist."""
    domain = domain.lower().strip(".")
    with open(CUSTOM_BLOCK_FILE, "a") as f:
        f.write(domain + "\n")
    click.echo(f"Added '{domain}' to blocklist.")
    click.echo("Restart coreguard or run 'coreguard update' to apply.")


@main.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real time")
@click.option("--lines", "-n", default=20, help="Number of lines to show")
def log(follow, lines):
    """Show the query log."""
    if not LOG_FILE.exists():
        click.echo("No log file found. Start coreguard first.")
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
        click.echo(result.stdout)


@main.command()
def lists():
    """Show active filter lists."""
    config = load_config()
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
def add_list(url, name):
    """Add a new filter list source by URL."""
    if name is None:
        name = url.rstrip("/").split("/")[-1].split(".")[0]

    config = load_config()

    for flist in config.filter_lists:
        if flist["url"] == url:
            click.echo(f"List already exists: {flist['name']}")
            return

    config.filter_lists.append({"name": name, "url": url, "enabled": True})
    save_config(config)
    click.echo(f"Added list '{name}'.")
    click.echo("Run 'sudo coreguard update' to download and apply.")


@main.command("remove-list")
@click.argument("name")
def remove_list(name):
    """Remove a filter list by name."""
    config = load_config()
    original_count = len(config.filter_lists)
    config.filter_lists = [f for f in config.filter_lists if f["name"] != name]

    if len(config.filter_lists) == original_count:
        click.echo(f"No list found with name '{name}'.")
        return

    save_config(config)
    click.echo(f"Removed list '{name}'.")
    click.echo("Run 'sudo coreguard update' to apply.")


@main.command()
def doctor():
    """Run diagnostics to check coreguard health."""
    issues = []
    config = load_config()

    # 1. Check if daemon is running (PID file or port 53)
    pid = read_pid()
    pid_running = pid is not None and process_exists(pid)
    port_responding = _port_53_responding()

    if pid_running:
        click.echo(click.style("[OK]", fg="green") + f"  Daemon is running (PID: {pid})")
    elif port_responding:
        click.echo(click.style("[OK]", fg="green") + "  Daemon is running (port 53 responding)")
    else:
        click.echo(click.style("[FAIL]", fg="red") + "  Daemon is not running")
        issues.append("Daemon is not running. Start with: sudo coreguard start")

    # 2. Check DNS configuration
    dns_ok = True
    for service in get_active_interfaces():
        servers = get_current_dns(service)
        if servers and "127.0.0.1" in servers:
            click.echo(click.style("[OK]", fg="green") + f"  DNS for '{service}' points to 127.0.0.1")
        elif not servers:
            click.echo(
                click.style("[WARN]", fg="yellow")
                + f"  DNS for '{service}' uses DHCP defaults (not coreguard)"
            )
            dns_ok = False
        else:
            click.echo(
                click.style("[FAIL]", fg="red")
                + f"  DNS for '{service}' points to {', '.join(servers)} (not coreguard)"
            )
            dns_ok = False
    if not dns_ok:
        issues.append("System DNS is not pointing to coreguard. Restart with: sudo coreguard start")

    # 3. Check if port 53 is responding (reuse result from step 1)
    if port_responding:
        click.echo(click.style("[OK]", fg="green") + "  Port 53 is responding on 127.0.0.1")
    else:
        click.echo(click.style("[FAIL]", fg="red") + "  Port 53 is not responding on 127.0.0.1")
        issues.append("DNS server is not responding on port 53")

    # 4. Check filter lists
    from coreguard.config import BLOCKLISTS_DIR

    cached_lists = list(BLOCKLISTS_DIR.glob("*.txt"))
    enabled_count = sum(1 for f in config.filter_lists if f.get("enabled", True))
    if cached_lists:
        newest = max(cached_lists, key=lambda p: p.stat().st_mtime)
        age_hours = (time.time() - newest.stat().st_mtime) / 3600
        if age_hours < 48:
            click.echo(
                click.style("[OK]", fg="green")
                + f"  {len(cached_lists)} filter lists cached (last update: {age_hours:.0f}h ago)"
            )
        else:
            click.echo(
                click.style("[WARN]", fg="yellow")
                + f"  Filter lists are stale (last update: {age_hours:.0f}h ago)"
            )
            issues.append("Filter lists haven't been updated recently. Run: sudo coreguard update")
    else:
        click.echo(click.style("[FAIL]", fg="red") + "  No cached filter lists found")
        issues.append("No filter lists downloaded. Run: sudo coreguard update")

    click.echo(
        click.style("[INFO]", fg="blue")
        + f"  {enabled_count} filter lists enabled, {len(config.filter_lists)} total configured"
    )

    # 5. Check launchd service (plist existence — launchctl list requires root)
    if LAUNCHD_PLIST_PATH.exists():
        click.echo(
            click.style("[OK]", fg="green") + "  Launchd service installed (auto-start on boot)"
        )
    else:
        click.echo(click.style("[INFO]", fg="blue") + "  Launchd service not installed (no auto-start)")

    # 6. Check log file
    if LOG_FILE.exists():
        log_size_mb = LOG_FILE.stat().st_size / (1024 * 1024)
        click.echo(click.style("[OK]", fg="green") + f"  Log file: {LOG_FILE} ({log_size_mb:.1f} MB)")
    else:
        click.echo(click.style("[INFO]", fg="blue") + "  No log file yet")

    # Summary
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
def install():
    """Install coreguard as a system service (auto-start on boot)."""
    if os.geteuid() != 0:
        click.echo("Error: requires root privileges. Run with: sudo coreguard install")
        sys.exit(1)

    try:
        coreguard_bin = _get_coreguard_bin()
    except FileNotFoundError as e:
        click.echo(f"Error: {e}")
        sys.exit(1)

    # Stop any running instance first
    if is_running():
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
        click.echo(f"Error: launchctl load failed: {result.stderr.strip()}")
        LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
        sys.exit(1)

    click.echo("Coreguard installed as system service.")
    click.echo(f"  Executable: {coreguard_bin}")
    click.echo(f"  Plist: {LAUNCHD_PLIST_PATH}")
    click.echo("Coreguard will now start automatically on boot.")


@main.command()
def uninstall():
    """Remove coreguard system service (disable auto-start)."""
    if os.geteuid() != 0:
        click.echo("Error: requires root privileges. Run with: sudo coreguard uninstall")
        sys.exit(1)

    if not LAUNCHD_PLIST_PATH.exists():
        click.echo("Coreguard is not installed as a system service.")
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

    # Clean up
    LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
    PID_FILE.unlink(missing_ok=True)
    click.echo("Coreguard system service removed. It will no longer start on boot.")
