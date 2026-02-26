import logging
import os
import signal
import subprocess
import sys
from functools import partial

import click

from coreguard.blocklist import update_all_lists
from coreguard.config import (
    CONFIG_DIR,
    CUSTOM_ALLOW_FILE,
    CUSTOM_BLOCK_FILE,
    LOG_FILE,
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
)
from coreguard.dns_server import start_dns_server
from coreguard.filtering import DomainFilter
from coreguard.logging_config import QueryLogger
from coreguard.network import flush_dns_cache, restore_dns, set_dns_to_local
from coreguard.stats import Stats


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

    # Restore DNS if stuck on 127.0.0.1 from a previous run,
    # otherwise filter list downloads will fail
    from coreguard.config import DNS_BACKUP_FILE
    if DNS_BACKUP_FILE.exists():
        click.echo("Restoring DNS from previous session...")
        restore_dns()

    click.echo("Loading filter lists...")
    count = update_all_lists(config, domain_filter)
    click.echo(f"Loaded {count:,} blocked domains from {sum(1 for f in config.filter_lists if f.get('enabled', True))} lists.")

    stats = Stats()
    query_logger = QueryLogger(LOG_FILE, max_bytes=config.log_max_size_mb * 1024 * 1024)

    if not foreground:
        click.echo("Starting coreguard daemon...")
        daemonize()

    # Start DNS server
    try:
        udp_server, tcp_server = start_dns_server(config, domain_filter, stats, query_logger)
    except Exception as e:
        click.echo(f"Error: Failed to start DNS server: {e}")
        click.echo("Is port 53 already in use? Check with: sudo lsof -i :53")
        sys.exit(1)

    # Configure macOS DNS
    set_dns_to_local()

    # Set up signal handlers
    cleanup_fn = partial(cleanup, udp_server, tcp_server)
    reload_fn = partial(update_all_lists, config, domain_filter)
    setup_signal_handlers(cleanup_fn, reload_fn)

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

    pid = read_pid()
    if pid is None or not process_exists(pid):
        # Still try to restore DNS in case of unclean shutdown
        restore_dns()
        click.echo("Coreguard is not running.")
        if pid is not None:
            from coreguard.config import PID_FILE
            PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    # Restore DNS before killing the daemon
    restore_dns()

    # Send SIGTERM to daemon
    try:
        os.kill(pid, signal.SIGTERM)
        click.echo("Coreguard stopped. DNS settings restored.")
    except ProcessLookupError:
        click.echo("Coreguard process not found. DNS settings restored.")
        from coreguard.config import PID_FILE
        PID_FILE.unlink(missing_ok=True)


@main.command()
def status():
    """Show coreguard status and statistics."""
    pid = read_pid()
    if pid is None or not process_exists(pid):
        click.echo("Coreguard is not running.")
        return

    click.echo(f"Coreguard is running (PID: {pid})")
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
        except ProcessLookupError:
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
        status_str = click.style("enabled", fg="green") if flist.get("enabled", True) else click.style("disabled", fg="red")
        click.echo(f"  [{status_str}] {flist['name']}")
        click.echo(f"           {flist['url']}")


@main.command("add-list")
@click.argument("url")
@click.option("--name", default=None, help="Name for the filter list")
def add_list(url, name):
    """Add a new filter list source by URL."""
    if name is None:
        # Derive name from URL
        name = url.rstrip("/").split("/")[-1].split(".")[0]

    config = load_config()

    # Check for duplicate URLs
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
