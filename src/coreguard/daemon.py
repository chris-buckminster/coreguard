import atexit
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from coreguard.blocklist import update_all_lists
from coreguard.config import PID_FILE, STATS_FILE, TEMP_ALLOW_FILE, Config
from coreguard.filtering import DomainFilter
from coreguard.network import restore_dns
from coreguard.schedule import collect_schedule_rules, get_active_schedules
from coreguard.stats import Stats
from coreguard.upstream import close_doh_client

logger = logging.getLogger("coreguard.daemon")

# Flag set by SIGHUP handler to trigger reload in main loop (signal-safe)
_reload_requested = threading.Event()


def daemonize() -> None:
    """Double-fork to become a background daemon."""
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error("First fork failed: %s", e)
        sys.exit(1)

    os.setsid()

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error("Second fork failed: %s", e)
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.close(devnull)


def write_pid_file() -> None:
    """Write current PID to file."""
    PID_FILE.write_text(str(os.getpid()))
    atexit.register(lambda: PID_FILE.unlink(missing_ok=True))


def setup_signal_handlers(cleanup_fn: callable) -> None:
    """Set up signal handlers for graceful shutdown and reload."""

    def shutdown_handler(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        cleanup_fn()
        sys.exit(0)

    def reload_handler(signum, frame):
        # Only set a flag — no I/O in signal context
        _reload_requested.set()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGHUP, reload_handler)


def cleanup(udp_server, tcp_server) -> None:
    """Stop servers, restore DNS, clean up."""
    logger.info("Cleaning up...")
    try:
        udp_server.stop()
        tcp_server.stop()
    except Exception as e:
        logger.warning("Error stopping servers: %s", e)
    try:
        restore_dns()
    except Exception as e:
        logger.warning("Error restoring DNS: %s", e)
    close_doh_client()
    PID_FILE.unlink(missing_ok=True)
    logger.info("Cleanup complete")


def _check_temp_expiry(config, domain_filter, cache) -> None:
    """Remove expired entries from temp-allow.json and reload filters if any were pruned."""
    if not TEMP_ALLOW_FILE.exists():
        return
    try:
        data = json.loads(TEMP_ALLOW_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return
    now = time.time()
    pruned = {domain: expires for domain, expires in data.items() if expires > now}
    if len(pruned) < len(data):
        if pruned:
            TEMP_ALLOW_FILE.write_text(json.dumps(pruned))
        else:
            TEMP_ALLOW_FILE.unlink(missing_ok=True)
        logger.info("Temp-allow entries expired, reloading filters")
        update_all_lists(config, domain_filter)
        if cache:
            cache.clear()


def main_loop(
    config: Config,
    domain_filter: DomainFilter,
    stats: Stats,
    cache=None,
) -> None:
    """Main daemon loop: periodic list updates, stats persistence, health checks."""
    update_interval = config.update_interval_hours * 3600
    last_update = time.time()
    last_dns_check = time.time()
    last_stats_trim = time.time()
    last_cache_sweep = time.time()
    last_temp_check = time.time()
    dns_check_interval = 60  # 1 minute — fast recovery after sleep/wake
    stats_trim_interval = 3600  # 1 hour
    cache_sweep_interval = 300  # 5 minutes
    temp_check_interval = 60  # 1 minute

    # Schedule tracking
    active_schedule_names: set[str] = set()
    domain_filter.snapshot_base()

    # Apply any initially active schedules
    if config.schedules:
        try:
            active = get_active_schedules(config.schedules)
            if active:
                active_schedule_names = {s.name for s in active}
                domains, wildcards, regexes = collect_schedule_rules(active)
                domain_filter.apply_schedule_overlay(domains, wildcards, regexes)
                logger.info("Initial schedules active: %s", active_schedule_names)
        except Exception as e:
            logger.debug("Initial schedule check failed: %s", e)

    while True:
        time.sleep(60)

        # Persist stats periodically
        try:
            stats.save(STATS_FILE)
        except Exception:
            pass

        # Handle SIGHUP reload (safe — runs in main loop, not signal context)
        if _reload_requested.is_set():
            _reload_requested.clear()
            try:
                logger.info("Reloading filter lists (SIGHUP)...")
                update_all_lists(config, domain_filter)
                domain_filter.snapshot_base()
                # Re-apply active schedules after reload
                if config.schedules:
                    active = get_active_schedules(config.schedules)
                    if active:
                        domains, wildcards, regexes = collect_schedule_rules(active)
                        domain_filter.apply_schedule_overlay(domains, wildcards, regexes)
                        active_schedule_names = {s.name for s in active}
                if cache:
                    cache.clear()
                    logger.info("Cache cleared after reload")
            except Exception as e:
                logger.warning("Reload failed: %s", e)

        # Check schedule transitions
        if config.schedules:
            try:
                active = get_active_schedules(config.schedules)
                new_names = {s.name for s in active}
                if new_names != active_schedule_names:
                    logger.info(
                        "Schedule transition: %s -> %s",
                        active_schedule_names, new_names,
                    )
                    domain_filter.restore_base()
                    if active:
                        domains, wildcards, regexes = collect_schedule_rules(active)
                        domain_filter.apply_schedule_overlay(domains, wildcards, regexes)
                    active_schedule_names = new_names
                    if cache:
                        cache.clear()
            except Exception as e:
                logger.debug("Schedule check failed: %s", e)

        # Check for expired temp-allow entries
        if (time.time() - last_temp_check) >= temp_check_interval:
            last_temp_check = time.time()
            try:
                _check_temp_expiry(config, domain_filter, cache)
            except Exception as e:
                logger.debug("Temp-allow expiry check failed: %s", e)

        # Periodic DNS health check — auto-re-apply if DNS has drifted
        if (time.time() - last_dns_check) >= dns_check_interval:
            last_dns_check = time.time()
            try:
                from coreguard.network import get_physical_interfaces, get_current_dns, reapply_dns
                from coreguard.notify import notify_dns_misconfigured
                reapply_failed = False
                for service in get_physical_interfaces():
                    servers = get_current_dns(service)
                    if "127.0.0.1" not in servers:
                        logger.warning(
                            "DNS for '%s' reset to %s, re-applying",
                            service, servers,
                        )
                        if not reapply_dns(service):
                            reapply_failed = True
                if reapply_failed:
                    notify_dns_misconfigured()
            except Exception as e:
                logger.debug("DNS health check failed: %s", e)

        # Sweep expired cache entries
        if cache and (time.time() - last_cache_sweep) >= cache_sweep_interval:
            last_cache_sweep = time.time()
            try:
                cache.sweep_expired()
            except Exception as e:
                logger.debug("Cache sweep failed: %s", e)

        # Trim stats counters to prevent unbounded memory growth
        if (time.time() - last_stats_trim) >= stats_trim_interval:
            last_stats_trim = time.time()
            stats.trim()

        # Auto-update filter lists
        if update_interval > 0 and (time.time() - last_update) >= update_interval:
            try:
                logger.info("Auto-updating filter lists...")
                update_all_lists(config, domain_filter)
                last_update = time.time()
            except Exception as e:
                logger.warning("Auto-update failed: %s", e)


def read_pid() -> int | None:
    """Read daemon PID from file, return None if not found."""
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        return pid
    except (ValueError, OSError):
        return None


def process_exists(pid: int) -> bool:
    """Check if a process with the given PID exists."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # PermissionError means the process exists but we can't signal it
        # (e.g., root-owned daemon checked by non-root user)
        return True


def is_running() -> bool:
    """Check if the daemon is currently running."""
    pid = read_pid()
    if pid is None:
        return False
    if process_exists(pid):
        return True
    # Stale PID file
    PID_FILE.unlink(missing_ok=True)
    return False
