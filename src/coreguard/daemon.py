import atexit
import logging
import os
import signal
import sys
import time
from pathlib import Path

from coreguard.blocklist import update_all_lists
from coreguard.config import PID_FILE, STATS_FILE, Config
from coreguard.filtering import DomainFilter
from coreguard.network import restore_dns
from coreguard.stats import Stats
from coreguard.upstream import close_doh_client

logger = logging.getLogger("coreguard.daemon")


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

    # Write PID file
    PID_FILE.write_text(str(os.getpid()))
    atexit.register(lambda: PID_FILE.unlink(missing_ok=True))


def setup_signal_handlers(
    cleanup_fn: callable,
    reload_fn: callable | None = None,
) -> None:
    """Set up signal handlers for graceful shutdown and reload."""

    def shutdown_handler(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        cleanup_fn()
        sys.exit(0)

    def reload_handler(signum, frame):
        logger.info("Received SIGHUP, reloading filter lists...")
        if reload_fn:
            reload_fn()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    if reload_fn:
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


def main_loop(
    config: Config,
    domain_filter: DomainFilter,
    stats: Stats,
) -> None:
    """Main daemon loop: periodic list updates and stats persistence."""
    update_interval = config.update_interval_hours * 3600
    last_update = time.time()

    while True:
        time.sleep(60)

        # Persist stats periodically
        try:
            stats.save(STATS_FILE)
        except Exception:
            pass

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
    except (ProcessLookupError, PermissionError):
        return False


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
