"""Lightweight macOS menubar status agent for Coreguard.

Displays daemon health and blocked-query count in the macOS menubar.
Runs as a separate user-level process, polling the daemon's PID file
and stats JSON every 5 seconds.
"""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
import webbrowser
from pathlib import Path

from coreguard.config import PID_FILE, STATS_FILE, load_config

_LAUNCH_AGENT_LABEL = "com.coreguard.status"
_LAUNCH_AGENT_DIR = Path.home() / "Library" / "LaunchAgents"
_LAUNCH_AGENT_FILE = _LAUNCH_AGENT_DIR / f"{_LAUNCH_AGENT_LABEL}.plist"

_ICON_RUNNING = "\u25cf"  # ●
_ICON_STOPPED = "\u25cb"  # ○

_POLL_INTERVAL = 5  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_blocked_count(count: int) -> str:
    """Return a human-readable menu label for blocked queries."""
    return f"Blocked: {count:,} queries"


def _is_running() -> bool:
    """Check whether the daemon process is alive (non-root safe)."""
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but owned by root — still running.
        return True


def _load_blocked_count() -> int:
    """Load blocked-query count from the stats file."""
    try:
        from coreguard.stats import Stats
        stats = Stats.load_from_file(STATS_FILE)
        return stats.get("blocked_queries", 0)
    except Exception:
        return 0


def _dashboard_port() -> int:
    """Return the configured dashboard port, falling back to 8080."""
    try:
        config = load_config()
        return config.dashboard_port
    except Exception:
        return 8080


def _generate_launch_agent_plist() -> str:
    """Generate a LaunchAgent plist that starts coreguard-status at login."""
    executable = os.path.join(os.path.dirname(sys.executable), "coreguard-status")
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"""


def install_launch_agent() -> Path:
    """Write the LaunchAgent plist and load it."""
    _LAUNCH_AGENT_DIR.mkdir(parents=True, exist_ok=True)
    _LAUNCH_AGENT_FILE.write_text(_generate_launch_agent_plist())
    subprocess.run(
        ["launchctl", "load", str(_LAUNCH_AGENT_FILE)],
        check=False,
    )
    return _LAUNCH_AGENT_FILE


def uninstall_launch_agent() -> None:
    """Unload and remove the LaunchAgent plist."""
    if _LAUNCH_AGENT_FILE.exists():
        subprocess.run(
            ["launchctl", "unload", str(_LAUNCH_AGENT_FILE)],
            check=False,
        )
        _LAUNCH_AGENT_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Root-context helpers (called from `sudo coreguard start/install/uninstall`)
# ---------------------------------------------------------------------------

def _get_sudo_user() -> tuple[str, int, int, Path] | None:
    """Return (username, uid, gid, home) for the user who invoked sudo."""
    username = os.environ.get("SUDO_USER")
    if not username:
        return None
    try:
        pw = pwd.getpwnam(username)
        return username, pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)
    except KeyError:
        return None


def _rumps_available() -> bool:
    """Check whether rumps is importable (installed)."""
    try:
        import importlib.util
        return importlib.util.find_spec("rumps") is not None
    except Exception:
        return False


def ensure_menubar_running() -> None:
    """Install and start the menubar LaunchAgent for the logged-in user.

    Safe to call from root context (e.g. ``sudo coreguard start``).
    Uses ``SUDO_USER`` to determine the real user. Does nothing if
    ``SUDO_USER`` is not set or if rumps is not installed.
    """
    try:
        if not _rumps_available():
            return
        user_info = _get_sudo_user()
        if user_info is None:
            return
        username, uid, gid, home = user_info

        agent_dir = home / "Library" / "LaunchAgents"
        agent_file = agent_dir / f"{_LAUNCH_AGENT_LABEL}.plist"
        agent_dir.mkdir(parents=True, exist_ok=True)
        agent_file.write_text(_generate_launch_agent_plist())
        os.chown(str(agent_file), uid, gid)

        # Load the LaunchAgent in the user's launchd domain.
        subprocess.run(
            ["launchctl", "asuser", str(uid), "launchctl", "load", str(agent_file)],
            capture_output=True,
            check=False,
        )
    except Exception:
        pass  # Non-critical — don't fail the daemon start


def remove_menubar() -> None:
    """Unload and remove the menubar LaunchAgent for the logged-in user.

    Safe to call from root context.
    """
    try:
        user_info = _get_sudo_user()
        if user_info is None:
            return
        _, uid, _, home = user_info

        agent_file = home / "Library" / "LaunchAgents" / f"{_LAUNCH_AGENT_LABEL}.plist"
        if not agent_file.exists():
            return

        subprocess.run(
            ["launchctl", "asuser", str(uid), "launchctl", "unload", str(agent_file)],
            capture_output=True,
            check=False,
        )
        agent_file.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Menubar application (requires rumps)
# ---------------------------------------------------------------------------

def _build_app():  # noqa: C901
    """Construct and return the rumps App instance.

    Isolated into a function so the import can be deferred and tests can
    mock the ``rumps`` module before calling this.
    """
    import rumps

    class CoreguardStatusApp(rumps.App):
        def __init__(self) -> None:
            super().__init__(_ICON_STOPPED, quit_button="Quit")
            self.status_item = rumps.MenuItem("Status: Stopped")
            self.blocked_item = rumps.MenuItem("Blocked: 0 queries")
            self.dashboard_item = rumps.MenuItem("Open Dashboard")
            self.menu = [
                self.status_item,
                self.blocked_item,
                None,  # separator
                self.dashboard_item,
            ]
            self._timer = rumps.Timer(self.refresh, _POLL_INTERVAL)
            self._timer.start()
            # Run an initial refresh immediately.
            self.refresh(None)

        def refresh(self, _sender) -> None:
            """Poll daemon status and update the menu."""
            try:
                running = _is_running()
                blocked = _load_blocked_count()
            except Exception:
                running = False
                blocked = 0

            self.title = _ICON_RUNNING if running else _ICON_STOPPED
            self.status_item.title = (
                "Status: Running" if running else "Status: Stopped"
            )
            self.blocked_item.title = _format_blocked_count(blocked)

        @rumps.clicked("Open Dashboard")
        def open_dashboard(self, _sender) -> None:
            port = _dashboard_port()
            webbrowser.open(f"http://localhost:{port}")

    return CoreguardStatusApp()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """Entry point for ``coreguard-status``."""
    args = argv if argv is not None else sys.argv[1:]

    if "--help" in args or "-h" in args:
        print(
            "Usage: coreguard-status [--install | --uninstall]\n"
            "\n"
            "Lightweight macOS menubar agent for Coreguard.\n"
            "\n"
            "Options:\n"
            "  --install      Install LaunchAgent to start at login\n"
            "  --uninstall    Remove LaunchAgent\n"
            "  --help, -h     Show this help message"
        )
        return

    if "--install" in args:
        path = install_launch_agent()
        print(f"LaunchAgent installed: {path}")
        return

    if "--uninstall" in args:
        uninstall_launch_agent()
        print("LaunchAgent uninstalled.")
        return

    # Start the menubar app.
    try:
        app = _build_app()
    except ImportError:
        print(
            "Error: rumps is not installed.\n"
            "Reinstall coreguard with: pip install coreguard",
            file=sys.stderr,
        )
        sys.exit(1)
    app.run()
