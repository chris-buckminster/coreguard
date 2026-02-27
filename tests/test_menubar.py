"""Tests for coreguard.menubar — the macOS menubar status agent."""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from coreguard.menubar import (
    _DOMAIN_RE,
    _format_blocked_count,
    _generate_launch_agent_plist,
    _get_coreguard_path,
    _get_sudo_user,
    _is_running,
    _load_blocked_count,
    _load_recent_blocked,
    _dashboard_port,
    _rumps_available,
    _LAUNCH_AGENT_FILE,
    _LAUNCH_AGENT_LABEL,
    ensure_menubar_running,
    install_launch_agent,
    main,
    remove_menubar,
    uninstall_launch_agent,
)


# ---------------------------------------------------------------------------
# _format_blocked_count
# ---------------------------------------------------------------------------


class TestFormatBlockedCount:
    def test_zero(self):
        assert _format_blocked_count(0) == "Blocked: 0 queries"

    def test_thousands(self):
        assert _format_blocked_count(4521) == "Blocked: 4,521 queries"

    def test_millions(self):
        assert _format_blocked_count(1_234_567) == "Blocked: 1,234,567 queries"


# ---------------------------------------------------------------------------
# _generate_launch_agent_plist
# ---------------------------------------------------------------------------


class TestGenerateLaunchAgentPlist:
    def test_contains_label(self):
        plist = _generate_launch_agent_plist()
        assert _LAUNCH_AGENT_LABEL in plist

    def test_contains_executable(self):
        plist = _generate_launch_agent_plist()
        assert "coreguard-status" in plist

    def test_contains_run_at_load(self):
        plist = _generate_launch_agent_plist()
        assert "<key>RunAtLoad</key>" in plist
        assert "<true/>" in plist

    def test_valid_xml_structure(self):
        plist = _generate_launch_agent_plist()
        assert plist.startswith("<?xml version=")
        assert "<plist version=" in plist
        assert "</plist>" in plist


# ---------------------------------------------------------------------------
# _is_running
# ---------------------------------------------------------------------------


class TestIsRunning:
    @patch("coreguard.menubar.PID_FILE")
    def test_no_pid_file(self, mock_pid_file):
        mock_pid_file.exists.return_value = False
        assert _is_running() is False

    @patch("coreguard.menubar.os.kill")
    @patch("coreguard.menubar.PID_FILE")
    def test_running_process(self, mock_pid_file, mock_kill):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "12345\n"
        assert _is_running() is True
        mock_kill.assert_called_once_with(12345, 0)

    @patch("coreguard.menubar.os.kill", side_effect=ProcessLookupError)
    @patch("coreguard.menubar.PID_FILE")
    def test_dead_process(self, mock_pid_file, mock_kill):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "12345\n"
        assert _is_running() is False

    @patch("coreguard.menubar.os.kill", side_effect=PermissionError)
    @patch("coreguard.menubar.PID_FILE")
    def test_permission_error_means_running(self, mock_pid_file, mock_kill):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "12345\n"
        assert _is_running() is True

    @patch("coreguard.menubar.PID_FILE")
    def test_invalid_pid_content(self, mock_pid_file):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "not-a-number"
        assert _is_running() is False


# ---------------------------------------------------------------------------
# _load_blocked_count
# ---------------------------------------------------------------------------


class TestLoadBlockedCount:
    @patch("coreguard.menubar.STATS_FILE", new_callable=lambda: MagicMock)
    def test_returns_blocked_queries(self, _mock_stats_file):
        with patch("coreguard.stats.Stats.load_from_file", return_value={"blocked_queries": 42}):
            assert _load_blocked_count() == 42

    def test_returns_zero_on_exception(self):
        with patch("coreguard.stats.Stats.load_from_file", side_effect=Exception("fail")):
            assert _load_blocked_count() == 0


# ---------------------------------------------------------------------------
# _dashboard_port
# ---------------------------------------------------------------------------


class TestDashboardPort:
    @patch("coreguard.menubar.load_config")
    def test_returns_configured_port(self, mock_load):
        mock_config = MagicMock()
        mock_config.dashboard_port = 9090
        mock_load.return_value = mock_config
        assert _dashboard_port() == 9090

    @patch("coreguard.menubar.load_config", side_effect=Exception("fail"))
    def test_falls_back_to_8080(self, _mock):
        assert _dashboard_port() == 8080


# ---------------------------------------------------------------------------
# install_launch_agent / uninstall_launch_agent
# ---------------------------------------------------------------------------


class TestInstallLaunchAgent:
    @patch("coreguard.menubar.subprocess.run")
    @patch("coreguard.menubar._LAUNCH_AGENT_FILE")
    @patch("coreguard.menubar._LAUNCH_AGENT_DIR")
    def test_writes_plist_and_loads(self, mock_dir, mock_file, mock_run):
        path = install_launch_agent()
        mock_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_file.write_text.assert_called_once()
        plist_content = mock_file.write_text.call_args[0][0]
        assert _LAUNCH_AGENT_LABEL in plist_content
        mock_run.assert_called_once()
        assert path is mock_file


class TestUninstallLaunchAgent:
    @patch("coreguard.menubar._LAUNCH_AGENT_FILE")
    @patch("coreguard.menubar.subprocess.run")
    def test_unloads_and_removes(self, mock_run, mock_file):
        mock_file.exists.return_value = True
        uninstall_launch_agent()
        mock_run.assert_called_once()
        mock_file.unlink.assert_called_once_with(missing_ok=True)

    @patch("coreguard.menubar._LAUNCH_AGENT_FILE")
    @patch("coreguard.menubar.subprocess.run")
    def test_noop_when_not_installed(self, mock_run, mock_file):
        mock_file.exists.return_value = False
        uninstall_launch_agent()
        mock_run.assert_not_called()
        mock_file.unlink.assert_not_called()


# ---------------------------------------------------------------------------
# _get_sudo_user / ensure_menubar_running / remove_menubar
# ---------------------------------------------------------------------------


class TestGetSudoUser:
    @patch("coreguard.menubar.pwd")
    @patch.dict(os.environ, {"SUDO_USER": "testuser"})
    def test_returns_user_info(self, mock_pwd):
        pw = MagicMock()
        pw.pw_uid = 501
        pw.pw_gid = 20
        pw.pw_dir = "/Users/testuser"
        mock_pwd.getpwnam.return_value = pw
        result = _get_sudo_user()
        assert result == ("testuser", 501, 20, Path("/Users/testuser"))
        mock_pwd.getpwnam.assert_called_once_with("testuser")

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_none_without_sudo(self):
        assert _get_sudo_user() is None

    @patch("coreguard.menubar.pwd")
    @patch.dict(os.environ, {"SUDO_USER": "ghost"})
    def test_returns_none_on_unknown_user(self, mock_pwd):
        mock_pwd.getpwnam.side_effect = KeyError("ghost")
        assert _get_sudo_user() is None


class TestEnsureMenubarRunning:
    @patch("coreguard.menubar.subprocess.run")
    @patch("coreguard.menubar.os.chown")
    @patch("coreguard.menubar._get_sudo_user")
    @patch("coreguard.menubar._rumps_available", return_value=True)
    def test_installs_and_loads_for_user(self, _mock_rumps, mock_user, mock_chown, mock_run):
        home = Path("/tmp/test_menubar_home")
        mock_user.return_value = ("testuser", 501, 20, home)
        agent_dir = home / "Library" / "LaunchAgents"
        agent_file = agent_dir / f"{_LAUNCH_AGENT_LABEL}.plist"

        with patch.object(Path, "mkdir") as mock_mkdir, \
             patch.object(Path, "write_text") as mock_write:
            ensure_menubar_running()
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
            mock_write.assert_called_once()
            plist = mock_write.call_args[0][0]
            assert _LAUNCH_AGENT_LABEL in plist

        mock_chown.assert_called_once_with(str(agent_file), 501, 20)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["launchctl", "asuser"]
        assert "501" in cmd

    @patch("coreguard.menubar._rumps_available", return_value=False)
    def test_noop_without_rumps(self, _mock):
        # Should not raise or install anything.
        ensure_menubar_running()

    @patch("coreguard.menubar._rumps_available", return_value=True)
    @patch("coreguard.menubar._get_sudo_user", return_value=None)
    def test_noop_without_sudo_user(self, _mock_user, _mock_rumps):
        # Should not raise.
        ensure_menubar_running()

    @patch("coreguard.menubar._rumps_available", return_value=True)
    @patch("coreguard.menubar._get_sudo_user", side_effect=Exception("boom"))
    def test_swallows_exceptions(self, _mock_user, _mock_rumps):
        # Should not raise — non-critical.
        ensure_menubar_running()


class TestRemoveMenubar:
    @patch("coreguard.menubar.subprocess.run")
    @patch("coreguard.menubar._get_sudo_user")
    def test_unloads_and_removes(self, mock_user, mock_run):
        home = Path("/tmp/test_menubar_home")
        mock_user.return_value = ("testuser", 501, 20, home)
        agent_file = home / "Library" / "LaunchAgents" / f"{_LAUNCH_AGENT_LABEL}.plist"

        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "unlink") as mock_unlink:
            remove_menubar()
            mock_unlink.assert_called_once_with(missing_ok=True)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "unload" in cmd

    @patch("coreguard.menubar._get_sudo_user", return_value=None)
    def test_noop_without_sudo_user(self, _mock):
        remove_menubar()

    @patch("coreguard.menubar._get_sudo_user", side_effect=Exception("boom"))
    def test_swallows_exceptions(self, _mock):
        remove_menubar()


# ---------------------------------------------------------------------------
# Refresh (requires mock rumps)
# ---------------------------------------------------------------------------


class _MockMenuItem:
    """Minimal stand-in for rumps.MenuItem that supports submenu operations."""

    def __init__(self, title="", callback=None):
        self.title = title
        self._callback = callback
        self._children: list[_MockMenuItem] = []

    def set_callback(self, cb):
        self._callback = cb

    def clear(self):
        self._children.clear()

    def add(self, item):
        self._children.append(item)

    @property
    def values(self):
        return list(self._children)


def _make_mock_rumps():
    """Create a mock rumps module suitable for sys.modules injection."""
    mock = types.ModuleType("rumps")
    mock.App = type("App", (), {
        "__init__": lambda self, title, quit_button=None: None,
        "run": lambda self: None,
    })
    mock.MenuItem = _MockMenuItem
    # Use a lambda so the callback arg isn't treated as MagicMock's spec.
    mock.Timer = lambda callback, interval: MagicMock()
    mock.clicked = lambda name: lambda fn: fn  # no-op decorator
    mock.notification = MagicMock()
    return mock


class TestRefresh:
    def setup_method(self):
        self.mock_rumps = _make_mock_rumps()
        self._orig = sys.modules.get("rumps")
        sys.modules["rumps"] = self.mock_rumps

    def teardown_method(self):
        if self._orig is None:
            sys.modules.pop("rumps", None)
        else:
            sys.modules["rumps"] = self._orig

    @patch("coreguard.menubar._load_blocked_count", return_value=100)
    @patch("coreguard.menubar._is_running", return_value=True)
    def test_refresh_running(self, _mock_running, _mock_blocked):
        from coreguard.menubar import _build_app
        app = _build_app()
        app.refresh(None)
        assert app.title == "\u25cf"
        assert app.status_item.title == "Status: Running"
        assert app.blocked_item.title == "Blocked: 100 queries"

    @patch("coreguard.menubar._load_blocked_count", return_value=0)
    @patch("coreguard.menubar._is_running", return_value=False)
    def test_refresh_stopped(self, _mock_running, _mock_blocked):
        from coreguard.menubar import _build_app
        app = _build_app()
        app.refresh(None)
        assert app.title == "\u25cb"
        assert app.status_item.title == "Status: Stopped"

    @patch("coreguard.menubar._load_blocked_count", side_effect=Exception("boom"))
    @patch("coreguard.menubar._is_running", side_effect=Exception("boom"))
    def test_refresh_exception_shows_stopped(self, _mock_running, _mock_blocked):
        from coreguard.menubar import _build_app
        app = _build_app()
        app.refresh(None)
        assert app.title == "\u25cb"
        assert app.status_item.title == "Status: Stopped"


# ---------------------------------------------------------------------------
# open_dashboard
# ---------------------------------------------------------------------------


class TestOpenDashboard:
    def setup_method(self):
        self.mock_rumps = _make_mock_rumps()
        self._orig = sys.modules.get("rumps")
        sys.modules["rumps"] = self.mock_rumps

    def teardown_method(self):
        if self._orig is None:
            sys.modules.pop("rumps", None)
        else:
            sys.modules["rumps"] = self._orig

    @patch("coreguard.menubar.webbrowser.open")
    @patch("coreguard.menubar._dashboard_port", return_value=8080)
    def test_opens_correct_url(self, _mock_port, mock_open):
        from coreguard.menubar import _build_app
        app = _build_app()
        app.open_dashboard(None)
        mock_open.assert_called_once_with("http://localhost:8080")

    @patch("coreguard.menubar.webbrowser.open")
    @patch("coreguard.menubar._dashboard_port", return_value=9090)
    def test_uses_configured_port(self, _mock_port, mock_open):
        from coreguard.menubar import _build_app
        app = _build_app()
        app.open_dashboard(None)
        mock_open.assert_called_once_with("http://localhost:9090")


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------


class TestMain:
    @patch("builtins.print")
    def test_help_flag(self, mock_print):
        main(["--help"])
        output = mock_print.call_args[0][0]
        assert "Usage:" in output
        assert "--install" in output

    @patch("coreguard.menubar.install_launch_agent")
    @patch("builtins.print")
    def test_install_flag(self, mock_print, mock_install):
        mock_install.return_value = Path("/tmp/test.plist")
        main(["--install"])
        mock_install.assert_called_once()
        assert "installed" in mock_print.call_args[0][0].lower()

    @patch("coreguard.menubar.uninstall_launch_agent")
    @patch("builtins.print")
    def test_uninstall_flag(self, mock_print, mock_uninstall):
        main(["--uninstall"])
        mock_uninstall.assert_called_once()
        assert "uninstalled" in mock_print.call_args[0][0].lower()

    @patch("coreguard.menubar._build_app", side_effect=ImportError("No module named 'rumps'"))
    def test_missing_rumps(self, _mock_build):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# _load_recent_blocked
# ---------------------------------------------------------------------------


class TestLoadRecentBlocked:
    def test_no_log_file(self, tmp_path):
        with patch("coreguard.menubar.LOG_FILE", tmp_path / "nonexistent.log"):
            assert _load_recent_blocked() == []

    def test_parses_blocked_entries(self, tmp_path):
        log = tmp_path / "coreguard.log"
        log.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO BLOCKED AAAA tracker.foo.com\n"
        )
        with patch("coreguard.menubar.LOG_FILE", log):
            result = _load_recent_blocked()
        assert result == ["tracker.foo.com", "ads.example.com"]

    def test_deduplicates(self, tmp_path):
        log = tmp_path / "coreguard.log"
        log.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO BLOCKED A tracker.foo.com\n"
            "2026-02-26 14:30:03 [coreguard.queries] INFO BLOCKED AAAA ads.example.com\n"
        )
        with patch("coreguard.menubar.LOG_FILE", log):
            result = _load_recent_blocked()
        # ads.example.com appears twice but should only show once (most recent first)
        assert result == ["ads.example.com", "tracker.foo.com"]

    def test_skips_allowed(self, tmp_path):
        log = tmp_path / "coreguard.log"
        log.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO ALLOWED A safe.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
        )
        with patch("coreguard.menubar.LOG_FILE", log):
            result = _load_recent_blocked()
        assert result == ["ads.example.com"]

    def test_limit(self, tmp_path):
        log = tmp_path / "coreguard.log"
        lines = [
            f"2026-02-26 14:30:{i:02d} [coreguard.queries] INFO BLOCKED A domain{i}.com\n"
            for i in range(10)
        ]
        log.write_text("".join(lines))
        with patch("coreguard.menubar.LOG_FILE", log):
            result = _load_recent_blocked(limit=3)
        assert len(result) == 3
        # Most recent (highest index) first
        assert result == ["domain9.com", "domain8.com", "domain7.com"]


# ---------------------------------------------------------------------------
# _get_coreguard_path
# ---------------------------------------------------------------------------


class TestGetCoreguardPath:
    def test_finds_alongside_executable(self, tmp_path):
        fake_bin = tmp_path / "coreguard"
        fake_bin.touch()
        with patch("coreguard.menubar.sys.executable", str(tmp_path / "python")):
            assert _get_coreguard_path() == str(fake_bin)

    @patch("coreguard.menubar.shutil.which", return_value="/usr/local/bin/coreguard")
    def test_falls_back_to_which(self, _mock_which, tmp_path):
        with patch("coreguard.menubar.sys.executable", str(tmp_path / "python")):
            assert _get_coreguard_path() == "/usr/local/bin/coreguard"

    @patch("coreguard.menubar.shutil.which", return_value=None)
    def test_returns_none_when_not_found(self, _mock_which, tmp_path):
        with patch("coreguard.menubar.sys.executable", str(tmp_path / "python")):
            assert _get_coreguard_path() is None


# ---------------------------------------------------------------------------
# Recent Blocked submenu (requires mock rumps)
# ---------------------------------------------------------------------------


class TestRecentBlockedSubmenu:
    def setup_method(self):
        self.mock_rumps = _make_mock_rumps()
        self._orig = sys.modules.get("rumps")
        sys.modules["rumps"] = self.mock_rumps

    def teardown_method(self):
        if self._orig is None:
            sys.modules.pop("rumps", None)
        else:
            sys.modules["rumps"] = self._orig

    @patch("coreguard.menubar._load_recent_blocked", return_value=["ads.example.com", "tracker.foo.com"])
    @patch("coreguard.menubar._load_blocked_count", return_value=100)
    @patch("coreguard.menubar._is_running", return_value=True)
    def test_refresh_populates_submenu(self, _run, _count, _blocked):
        from coreguard.menubar import _build_app
        app = _build_app()
        children = app.recent_blocked_item.values
        assert len(children) == 2
        assert children[0].title == "ads.example.com"
        assert children[1].title == "tracker.foo.com"

    @patch("coreguard.menubar._load_recent_blocked", return_value=[])
    @patch("coreguard.menubar._load_blocked_count", return_value=0)
    @patch("coreguard.menubar._is_running", return_value=False)
    def test_refresh_empty_submenu(self, _run, _count, _blocked):
        from coreguard.menubar import _build_app
        app = _build_app()
        children = app.recent_blocked_item.values
        assert len(children) == 1
        assert children[0].title == "No blocked queries yet"


# ---------------------------------------------------------------------------
# _unblock_clicked
# ---------------------------------------------------------------------------


class TestUnblockClicked:
    def setup_method(self):
        self.mock_rumps = _make_mock_rumps()
        self._orig = sys.modules.get("rumps")
        sys.modules["rumps"] = self.mock_rumps

    def teardown_method(self):
        if self._orig is None:
            sys.modules.pop("rumps", None)
        else:
            sys.modules["rumps"] = self._orig

    @patch("coreguard.menubar.subprocess.run")
    @patch("coreguard.menubar._get_coreguard_path", return_value="/usr/local/bin/coreguard")
    @patch("coreguard.menubar._load_recent_blocked", return_value=[])
    @patch("coreguard.menubar._load_blocked_count", return_value=0)
    @patch("coreguard.menubar._is_running", return_value=False)
    def test_unblock_calls_osascript(self, _run, _count, _blocked, _cg, mock_subproc):
        from coreguard.menubar import _build_app
        app = _build_app()
        sender = MagicMock()
        sender.title = "ads.example.com"
        app._unblock_clicked(sender)
        mock_subproc.assert_called_once()
        cmd = mock_subproc.call_args[0][0]
        assert cmd[0] == "osascript"
        assert "ads.example.com" in mock_subproc.call_args[0][0][-1]
        assert "unblock" in mock_subproc.call_args[0][0][-1]
        assert "administrator privileges" in mock_subproc.call_args[0][0][-1]

    @patch("coreguard.menubar.subprocess.run")
    @patch("coreguard.menubar._get_coreguard_path", return_value="/usr/local/bin/coreguard")
    @patch("coreguard.menubar._load_recent_blocked", return_value=[])
    @patch("coreguard.menubar._load_blocked_count", return_value=0)
    @patch("coreguard.menubar._is_running", return_value=False)
    def test_unblock_validates_domain(self, _run, _count, _blocked, _cg, mock_subproc):
        from coreguard.menubar import _build_app
        app = _build_app()
        sender = MagicMock()
        sender.title = "bad domain; rm -rf /"
        app._unblock_clicked(sender)
        mock_subproc.assert_not_called()

    @patch("coreguard.menubar.subprocess.run", side_effect=subprocess.CalledProcessError(1, "osascript"))
    @patch("coreguard.menubar._get_coreguard_path", return_value="/usr/local/bin/coreguard")
    @patch("coreguard.menubar._load_recent_blocked", return_value=[])
    @patch("coreguard.menubar._load_blocked_count", return_value=0)
    @patch("coreguard.menubar._is_running", return_value=False)
    def test_unblock_handles_cancel(self, _run, _count, _blocked, _cg, _subproc):
        from coreguard.menubar import _build_app
        app = _build_app()
        sender = MagicMock()
        sender.title = "ads.example.com"
        # Should not raise
        app._unblock_clicked(sender)
