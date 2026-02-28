import json
import signal
from unittest.mock import patch, MagicMock

import click
import pytest
from click.testing import CliRunner

from coreguard.cli import main, parse_duration


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()
        # Mock ensure_dirs since /usr/local/etc/coreguard/ requires root
        self._ensure_patcher = patch("coreguard.cli.ensure_dirs")
        self._ensure_patcher.start()

    def teardown_method(self):
        self._ensure_patcher.stop()

    def test_help(self):
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Coreguard" in result.output

    def test_start_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result = self.runner.invoke(main, ["start"])
            assert result.exit_code != 0
            assert "root" in result.output or "sudo" in result.output

    def test_stop_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result = self.runner.invoke(main, ["stop"])
            assert result.exit_code != 0

    @patch("coreguard.cli._port_53_responding", return_value=False)
    @patch("coreguard.cli.read_pid", return_value=None)
    @patch("coreguard.cli.process_exists", return_value=False)
    def test_status_not_running(self, mock_exists, mock_pid, mock_port):
        result = self.runner.invoke(main, ["status"])
        assert "not running" in result.output

    @patch("coreguard.cli.load_config")
    def test_lists_shows_filter_lists(self, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["lists"])
        assert result.exit_code == 0
        assert "stevenblack" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_allow_adds_domain(self, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file):
            result = self.runner.invoke(main, ["allow", "example.com"])
            assert result.exit_code == 0
            assert "example.com" in allow_file.read_text()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_block_adds_domain(self, mock_euid, tmp_path):
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["block", "evil.com"])
            assert result.exit_code == 0
            assert "evil.com" in block_file.read_text()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_block_regex(self, mock_euid, tmp_path):
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["block", "--regex", r"^ads\..*\.com$"])
            assert result.exit_code == 0
            assert r"regex:^ads\..*\.com$" in block_file.read_text()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_allow_regex(self, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file):
            result = self.runner.invoke(main, ["allow", "--regex", r"^safe\..*\.com$"])
            assert result.exit_code == 0
            assert r"regex:^safe\..*\.com$" in allow_file.read_text()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_block_regex_invalid(self, mock_euid, tmp_path):
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["block", "--regex", r"[invalid"])
            assert result.exit_code != 0
            assert "Invalid regex" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_adds_to_allowlist(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["unblock", "example.com"])
            assert result.exit_code == 0
            assert "example.com" in allow_file.read_text()
            assert "allowlist" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_removes_from_blocklist(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.write_text("other.com\nevil.com\nmore.com\n")
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["unblock", "evil.com"])
            assert result.exit_code == 0
            assert "Removed" in result.output
            contents = block_file.read_text()
            assert "evil.com" not in contents
            assert "other.com" in contents
            assert "more.com" in contents

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_deduplicates(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("example.com\n")
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["unblock", "example.com"])
            assert result.exit_code == 0
            assert "already in allowlist" in result.output
            # Should not duplicate
            assert allow_file.read_text().count("example.com") == 1

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.process_exists", return_value=True)
    @patch("coreguard.cli.read_pid", return_value=1234)
    def test_unblock_signals_daemon(self, mock_pid, mock_exists, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.cli.os.kill") as mock_kill:
            result = self.runner.invoke(main, ["unblock", "example.com"])
            assert result.exit_code == 0
            mock_kill.assert_called_once_with(1234, signal.SIGHUP)
            assert "Reload signal sent" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_with_for_flag(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.touch()
        temp_file = tmp_path / "temp-allow.json"
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.cli.TEMP_ALLOW_FILE", temp_file):
            result = self.runner.invoke(main, ["unblock", "example.com", "--for", "5m"])
            assert result.exit_code == 0
            assert "Temporarily allowed" in result.output
            # Should write to temp-allow.json, not custom-allow.txt
            assert allow_file.read_text() == ""
            data = json.loads(temp_file.read_text())
            assert "example.com" in data

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.process_exists", return_value=True)
    @patch("coreguard.cli.read_pid", return_value=1234)
    def test_unblock_for_signals_daemon(self, mock_pid, mock_exists, mock_euid, tmp_path):
        temp_file = tmp_path / "temp-allow.json"
        with patch("coreguard.cli.TEMP_ALLOW_FILE", temp_file), \
             patch("coreguard.cli.os.kill") as mock_kill:
            result = self.runner.invoke(main, ["unblock", "example.com", "--for", "10s"])
            assert result.exit_code == 0
            mock_kill.assert_called_once_with(1234, signal.SIGHUP)
            assert "Reload signal sent" in result.output


class TestParseDuration:
    def test_parse_duration_minutes(self):
        assert parse_duration("5m") == 300

    def test_parse_duration_hours(self):
        assert parse_duration("1h") == 3600

    def test_parse_duration_seconds(self):
        assert parse_duration("30s") == 30

    def test_parse_duration_invalid(self):
        with pytest.raises(click.BadParameter):
            parse_duration("5x")

    def test_parse_duration_no_unit(self):
        with pytest.raises(click.BadParameter):
            parse_duration("300")

    def test_parse_duration_empty(self):
        with pytest.raises(click.BadParameter):
            parse_duration("")


class TestJSONOutput:
    """Tests for --json flag on all CLI commands."""

    def setup_method(self):
        self.runner = CliRunner()
        self._ensure_patcher = patch("coreguard.cli.ensure_dirs")
        self._ensure_patcher.start()

    def teardown_method(self):
        self._ensure_patcher.stop()

    def _invoke_json(self, args):
        """Invoke CLI with --json flag and parse output."""
        result = self.runner.invoke(main, ["--json"] + args)
        if result.output.strip():
            data = json.loads(result.output.strip())
        else:
            data = None
        return result, data

    # --- status ---

    @patch("coreguard.cli._port_53_responding", return_value=False)
    @patch("coreguard.cli.read_pid", return_value=None)
    @patch("coreguard.cli.process_exists", return_value=False)
    def test_status_json_not_running(self, mock_exists, mock_pid, mock_port):
        result, data = self._invoke_json(["status"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert data["running"] is False
        assert data["pid"] is None
        assert data["port_53_responding"] is False
        assert "config_dir" in data
        assert "stats" in data

    @patch("coreguard.cli._port_53_responding", return_value=True)
    @patch("coreguard.cli.read_pid", return_value=42)
    @patch("coreguard.cli.process_exists", return_value=True)
    @patch("coreguard.cli.Stats.load_from_file")
    def test_status_json_running(self, mock_stats, mock_exists, mock_pid, mock_port):
        mock_stats.return_value = {
            "total_queries": 100, "blocked_queries": 30, "blocked_percent": 30.0,
            "error_queries": 0, "cache_hits": 50, "cache_misses": 50,
            "cache_hit_rate": 50.0, "cname_blocks": 2,
            "top_blocked": {"ads.example.com": 10}, "top_queried": {"google.com": 20},
        }
        result, data = self._invoke_json(["status"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert data["running"] is True
        assert data["pid"] == 42
        assert data["stats"]["total_queries"] == 100

    # --- lists ---

    @patch("coreguard.cli.load_config")
    def test_lists_json(self, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result, data = self._invoke_json(["lists"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert isinstance(data["filter_lists"], list)
        assert len(data["filter_lists"]) > 0
        first = data["filter_lists"][0]
        assert "name" in first
        assert "url" in first
        assert "enabled" in first

    # --- doctor ---

    @patch("coreguard.cli._port_53_responding", return_value=False)
    @patch("coreguard.cli.read_pid", return_value=None)
    @patch("coreguard.cli.process_exists", return_value=False)
    @patch("coreguard.cli.get_active_interfaces", return_value=[])
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.LOG_FILE")
    @patch("coreguard.cli.LAUNCHD_PLIST_PATH")
    def test_doctor_json(self, mock_plist, mock_log, mock_config, mock_ifaces,
                         mock_exists, mock_pid, mock_port):
        from coreguard.config import Config
        mock_config.return_value = Config()
        mock_plist.exists.return_value = False
        mock_log.exists.return_value = False
        mock_bldir = MagicMock()
        mock_bldir.glob.return_value = []
        with patch("coreguard.config.BLOCKLISTS_DIR", mock_bldir):
            result, data = self._invoke_json(["doctor"])
        assert result.exit_code == 0
        assert data["status"] in ("ok", "error")
        assert isinstance(data["checks"], list)
        assert isinstance(data["issues"], list)
        # At minimum, daemon and port_53 checks should be present
        check_names = [c["name"] for c in data["checks"]]
        assert "daemon" in check_names
        assert "port_53" in check_names

    # --- allow / block ---

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_allow_json(self, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file):
            result, data = self._invoke_json(["allow", "example.com"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert data["domain"] == "example.com"
            assert data["action"] == "added_to_allowlist"
            assert "example.com" in allow_file.read_text()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    def test_block_json(self, mock_euid, tmp_path):
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result, data = self._invoke_json(["block", "evil.com"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert data["domain"] == "evil.com"
            assert data["action"] == "added_to_blocklist"

    # --- unblock ---

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_json(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result, data = self._invoke_json(["unblock", "example.com"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert data["domain"] == "example.com"
            assert data["action"] == "added_to_allowlist"
            assert "reload_signal_sent" in data

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_for_json(self, mock_pid, mock_euid, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        block_file = tmp_path / "block.txt"
        block_file.touch()
        temp_file = tmp_path / "temp-allow.json"
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.cli.TEMP_ALLOW_FILE", temp_file):
            result, data = self._invoke_json(["unblock", "example.com", "--for", "5m"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert data["domain"] == "example.com"
            assert data["action"] == "temp_allowed"
            assert data["duration"] == "5m"
            assert "expires_at" in data

    # --- log ---

    def test_log_json(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text("line1\nline2\nline3\n")
        with patch("coreguard.cli.LOG_FILE", log_file):
            result, data = self._invoke_json(["log"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert isinstance(data["lines"], list)
            assert len(data["lines"]) == 3

    def test_log_json_rejects_follow(self):
        result, data = self._invoke_json(["log", "-f"])
        assert result.exit_code != 0
        assert data["status"] == "error"
        assert "incompatible" in data["message"]

    def test_log_json_no_file(self, tmp_path):
        log_file = tmp_path / "nonexistent.log"
        with patch("coreguard.cli.LOG_FILE", log_file):
            result, data = self._invoke_json(["log"])
            assert result.exit_code == 0
            assert data["status"] == "ok"
            assert data["lines"] == []

    # --- start / stop require root ---

    def test_start_json_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result, data = self._invoke_json(["start"])
            assert result.exit_code != 0
            assert data["status"] == "error"
            assert "root" in data["message"]

    def test_stop_json_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result, data = self._invoke_json(["stop"])
            assert result.exit_code != 0
            assert data["status"] == "error"
            assert "root" in data["message"]

    # --- add-list / remove-list ---

    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    def test_add_list_json(self, mock_save, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result, data = self._invoke_json(["add-list", "https://example.com/hosts.txt", "--name", "test-list"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert data["name"] == "test-list"
        assert data["action"] == "added"

    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    def test_remove_list_json(self, mock_save, mock_config):
        from coreguard.config import Config
        config = Config()
        config.filter_lists = [{"name": "test-list", "url": "https://example.com/hosts.txt", "enabled": True}]
        mock_config.return_value = config
        result, data = self._invoke_json(["remove-list", "test-list"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert data["name"] == "test-list"
        assert data["action"] == "removed"

    @patch("coreguard.cli.load_config")
    def test_remove_list_json_not_found(self, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result, data = self._invoke_json(["remove-list", "nonexistent"])
        assert result.exit_code == 0
        assert data["status"] == "error"
        assert data["action"] == "not_found"

    # --- install / uninstall ---

    def test_install_json_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result, data = self._invoke_json(["install"])
            assert result.exit_code != 0
            assert data["status"] == "error"
            assert "root" in data["message"]

    def test_uninstall_json_requires_root(self):
        with patch("coreguard.cli.os.geteuid", return_value=1000):
            result, data = self._invoke_json(["uninstall"])
            assert result.exit_code != 0
            assert data["status"] == "error"
            assert "root" in data["message"]

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.LAUNCHD_PLIST_PATH")
    def test_uninstall_json_not_installed(self, mock_plist, mock_euid):
        mock_plist.exists.return_value = False
        result, data = self._invoke_json(["uninstall"])
        assert result.exit_code == 0
        assert data["status"] == "ok"

    # --- update ---

    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.update_all_lists", return_value=50000)
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_update_json(self, mock_pid, mock_update, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result, data = self._invoke_json(["update"])
        assert result.exit_code == 0
        assert data["status"] == "ok"
        assert data["domains_count"] == 50000
        assert "reload_signal_sent" in data


class TestScheduleCLI:
    def setup_method(self):
        self.runner = CliRunner()
        self._ensure_patcher = patch("coreguard.cli.ensure_dirs")
        self._ensure_patcher.start()

    def teardown_method(self):
        self._ensure_patcher.stop()

    @patch("coreguard.cli.load_config")
    def test_schedule_list_empty(self, mock_config):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["schedule", "list"])
        assert result.exit_code == 0
        assert "No schedules" in result.output

    @patch("coreguard.cli.load_config")
    def test_schedule_list_json(self, mock_config):
        from coreguard.config import Config, Schedule
        config = Config()
        config.schedules = [Schedule(name="test", start="09:00", end="17:00")]
        mock_config.return_value = config
        result = self.runner.invoke(main, ["--json", "schedule", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert data["status"] == "ok"
        assert len(data["schedules"]) == 1
        assert data["schedules"][0]["name"] == "test"

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_schedule_add(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, [
            "schedule", "add", "--name", "work",
            "--start", "09:00", "--end", "17:00",
            "--days", "mon,tue,wed,thu,fri",
            "--domain", "reddit.com",
            "--pattern", "*.tiktok.com",
        ])
        assert result.exit_code == 0
        assert "work" in result.output
        assert "added" in result.output.lower()
        # Verify config was saved with the new schedule
        saved_config = mock_save.call_args[0][0]
        assert len(saved_config.schedules) == 1
        assert saved_config.schedules[0].name == "work"
        assert saved_config.schedules[0].block_domains == ["reddit.com"]
        assert saved_config.schedules[0].block_patterns == ["*.tiktok.com"]
        assert saved_config.schedules[0].days == ["mon", "tue", "wed", "thu", "fri"]

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_schedule_add_defaults_all_days(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, [
            "schedule", "add", "--name", "daily",
            "--start", "08:00", "--end", "22:00",
        ])
        assert result.exit_code == 0
        saved_config = mock_save.call_args[0][0]
        assert saved_config.schedules[0].days == ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_schedule_add_duplicate_name(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config, Schedule
        config = Config()
        config.schedules = [Schedule(name="work")]
        mock_config.return_value = config
        result = self.runner.invoke(main, [
            "schedule", "add", "--name", "work",
            "--start", "09:00", "--end", "17:00",
        ])
        assert result.exit_code != 0
        assert "already exists" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_schedule_remove(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config, Schedule
        config = Config()
        config.schedules = [Schedule(name="work"), Schedule(name="night")]
        mock_config.return_value = config
        result = self.runner.invoke(main, ["schedule", "remove", "work"])
        assert result.exit_code == 0
        assert "removed" in result.output.lower()
        saved_config = mock_save.call_args[0][0]
        assert len(saved_config.schedules) == 1
        assert saved_config.schedules[0].name == "night"

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    def test_schedule_remove_not_found(self, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["schedule", "remove", "nonexistent"])
        assert result.exit_code != 0
        assert "no schedule found" in result.output.lower()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_schedule_enable_disable(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config, Schedule
        config = Config()
        config.schedules = [Schedule(name="work", enabled=True)]
        mock_config.return_value = config
        result = self.runner.invoke(main, ["schedule", "disable", "work"])
        assert result.exit_code == 0
        assert "disabled" in result.output.lower()
        saved_config = mock_save.call_args[0][0]
        assert saved_config.schedules[0].enabled is False

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    def test_schedule_add_invalid_time(self, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, [
            "schedule", "add", "--name", "bad",
            "--start", "not-a-time", "--end", "17:00",
        ])
        assert result.exit_code != 0
        assert "Invalid time" in result.output

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    def test_schedule_add_invalid_day(self, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, [
            "schedule", "add", "--name", "bad",
            "--start", "09:00", "--end", "17:00",
            "--days", "monday",
        ])
        assert result.exit_code != 0
        assert "Invalid day" in result.output


class TestParentalCLI:
    def setup_method(self):
        self.runner = CliRunner()
        self._ensure_patcher = patch("coreguard.cli.ensure_dirs")
        self._ensure_patcher.start()

    def teardown_method(self):
        self._ensure_patcher.stop()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_safesearch_enable(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["parental", "safesearch", "--enable"])
        assert result.exit_code == 0
        assert "enabled" in result.output.lower()
        saved_config = mock_save.call_args[0][0]
        assert saved_config.safe_search_enabled is True

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_safesearch_disable(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        config = Config()
        config.safe_search_enabled = True
        mock_config.return_value = config
        result = self.runner.invoke(main, ["parental", "safesearch", "--disable"])
        assert result.exit_code == 0
        assert "disabled" in result.output.lower()

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_categories_add(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["parental", "categories", "--add", "adult", "--add", "gambling"])
        assert result.exit_code == 0
        saved_config = mock_save.call_args[0][0]
        assert "adult" in saved_config.content_categories
        assert "gambling" in saved_config.content_categories

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    @patch("coreguard.cli.save_config")
    @patch("coreguard.cli.read_pid", return_value=None)
    def test_categories_remove(self, mock_pid, mock_save, mock_config, mock_euid):
        from coreguard.config import Config
        config = Config()
        config.content_categories = ["adult", "gambling"]
        mock_config.return_value = config
        result = self.runner.invoke(main, ["parental", "categories", "--remove", "gambling"])
        assert result.exit_code == 0
        saved_config = mock_save.call_args[0][0]
        assert saved_config.content_categories == ["adult"]

    @patch("coreguard.cli.os.geteuid", return_value=0)
    @patch("coreguard.cli.load_config")
    def test_categories_invalid(self, mock_config, mock_euid):
        from coreguard.config import Config
        mock_config.return_value = Config()
        result = self.runner.invoke(main, ["parental", "categories", "--add", "invalid"])
        assert result.exit_code != 0
        assert "Unknown category" in result.output


class TestPort53Responding:
    def test_socket_closed_on_exception(self):
        """Socket should be closed even when an exception occurs."""
        from unittest.mock import MagicMock

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = OSError("Connection refused")

        with patch("socket.socket", return_value=mock_sock):
            from coreguard.cli import _port_53_responding
            result = _port_53_responding()

        assert result is False
        mock_sock.close.assert_called_once()

    def test_socket_closed_on_success(self):
        """Socket should be closed after successful response."""
        from unittest.mock import MagicMock

        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"\x00" * 12, ("127.0.0.1", 53))

        with patch("socket.socket", return_value=mock_sock):
            from coreguard.cli import _port_53_responding
            result = _port_53_responding()

        assert result is True
        mock_sock.close.assert_called_once()
