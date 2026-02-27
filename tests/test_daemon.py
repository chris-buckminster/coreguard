import json
import signal
import threading
import time
from unittest.mock import MagicMock, patch, call

from coreguard.daemon import (
    _check_temp_expiry,
    cleanup,
    is_running,
    main_loop,
    process_exists,
    read_pid,
    setup_signal_handlers,
    write_pid_file,
)
from coreguard.config import Config
from coreguard.filtering import DomainFilter
from coreguard.stats import Stats


class TestReadPid:
    @patch("coreguard.daemon.PID_FILE")
    def test_returns_pid(self, mock_pid_file):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "12345"
        assert read_pid() == 12345

    @patch("coreguard.daemon.PID_FILE")
    def test_returns_none_when_missing(self, mock_pid_file):
        mock_pid_file.exists.return_value = False
        assert read_pid() is None

    @patch("coreguard.daemon.PID_FILE")
    def test_returns_none_on_invalid_content(self, mock_pid_file):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.return_value = "not-a-pid"
        assert read_pid() is None

    @patch("coreguard.daemon.PID_FILE")
    def test_returns_none_on_os_error(self, mock_pid_file):
        mock_pid_file.exists.return_value = True
        mock_pid_file.read_text.side_effect = OSError("permission denied")
        assert read_pid() is None


class TestProcessExists:
    @patch("os.kill")
    def test_returns_true_when_process_alive(self, mock_kill):
        mock_kill.return_value = None
        assert process_exists(1234) is True
        mock_kill.assert_called_once_with(1234, 0)

    @patch("os.kill")
    def test_returns_false_when_no_process(self, mock_kill):
        mock_kill.side_effect = ProcessLookupError()
        assert process_exists(1234) is False

    @patch("os.kill")
    def test_returns_true_on_permission_error(self, mock_kill):
        mock_kill.side_effect = PermissionError()
        assert process_exists(1234) is True


class TestIsRunning:
    @patch("coreguard.daemon.PID_FILE")
    @patch("coreguard.daemon.process_exists", return_value=True)
    @patch("coreguard.daemon.read_pid", return_value=999)
    def test_running(self, mock_read, mock_exists, mock_pid_file):
        assert is_running() is True

    @patch("coreguard.daemon.read_pid", return_value=None)
    def test_no_pid_file(self, mock_read):
        assert is_running() is False

    @patch("coreguard.daemon.PID_FILE")
    @patch("coreguard.daemon.process_exists", return_value=False)
    @patch("coreguard.daemon.read_pid", return_value=999)
    def test_stale_pid_cleans_up(self, mock_read, mock_exists, mock_pid_file):
        assert is_running() is False
        mock_pid_file.unlink.assert_called_once_with(missing_ok=True)


class TestWritePidFile:
    @patch("atexit.register")
    @patch("os.getpid", return_value=42)
    @patch("coreguard.daemon.PID_FILE")
    def test_writes_pid_and_registers_cleanup(self, mock_pid_file, mock_getpid, mock_atexit):
        write_pid_file()
        mock_pid_file.write_text.assert_called_once_with("42")
        mock_atexit.assert_called_once()


class TestSetupSignalHandlers:
    @patch("signal.signal")
    def test_registers_all_signals(self, mock_signal):
        cleanup_fn = MagicMock()
        setup_signal_handlers(cleanup_fn)
        registered_signals = [c[0][0] for c in mock_signal.call_args_list]
        assert signal.SIGTERM in registered_signals
        assert signal.SIGINT in registered_signals
        assert signal.SIGHUP in registered_signals

    @patch("sys.exit")
    @patch("signal.signal")
    def test_shutdown_handler_calls_cleanup(self, mock_signal, mock_exit):
        cleanup_fn = MagicMock()
        setup_signal_handlers(cleanup_fn)
        # Extract the SIGTERM handler
        for c in mock_signal.call_args_list:
            if c[0][0] == signal.SIGTERM:
                handler = c[0][1]
                break
        handler(signal.SIGTERM, None)
        cleanup_fn.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("signal.signal")
    def test_sighup_sets_reload_flag(self, mock_signal):
        from coreguard.daemon import _reload_requested
        _reload_requested.clear()

        setup_signal_handlers(MagicMock())
        # Extract the SIGHUP handler
        for c in mock_signal.call_args_list:
            if c[0][0] == signal.SIGHUP:
                handler = c[0][1]
                break
        handler(signal.SIGHUP, None)
        assert _reload_requested.is_set()
        _reload_requested.clear()


class TestCleanup:
    @patch("coreguard.daemon.PID_FILE")
    @patch("coreguard.daemon.close_doh_client")
    @patch("coreguard.daemon.restore_dns")
    def test_happy_path(self, mock_restore, mock_close, mock_pid_file):
        udp = MagicMock()
        tcp = MagicMock()
        cleanup(udp, tcp)
        udp.stop.assert_called_once()
        tcp.stop.assert_called_once()
        mock_restore.assert_called_once()
        mock_close.assert_called_once()
        mock_pid_file.unlink.assert_called_once_with(missing_ok=True)

    @patch("coreguard.daemon.PID_FILE")
    @patch("coreguard.daemon.close_doh_client")
    @patch("coreguard.daemon.restore_dns")
    def test_continues_on_server_stop_error(self, mock_restore, mock_close, mock_pid_file):
        udp = MagicMock()
        udp.stop.side_effect = RuntimeError("shutdown failed")
        tcp = MagicMock()
        cleanup(udp, tcp)
        # Should still restore DNS and clean up
        mock_restore.assert_called_once()
        mock_close.assert_called_once()
        mock_pid_file.unlink.assert_called_once_with(missing_ok=True)

    @patch("coreguard.daemon.PID_FILE")
    @patch("coreguard.daemon.close_doh_client")
    @patch("coreguard.daemon.restore_dns")
    def test_continues_on_dns_restore_error(self, mock_restore, mock_close, mock_pid_file):
        mock_restore.side_effect = RuntimeError("restore failed")
        cleanup(MagicMock(), MagicMock())
        # Should still close client and unlink PID
        mock_close.assert_called_once()
        mock_pid_file.unlink.assert_called_once_with(missing_ok=True)


class TestMainLoop:
    """Tests for main_loop. Each test patches time.sleep to raise after
    controlled iterations so the infinite loop terminates."""

    def setup_method(self):
        self.config = Config()
        self.config.update_interval_hours = 24
        self.domain_filter = DomainFilter()
        self.stats = Stats()
        self.cache = MagicMock()

    @patch("coreguard.daemon.time")
    @patch("coreguard.daemon.STATS_FILE")
    @patch.object(Stats, "save")
    def test_persists_stats(self, mock_save, mock_stats_file, mock_time):
        mock_time.time.return_value = 0
        mock_time.sleep.side_effect = [None, StopIteration]

        try:
            main_loop(self.config, self.domain_filter, self.stats, self.cache)
        except StopIteration:
            pass

        mock_save.assert_called()

    @patch("coreguard.daemon.update_all_lists")
    @patch("coreguard.daemon._reload_requested")
    @patch("coreguard.daemon.time")
    def test_sighup_triggers_reload(self, mock_time, mock_reload, mock_update):
        mock_time.time.return_value = 0
        mock_time.sleep.side_effect = [None, StopIteration]
        mock_reload.is_set.return_value = True

        try:
            main_loop(self.config, self.domain_filter, self.stats, self.cache)
        except StopIteration:
            pass

        mock_update.assert_called_once_with(self.config, self.domain_filter)
        self.cache.clear.assert_called_once()
        mock_reload.clear.assert_called()

    @patch("coreguard.daemon.update_all_lists")
    @patch("coreguard.daemon._reload_requested")
    @patch("coreguard.daemon.time")
    def test_reload_without_cache(self, mock_time, mock_reload, mock_update):
        mock_time.time.return_value = 0
        mock_time.sleep.side_effect = [None, StopIteration]
        mock_reload.is_set.return_value = True

        try:
            main_loop(self.config, self.domain_filter, self.stats, cache=None)
        except StopIteration:
            pass

        mock_update.assert_called_once()

    @patch("coreguard.notify.send_notification")
    @patch("coreguard.network.reapply_dns", return_value=True)
    @patch("coreguard.network.get_current_dns", return_value=["8.8.8.8"])
    @patch("coreguard.network.get_physical_interfaces", return_value=["Wi-Fi"])
    @patch("coreguard.daemon._reload_requested")
    @patch("coreguard.daemon.time")
    def test_dns_drift_reapplies(self, mock_time, mock_reload, mock_ifaces,
                                  mock_dns, mock_reapply, mock_notify):
        # Simulate enough time passing for DNS check (>60s)
        mock_time.time.side_effect = [0, 0, 0, 0, 100, 100, 100, 100, 100, 100, 100]
        mock_time.sleep.side_effect = [None, StopIteration]
        mock_reload.is_set.return_value = False

        try:
            main_loop(self.config, self.domain_filter, self.stats, self.cache)
        except StopIteration:
            pass

        mock_reapply.assert_called_with("Wi-Fi")

    @patch("coreguard.daemon._reload_requested")
    @patch("coreguard.daemon.time")
    def test_cache_sweep(self, mock_time, mock_reload):
        # Simulate 301 seconds elapsed for cache sweep (>300s interval)
        mock_time.time.side_effect = [0, 0, 0, 0, 301, 301, 301, 301, 301, 301, 301]
        mock_time.sleep.side_effect = [None, StopIteration]
        mock_reload.is_set.return_value = False

        try:
            main_loop(self.config, self.domain_filter, self.stats, self.cache)
        except StopIteration:
            pass

        self.cache.sweep_expired.assert_called()

    @patch("coreguard.daemon.update_all_lists")
    @patch("coreguard.daemon._reload_requested")
    @patch("coreguard.daemon.time")
    def test_auto_update(self, mock_time, mock_reload, mock_update):
        self.config.update_interval_hours = 1
        # Simulate 3601 seconds elapsed — enough values for all timer checks
        mock_time.time.side_effect = [0] * 5 + [3601] * 20
        mock_time.sleep.side_effect = [None, StopIteration]
        mock_reload.is_set.return_value = False

        try:
            main_loop(self.config, self.domain_filter, self.stats, self.cache)
        except StopIteration:
            pass

        mock_update.assert_called()


class TestCheckTempExpiry:
    def setup_method(self):
        self.config = Config()
        self.domain_filter = DomainFilter()
        self.cache = MagicMock()

    @patch("coreguard.daemon.update_all_lists")
    def test_removes_expired_entries(self, mock_update, tmp_path):
        temp_file = tmp_path / "temp-allow.json"
        past = time.time() - 100
        future = time.time() + 300
        temp_file.write_text(json.dumps({"expired.com": past, "valid.com": future}))

        with patch("coreguard.daemon.TEMP_ALLOW_FILE", temp_file):
            _check_temp_expiry(self.config, self.domain_filter, self.cache)

        # Should have pruned expired entry and triggered reload
        data = json.loads(temp_file.read_text())
        assert "expired.com" not in data
        assert "valid.com" in data
        mock_update.assert_called_once_with(self.config, self.domain_filter)
        self.cache.clear.assert_called_once()

    @patch("coreguard.daemon.update_all_lists")
    def test_no_op_when_nothing_expired(self, mock_update, tmp_path):
        temp_file = tmp_path / "temp-allow.json"
        future = time.time() + 300
        temp_file.write_text(json.dumps({"valid.com": future}))

        with patch("coreguard.daemon.TEMP_ALLOW_FILE", temp_file):
            _check_temp_expiry(self.config, self.domain_filter, self.cache)

        mock_update.assert_not_called()
        self.cache.clear.assert_not_called()

    @patch("coreguard.daemon.update_all_lists")
    def test_missing_file_no_crash(self, mock_update, tmp_path):
        temp_file = tmp_path / "temp-allow.json"  # does not exist

        with patch("coreguard.daemon.TEMP_ALLOW_FILE", temp_file):
            _check_temp_expiry(self.config, self.domain_filter, self.cache)

        mock_update.assert_not_called()

    @patch("coreguard.daemon.update_all_lists")
    def test_deletes_file_when_all_expired(self, mock_update, tmp_path):
        temp_file = tmp_path / "temp-allow.json"
        past = time.time() - 100
        temp_file.write_text(json.dumps({"expired.com": past}))

        with patch("coreguard.daemon.TEMP_ALLOW_FILE", temp_file):
            _check_temp_expiry(self.config, self.domain_filter, self.cache)

        assert not temp_file.exists()
        mock_update.assert_called_once()
