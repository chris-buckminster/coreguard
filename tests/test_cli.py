import signal
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from coreguard.cli import main


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

    def test_allow_adds_domain(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.touch()
        with patch("coreguard.cli.CUSTOM_ALLOW_FILE", allow_file):
            result = self.runner.invoke(main, ["allow", "example.com"])
            assert result.exit_code == 0
            assert "example.com" in allow_file.read_text()

    def test_block_adds_domain(self, tmp_path):
        block_file = tmp_path / "block.txt"
        block_file.touch()
        with patch("coreguard.cli.CUSTOM_BLOCK_FILE", block_file):
            result = self.runner.invoke(main, ["block", "evil.com"])
            assert result.exit_code == 0
            assert "evil.com" in block_file.read_text()

    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_adds_to_allowlist(self, mock_pid, tmp_path):
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

    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_removes_from_blocklist(self, mock_pid, tmp_path):
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

    @patch("coreguard.cli.read_pid", return_value=None)
    def test_unblock_deduplicates(self, mock_pid, tmp_path):
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

    @patch("coreguard.cli.process_exists", return_value=True)
    @patch("coreguard.cli.read_pid", return_value=1234)
    def test_unblock_signals_daemon(self, mock_pid, mock_exists, tmp_path):
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
