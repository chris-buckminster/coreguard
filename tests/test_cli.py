from unittest.mock import patch

from click.testing import CliRunner

from coreguard.cli import main


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

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

    @patch("coreguard.cli.read_pid", return_value=None)
    @patch("coreguard.cli.process_exists", return_value=False)
    def test_status_not_running(self, mock_exists, mock_pid):
        result = self.runner.invoke(main, ["status"])
        assert "not running" in result.output

    def test_lists_shows_filter_lists(self):
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
