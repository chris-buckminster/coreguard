import logging
from unittest.mock import patch, MagicMock

from coreguard.logging_config import QueryLogger


class TestQueryLoggerInit:
    def test_creates_logger_with_handler(self, tmp_path):
        log_file = tmp_path / "test.log"
        ql = QueryLogger(log_file)
        assert ql.logger.name == "coreguard.queries"
        assert ql.logger.level == logging.INFO
        assert ql.logger.propagate is False
        assert len(ql.logger.handlers) >= 1
        # Clean up handlers to avoid leaking across tests
        ql.logger.handlers.clear()

    def test_no_duplicate_handlers_on_reinit(self, tmp_path):
        log_file = tmp_path / "test.log"
        ql1 = QueryLogger(log_file)
        handler_count = len(ql1.logger.handlers)
        ql2 = QueryLogger(log_file)
        assert len(ql2.logger.handlers) == handler_count
        # Clean up
        ql1.logger.handlers.clear()


class TestLogQuery:
    def setup_method(self):
        self.mock_logger = MagicMock()

    @patch("coreguard.logging_config.logging.getLogger")
    def test_logs_blocked(self, mock_get_logger, tmp_path):
        mock_get_logger.return_value = self.mock_logger
        self.mock_logger.handlers = []
        ql = QueryLogger(tmp_path / "test.log")
        ql.log_query("ads.example.com", "A", blocked=True)
        self.mock_logger.info.assert_called_once_with("%s %s %s", "BLOCKED", "A", "ads.example.com")

    @patch("coreguard.logging_config.logging.getLogger")
    def test_logs_allowed(self, mock_get_logger, tmp_path):
        mock_get_logger.return_value = self.mock_logger
        self.mock_logger.handlers = []
        ql = QueryLogger(tmp_path / "test.log")
        ql.log_query("github.com", "AAAA", blocked=False)
        self.mock_logger.info.assert_called_once_with("%s %s %s", "ALLOWED", "AAAA", "github.com")

    @patch("coreguard.logging_config.logging.getLogger")
    def test_logs_various_qtypes(self, mock_get_logger, tmp_path):
        mock_get_logger.return_value = self.mock_logger
        self.mock_logger.handlers = []
        ql = QueryLogger(tmp_path / "test.log")
        ql.log_query("example.com", "MX", blocked=False)
        self.mock_logger.info.assert_called_once_with("%s %s %s", "ALLOWED", "MX", "example.com")
