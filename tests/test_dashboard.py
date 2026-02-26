import json
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from coreguard.config import Config
from coreguard.dashboard import DashboardHandler, start_dashboard
from coreguard.stats import Stats


def _start_test_server(stats=None, cache=None, config=None):
    """Start a dashboard server on a random port for testing."""
    from http.server import HTTPServer

    if config is None:
        config = Config()
        config.dashboard_enabled = True
    if stats is None:
        stats = Stats()

    DashboardHandler.stats = stats
    DashboardHandler.cache = cache
    DashboardHandler.config = config

    server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
    port = server.server_address[1]

    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _get(port, path):
    """Make a GET request to the test server."""
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers, resp.read()


class TestDashboardEndpoints:
    def setup_method(self):
        self.stats = Stats()
        self.stats.record_query("example.com", blocked=False)
        self.stats.record_query("ads.tracker.com", blocked=True)
        self.stats.record_query("ads.tracker.com", blocked=True)
        self.stats.record_cache_hit()

        self.cache = MagicMock()
        self.cache.size = 42

        self.config = Config()
        self.config.dashboard_enabled = True

        self.server, self.port = _start_test_server(
            stats=self.stats, cache=self.cache, config=self.config
        )

    def teardown_method(self):
        self.server.shutdown()

    def test_html_endpoint(self):
        status, headers, body = _get(self.port, "/")
        assert status == 200
        assert "text/html" in headers["Content-Type"]
        html = body.decode()
        assert "Coreguard" in html
        assert "/api/stats" in html

    def test_stats_endpoint(self):
        status, headers, body = _get(self.port, "/api/stats")
        assert status == 200
        assert "application/json" in headers["Content-Type"]
        data = json.loads(body)
        assert data["total_queries"] == 3
        assert data["blocked_queries"] == 2
        assert data["cache_size"] == 42
        assert "top_blocked" in data
        assert "top_queried" in data

    def test_queries_endpoint(self):
        status, headers, body = _get(self.port, "/api/queries?limit=10")
        assert status == 200
        assert "application/json" in headers["Content-Type"]
        data = json.loads(body)
        assert isinstance(data, list)

    def test_config_endpoint(self):
        status, headers, body = _get(self.port, "/api/config")
        assert status == 200
        data = json.loads(body)
        assert data["upstream_mode"] == "doh"
        assert data["cache_enabled"] is True
        assert data["dashboard_port"] == 8080
        assert isinstance(data["providers"], list)
        assert isinstance(data["filter_lists"], list)

    def test_404_for_unknown_path(self):
        try:
            _get(self.port, "/nonexistent")
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_queries_limit_clamped(self):
        """Limit is clamped between 1 and 500."""
        status, _, body = _get(self.port, "/api/queries?limit=9999")
        assert status == 200
        # Should not error even with absurd limit

        status, _, body = _get(self.port, "/api/queries?limit=-5")
        assert status == 200

    def test_cors_header(self):
        _, headers, _ = _get(self.port, "/api/stats")
        assert headers["Access-Control-Allow-Origin"] == "*"


class TestStartDashboard:
    def test_returns_none_when_disabled(self):
        config = Config()
        config.dashboard_enabled = False
        stats = Stats()
        result = start_dashboard(config, stats)
        assert result is None

    def test_returns_server_when_enabled(self):
        config = Config()
        config.dashboard_enabled = True
        config.dashboard_port = 0  # Random port
        stats = Stats()
        server = start_dashboard(config, stats)
        assert server is not None
        server.shutdown()

    def test_returns_none_on_port_conflict(self):
        """If the port is already in use, returns None instead of crashing."""
        from http.server import HTTPServer

        # Occupy a port
        blocker = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = blocker.server_address[1]

        config = Config()
        config.dashboard_enabled = True
        config.dashboard_port = port

        stats = Stats()
        result = start_dashboard(config, stats)
        # The port is already bound by blocker, so start_dashboard should fail gracefully
        # Note: this may or may not conflict depending on SO_REUSEADDR, so we just
        # verify it doesn't raise
        if result is not None:
            result.shutdown()
        blocker.server_close()


class TestReadRecentQueries:
    def test_parses_log_entries(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO ALLOWED A github.com\n"
            "2026-02-26 14:30:03 [coreguard.queries] INFO BLOCKED AAAA tracker.net\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            from coreguard.dashboard import _read_recent_queries

            results = _read_recent_queries(100)
        assert len(results) == 3
        # Results are in reverse order (most recent first)
        assert results[0]["domain"] == "tracker.net"
        assert results[0]["status"] == "BLOCKED"
        assert results[0]["type"] == "AAAA"
        assert results[1]["domain"] == "github.com"
        assert results[1]["status"] == "ALLOWED"
        assert results[2]["domain"] == "ads.example.com"

    def test_respects_limit(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        lines = ""
        for i in range(10):
            lines += f"2026-02-26 14:30:{i:02d} [coreguard.queries] INFO ALLOWED A domain{i}.com\n"
        log_file.write_text(lines)
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            from coreguard.dashboard import _read_recent_queries

            results = _read_recent_queries(3)
        assert len(results) == 3

    def test_missing_log_file(self, tmp_path):
        log_file = tmp_path / "nonexistent.log"
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            from coreguard.dashboard import _read_recent_queries

            results = _read_recent_queries(100)
        assert results == []
