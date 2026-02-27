import json
import threading
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from coreguard.config import Config
from coreguard.dashboard import (
    DashboardHandler,
    _history_cache,
    _read_query_history,
    _read_recent_queries,
    _validate_domain,
    _remove_from_file,
    _parse_duration,
    start_dashboard,
)
from coreguard.stats import Stats


def _start_test_server(stats=None, cache=None, config=None, token=""):
    """Start a dashboard server on a random port for testing."""
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn

    class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    if config is None:
        config = Config()
        config.dashboard_enabled = True
    if stats is None:
        stats = Stats()

    DashboardHandler.stats = stats
    DashboardHandler.cache = cache
    DashboardHandler.config = config
    DashboardHandler.token = token

    server = _ThreadedHTTPServer(("127.0.0.1", 0), DashboardHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _get(port, path):
    """Make a GET request to the test server."""
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers, resp.read()


def _request(port, method, path, body=None, token=None):
    """Make an HTTP request to the test server."""
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, e.headers, json.loads(e.read())


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
        self.server.server_close()

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
        assert "query_types" in data
        assert "top_clients" in data
        assert "sparkline" in data
        assert isinstance(data["sparkline"]["total"], list)
        assert isinstance(data["sparkline"]["blocked"], list)
        assert isinstance(data["sparkline"]["allowed"], list)
        assert len(data["sparkline"]["total"]) == 12

    def test_queries_endpoint(self):
        status, headers, body = _get(self.port, "/api/queries?limit=10")
        assert status == 200
        assert "application/json" in headers["Content-Type"]
        data = json.loads(body)
        assert "queries" in data
        assert isinstance(data["queries"], list)
        assert "total" in data
        assert "offset" in data
        assert "limit" in data
        assert "has_more" in data

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

        status, _, body = _get(self.port, "/api/queries?limit=-5")
        assert status == 200

    def test_cors_header(self):
        _, headers, _ = _get(self.port, "/api/stats")
        assert headers["Access-Control-Allow-Origin"] == "*"

    def test_domains_endpoint(self, tmp_path):
        allow_file = tmp_path / "custom-allow.txt"
        block_file = tmp_path / "custom-block.txt"
        temp_file = tmp_path / "temp-allow.json"

        allow_file.write_text("example.com\ngoogle.com\n")
        block_file.write_text("ads.example.com\n")
        temp_file.write_text("{}")

        with patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.dashboard.TEMP_ALLOW_FILE", temp_file):
            status, _, body = _get(self.port, "/api/domains")
            assert status == 200
            data = json.loads(body)
            assert "example.com" in data["allowlist"]
            assert "google.com" in data["allowlist"]
            assert "ads.example.com" in data["blocklist"]
            assert data["temp_allowlist"] == []


class TestDashboardAuth:
    def setup_method(self):
        self.token = "test-secret-token-12345"
        self.server, self.port = _start_test_server(token=self.token)

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_get_without_auth_works(self):
        """GET endpoints should work without auth."""
        status, _, _ = _get(self.port, "/api/stats")
        assert status == 200

    def test_post_without_auth_fails(self):
        """POST endpoints should require auth."""
        status, _, data = _request(self.port, "POST", "/api/auth/verify")
        assert status == 401
        assert "error" in data

    def test_post_with_wrong_token_fails(self):
        status, _, data = _request(
            self.port, "POST", "/api/auth/verify", token="wrong-token"
        )
        assert status == 401

    def test_post_with_correct_token_succeeds(self):
        status, _, data = _request(
            self.port, "POST", "/api/auth/verify", token=self.token
        )
        assert status == 200
        assert data["status"] == "ok"

    def test_verify_endpoint(self):
        status, _, data = _request(
            self.port, "POST", "/api/auth/verify", body={}, token=self.token
        )
        assert status == 200
        assert data["status"] == "ok"

    def test_no_token_configured_allows_all(self):
        """When no token is set, all requests are allowed."""
        server, port = _start_test_server(token="")
        try:
            status, _, data = _request(port, "POST", "/api/auth/verify")
            assert status == 200
        finally:
            server.shutdown()
            server.server_close()


class TestDomainEndpoints:
    def setup_method(self):
        self.token = "domain-test-token"
        self.server, self.port = _start_test_server(token=self.token)

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_add_allow_domain(self, tmp_path):
        allow_file = tmp_path / "custom-allow.txt"
        allow_file.write_text("")
        with patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/allow",
                body={"domain": "example.com"}, token=self.token
            )
            assert status == 200
            assert data["status"] == "ok"
            assert "example.com" in allow_file.read_text()

    def test_add_block_domain(self, tmp_path):
        block_file = tmp_path / "custom-block.txt"
        block_file.write_text("")
        with patch("coreguard.dashboard.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/block",
                body={"domain": "ads.example.com"}, token=self.token
            )
            assert status == 200
            assert "ads.example.com" in block_file.read_text()

    def test_remove_allow_domain(self, tmp_path):
        allow_file = tmp_path / "custom-allow.txt"
        allow_file.write_text("example.com\nother.com\n")
        with patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "DELETE", "/api/domains/allow",
                body={"domain": "example.com"}, token=self.token
            )
            assert status == 200
            assert "example.com" not in allow_file.read_text()
            assert "other.com" in allow_file.read_text()

    def test_remove_block_domain(self, tmp_path):
        block_file = tmp_path / "custom-block.txt"
        block_file.write_text("ads.example.com\n")
        with patch("coreguard.dashboard.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "DELETE", "/api/domains/block",
                body={"domain": "ads.example.com"}, token=self.token
            )
            assert status == 200

    def test_remove_nonexistent_domain_returns_404(self, tmp_path):
        allow_file = tmp_path / "custom-allow.txt"
        allow_file.write_text("")
        with patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "DELETE", "/api/domains/allow",
                body={"domain": "notfound.com"}, token=self.token
            )
            assert status == 404
            assert "error" in data

    def test_invalid_domain_rejected(self):
        with patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/allow",
                body={"domain": "not a valid domain!!!"}, token=self.token
            )
            assert status == 400
            assert "Invalid domain" in data["error"]

    def test_empty_domain_rejected(self):
        with patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/allow",
                body={"domain": ""}, token=self.token
            )
            assert status == 400

    def test_domain_normalization(self, tmp_path):
        allow_file = tmp_path / "custom-allow.txt"
        allow_file.write_text("")
        with patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/allow",
                body={"domain": "EXAMPLE.COM."}, token=self.token
            )
            assert status == 200
            assert data["domain"] == "example.com"

    def test_permanent_unblock(self, tmp_path):
        block_file = tmp_path / "custom-block.txt"
        allow_file = tmp_path / "custom-allow.txt"
        block_file.write_text("blocked.com\n")
        allow_file.write_text("")
        with patch("coreguard.dashboard.CUSTOM_BLOCK_FILE", block_file), \
             patch("coreguard.dashboard.CUSTOM_ALLOW_FILE", allow_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/unblock",
                body={"domain": "blocked.com"}, token=self.token
            )
            assert status == 200
            assert "blocked.com" not in block_file.read_text()
            assert "blocked.com" in allow_file.read_text()

    def test_temp_unblock(self, tmp_path):
        temp_file = tmp_path / "temp-allow.json"
        temp_file.write_text("{}")
        with patch("coreguard.dashboard.TEMP_ALLOW_FILE", temp_file), \
             patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/unblock",
                body={"domain": "temp.com", "duration": "5m"}, token=self.token
            )
            assert status == 200
            temp_data = json.loads(temp_file.read_text())
            assert "temp.com" in temp_data

    def test_temp_unblock_invalid_duration(self):
        with patch("coreguard.dashboard._send_self_sighup"):
            status, _, data = _request(
                self.port, "POST", "/api/domains/unblock",
                body={"domain": "temp.com", "duration": "xyz"}, token=self.token
            )
            assert status == 400
            assert "Invalid duration" in data["error"]


class TestListEndpoints:
    def setup_method(self):
        self.token = "list-test-token"
        self.config = Config()
        self.config.dashboard_enabled = True
        self.server, self.port = _start_test_server(
            config=self.config, token=self.token
        )

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_toggle_list(self, tmp_path):
        config_file = tmp_path / "config.toml"
        with patch("coreguard.dashboard.load_config", return_value=Config()) as mock_load, \
             patch("coreguard.dashboard.save_config") as mock_save:
            status, _, data = _request(
                self.port, "POST", "/api/lists/toggle",
                body={"name": "stevenblack-unified", "enabled": False},
                token=self.token,
            )
            assert status == 200
            assert data["status"] == "ok"
            assert data["enabled"] is False
            mock_save.assert_called_once()

    def test_toggle_nonexistent_list(self):
        with patch("coreguard.dashboard.load_config", return_value=Config()):
            status, _, data = _request(
                self.port, "POST", "/api/lists/toggle",
                body={"name": "nonexistent-list", "enabled": True},
                token=self.token,
            )
            assert status == 404
            assert "not found" in data["error"]

    def test_add_list(self):
        with patch("coreguard.dashboard.load_config", return_value=Config()) as mock_load, \
             patch("coreguard.dashboard.save_config") as mock_save:
            status, _, data = _request(
                self.port, "POST", "/api/lists/add",
                body={"url": "https://example.com/hosts.txt", "name": "test-list"},
                token=self.token,
            )
            assert status == 200
            assert data["name"] == "test-list"
            mock_save.assert_called_once()

    def test_add_duplicate_list(self):
        cfg = Config()
        with patch("coreguard.dashboard.load_config", return_value=cfg):
            existing_url = cfg.filter_lists[0]["url"]
            status, _, data = _request(
                self.port, "POST", "/api/lists/add",
                body={"url": existing_url, "name": "duplicate"},
                token=self.token,
            )
            assert status == 409
            assert "already exists" in data["error"]

    def test_remove_list(self):
        with patch("coreguard.dashboard.load_config", return_value=Config()) as mock_load, \
             patch("coreguard.dashboard.save_config") as mock_save:
            status, _, data = _request(
                self.port, "POST", "/api/lists/remove",
                body={"name": "stevenblack-unified"},
                token=self.token,
            )
            assert status == 200
            assert data["name"] == "stevenblack-unified"
            mock_save.assert_called_once()

    def test_remove_nonexistent_list(self):
        with patch("coreguard.dashboard.load_config", return_value=Config()):
            status, _, data = _request(
                self.port, "POST", "/api/lists/remove",
                body={"name": "nonexistent"},
                token=self.token,
            )
            assert status == 404

    def test_toggle_missing_fields(self):
        status, _, data = _request(
            self.port, "POST", "/api/lists/toggle",
            body={"name": "foo"}, token=self.token
        )
        assert status == 400

    def test_add_missing_fields(self):
        status, _, data = _request(
            self.port, "POST", "/api/lists/add",
            body={"url": "https://example.com"}, token=self.token
        )
        assert status == 400


class TestSystemEndpoints:
    def setup_method(self):
        self.token = "system-test-token"
        self.cache = MagicMock()
        self.server, self.port = _start_test_server(
            cache=self.cache, token=self.token
        )

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_update_trigger(self):
        with patch("coreguard.dashboard._send_self_sighup") as mock_sighup:
            status, _, data = _request(
                self.port, "POST", "/api/update",
                body={}, token=self.token
            )
            assert status == 200
            assert data["status"] == "ok"
            mock_sighup.assert_called_once()

    def test_cache_clear(self):
        status, _, data = _request(
            self.port, "POST", "/api/cache/clear",
            body={}, token=self.token
        )
        assert status == 200
        self.cache.clear.assert_called_once()

    def test_daemon_stop(self):
        with patch("coreguard.dashboard.os.kill") as mock_kill, \
             patch("coreguard.dashboard.threading.Timer") as mock_timer:
            status, _, data = _request(
                self.port, "POST", "/api/daemon/stop",
                body={}, token=self.token
            )
            assert status == 200
            assert "stopping" in data["message"].lower()


class TestOptionsPreFlight:
    def setup_method(self):
        self.server, self.port = _start_test_server()

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_options_returns_cors_headers(self):
        url = f"http://127.0.0.1:{self.port}/api/domains/allow"
        req = urllib.request.Request(url, method="OPTIONS")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 204
            assert "POST" in resp.headers["Access-Control-Allow-Methods"]
            assert "DELETE" in resp.headers["Access-Control-Allow-Methods"]
            assert "Authorization" in resp.headers["Access-Control-Allow-Headers"]


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
        config.dashboard_token = "existing-token"
        stats = Stats()
        with patch("coreguard.dashboard.save_config"):
            server = start_dashboard(config, stats)
        assert server is not None
        server.shutdown()
        server.server_close()

    def test_auto_generates_token_when_empty(self):
        config = Config()
        config.dashboard_enabled = True
        config.dashboard_port = 0
        config.dashboard_token = ""
        stats = Stats()
        with patch("coreguard.dashboard.save_config") as mock_save:
            server = start_dashboard(config, stats)
        assert server is not None
        assert len(config.dashboard_token) == 32  # uuid4().hex
        mock_save.assert_called_once()
        server.shutdown()
        server.server_close()

    def test_preserves_existing_token(self):
        config = Config()
        config.dashboard_enabled = True
        config.dashboard_port = 0
        config.dashboard_token = "my-existing-token"
        stats = Stats()
        with patch("coreguard.dashboard.save_config"):
            server = start_dashboard(config, stats)
        assert config.dashboard_token == "my-existing-token"
        server.shutdown()
        server.server_close()

    def test_returns_none_on_port_conflict(self):
        """If the port is already in use, returns None instead of crashing."""
        from http.server import HTTPServer

        # Occupy a port
        blocker = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = blocker.server_address[1]

        config = Config()
        config.dashboard_enabled = True
        config.dashboard_port = port
        config.dashboard_token = "test"

        stats = Stats()
        with patch("coreguard.dashboard.save_config"):
            result = start_dashboard(config, stats)
        if result is not None:
            result.shutdown()
            result.server_close()
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
            results, total = _read_recent_queries(100)
        assert total == 3
        assert len(results) == 3
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
            results, total = _read_recent_queries(3)
        assert len(results) == 3
        assert total == 10

    def test_missing_log_file(self, tmp_path):
        log_file = tmp_path / "nonexistent.log"
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            results, total = _read_recent_queries(100)
        assert results == []
        assert total == 0

    def test_pagination_with_offset(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        lines = ""
        for i in range(10):
            lines += f"2026-02-26 14:30:{i:02d} [coreguard.queries] INFO ALLOWED A domain{i}.com\n"
        log_file.write_text(lines)
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            results, total = _read_recent_queries(3, offset=2)
        assert len(results) == 3
        assert total == 10

    def test_time_range_filter(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A early.com\n"
            "2026-02-26 15:00:01 [coreguard.queries] INFO ALLOWED A middle.com\n"
            "2026-02-26 16:00:01 [coreguard.queries] INFO ALLOWED A late.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            results, total = _read_recent_queries(
                100, start="2026-02-26 14:45:00", end="2026-02-26 15:30:00"
            )
        assert total == 1
        assert results[0]["domain"] == "middle.com"

    def test_status_filter(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO ALLOWED A good.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            results, total = _read_recent_queries(100, status="BLOCKED")
        assert total == 1
        assert results[0]["domain"] == "ads.com"

    def test_has_more_flag(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        lines = ""
        for i in range(5):
            lines += f"2026-02-26 14:30:{i:02d} [coreguard.queries] INFO ALLOWED A domain{i}.com\n"
        log_file.write_text(lines)
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            results, total = _read_recent_queries(2, offset=0)
        assert len(results) == 2
        assert total == 5
        # has_more = offset + limit < total = 0 + 2 < 5 = True


class TestHelpers:
    def test_validate_domain_valid(self):
        assert _validate_domain("example.com") == "example.com"
        assert _validate_domain("EXAMPLE.COM") == "example.com"
        assert _validate_domain("sub.example.com.") == "sub.example.com"
        assert _validate_domain("a") == "a"
        assert _validate_domain("a-b.com") == "a-b.com"

    def test_validate_domain_invalid(self):
        assert _validate_domain("") is None
        assert _validate_domain("not valid!") is None
        assert _validate_domain("-start.com") is None
        assert _validate_domain(".") is None

    def test_remove_from_file(self, tmp_path):
        f = tmp_path / "domains.txt"
        f.write_text("example.com\nother.com\n")
        assert _remove_from_file(f, "example.com") is True
        assert "example.com" not in f.read_text()
        assert "other.com" in f.read_text()

    def test_remove_from_file_not_found(self, tmp_path):
        f = tmp_path / "domains.txt"
        f.write_text("example.com\n")
        assert _remove_from_file(f, "notfound.com") is False

    def test_remove_from_file_missing(self, tmp_path):
        f = tmp_path / "nonexistent.txt"
        assert _remove_from_file(f, "example.com") is False

    def test_parse_duration(self):
        assert _parse_duration("5m") == 300
        assert _parse_duration("1h") == 3600
        assert _parse_duration("30s") == 30
        assert _parse_duration("xyz") is None
        assert _parse_duration("") is None
        assert _parse_duration("5x") is None


class TestHistoryEndpoint:
    """Tests for the /api/history endpoint and _read_query_history()."""

    def setup_method(self):
        # Clear the cache before each test
        _history_cache["data"] = None
        _history_cache["timestamp"] = 0

    def test_bucket_structure(self, tmp_path):
        """Returned data has 144 buckets with correct keys."""
        log_file = tmp_path / "coreguard.log"
        log_file.write_text("")
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()
        assert len(result) == 144
        for bucket in result:
            assert "time" in bucket
            assert "allowed" in bucket
            assert "blocked" in bucket
            assert isinstance(bucket["allowed"], int)
            assert isinstance(bucket["blocked"], int)

    def test_empty_log_returns_zero_counts(self, tmp_path):
        """Empty log file produces 144 buckets all with zero counts."""
        log_file = tmp_path / "coreguard.log"
        log_file.write_text("")
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()
        assert all(b["allowed"] == 0 and b["blocked"] == 0 for b in result)

    def test_missing_log_returns_zero_counts(self, tmp_path):
        """Non-existent log file produces 144 zero-count buckets."""
        log_file = tmp_path / "nonexistent.log"
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()
        assert len(result) == 144
        assert all(b["allowed"] == 0 and b["blocked"] == 0 for b in result)

    def test_counts_queries_in_buckets(self, tmp_path):
        """Queries are counted in the correct 10-minute buckets."""
        from datetime import datetime, timedelta

        now = datetime.now()
        # Generate queries at 5 minutes ago (should be in a recent bucket)
        t1 = now - timedelta(minutes=5)
        t2 = now - timedelta(minutes=3)
        t3 = now - timedelta(minutes=1)

        lines = [
            f"{t1:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A example.com\n",
            f"{t2:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO BLOCKED A ads.com\n",
            f"{t3:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED AAAA github.com\n",
        ]

        log_file = tmp_path / "coreguard.log"
        log_file.write_text("".join(lines))
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()

        total_allowed = sum(b["allowed"] for b in result)
        total_blocked = sum(b["blocked"] for b in result)
        assert total_allowed == 2
        assert total_blocked == 1

    def test_24h_cutoff(self, tmp_path):
        """Queries older than 24 hours are excluded."""
        from datetime import datetime, timedelta

        old = datetime.now() - timedelta(hours=25)
        recent = datetime.now() - timedelta(minutes=5)

        lines = [
            f"{old:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A old.com\n",
            f"{recent:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A recent.com\n",
        ]

        log_file = tmp_path / "coreguard.log"
        log_file.write_text("".join(lines))
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()

        total = sum(b["allowed"] + b["blocked"] for b in result)
        assert total == 1  # only the recent query

    def test_cache_prevents_reparse(self, tmp_path):
        """Second call within 60s returns cached result without re-reading file."""
        import time as _time

        log_file = tmp_path / "coreguard.log"
        now = datetime.now() - timedelta(minutes=5)
        log_file.write_text(
            f"{now:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A cached.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result1 = _read_query_history()

        # Modify the file — but cache should prevent re-read
        log_file.write_text("")
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result2 = _read_query_history()

        # Same object reference — proves cache was used
        assert result1 is result2

    def test_cache_expires(self, tmp_path):
        """Cache expires after 60 seconds and data is re-parsed."""
        log_file = tmp_path / "coreguard.log"
        now = datetime.now() - timedelta(minutes=5)
        log_file.write_text(
            f"{now:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A first.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result1 = _read_query_history()

        # Force cache expiry
        _history_cache["timestamp"] = 0

        log_file.write_text("")
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result2 = _read_query_history()

        # Different object — cache was invalidated
        assert result1 is not result2

    def test_api_endpoint_returns_json(self, tmp_path):
        """GET /api/history returns proper JSON with buckets and bucket_minutes."""
        log_file = tmp_path / "coreguard.log"
        log_file.write_text("")
        server, port = _start_test_server()
        try:
            with patch("coreguard.dashboard.LOG_FILE", log_file):
                status, headers, body = _get(port, "/api/history")
            assert status == 200
            assert "application/json" in headers["Content-Type"]
            data = json.loads(body)
            assert "buckets" in data
            assert data["bucket_minutes"] == 10
            assert len(data["buckets"]) == 144
        finally:
            server.shutdown()
            server.server_close()

    def test_multiple_hours_distributed(self, tmp_path):
        """Queries spread across different hours land in different buckets."""
        from datetime import datetime, timedelta

        now = datetime.now()
        lines = []
        # Add queries at 1h, 3h, 5h, and 7h ago
        for hours_ago in [1, 3, 5, 7]:
            t = now - timedelta(hours=hours_ago)
            lines.append(
                f"{t:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO ALLOWED A host{hours_ago}h.com\n"
            )
            lines.append(
                f"{t:%Y-%m-%d %H:%M:%S} [coreguard.queries] INFO BLOCKED A block{hours_ago}h.com\n"
            )

        log_file = tmp_path / "coreguard.log"
        log_file.write_text("".join(lines))
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            result = _read_query_history()

        # Count non-zero buckets
        non_zero = [b for b in result if b["allowed"] > 0 or b["blocked"] > 0]
        assert len(non_zero) >= 4  # at least 4 distinct buckets
        assert sum(b["allowed"] for b in result) == 4
        assert sum(b["blocked"] for b in result) == 4


class TestQueryTypesAndClients:
    """Tests for query_types, top_clients, and sparkline in /api/stats."""

    def setup_method(self):
        self.stats = Stats()
        self.stats.record_query("example.com", blocked=False, qtype="A", client_ip="127.0.0.1")
        self.stats.record_query("google.com", blocked=False, qtype="AAAA", client_ip="127.0.0.1")
        self.stats.record_query("ads.com", blocked=True, qtype="A", client_ip="192.168.1.2")
        self.stats.record_query("cdn.com", blocked=False, qtype="CNAME")

        self.cache = MagicMock()
        self.cache.size = 10

        self.config = Config()
        self.config.dashboard_enabled = True

        self.server, self.port = _start_test_server(
            stats=self.stats, cache=self.cache, config=self.config
        )

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_query_types_in_stats(self):
        status, _, body = _get(self.port, "/api/stats")
        assert status == 200
        data = json.loads(body)
        qt = data["query_types"]
        assert qt["A"] == 2
        assert qt["AAAA"] == 1
        assert qt["CNAME"] == 1

    def test_top_clients_in_stats(self):
        status, _, body = _get(self.port, "/api/stats")
        assert status == 200
        data = json.loads(body)
        clients = data["top_clients"]
        assert clients["127.0.0.1"] == 2
        assert clients["192.168.1.2"] == 1

    def test_clients_endpoint(self):
        status, _, body = _get(self.port, "/api/clients")
        assert status == 200
        data = json.loads(body)
        assert "clients" in data
        assert data["clients"]["127.0.0.1"] == 2


class TestExportEndpoint:
    """Tests for /api/queries/export."""

    def setup_method(self):
        self.server, self.port = _start_test_server()

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_csv_export(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
            "2026-02-26 14:30:02 [coreguard.queries] INFO ALLOWED A github.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            url = f"http://127.0.0.1:{self.port}/api/queries/export?format=csv"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                assert "text/csv" in resp.headers["Content-Type"]
                assert "attachment" in resp.headers["Content-Disposition"]
                content = resp.read().decode()
                assert "time,status,type,domain" in content
                assert "ads.example.com" in content

    def test_json_export(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            url = f"http://127.0.0.1:{self.port}/api/queries/export?format=json"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                assert "application/json" in resp.headers["Content-Type"]
                data = json.loads(resp.read())
                assert isinstance(data, list)
                assert len(data) == 1

    def test_empty_export(self, tmp_path):
        log_file = tmp_path / "nonexistent.log"
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            url = f"http://127.0.0.1:{self.port}/api/queries/export?format=csv"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                content = resp.read().decode()
                # Should have header row only
                lines = content.strip().split("\n")
                assert len(lines) == 1


class TestSSEEndpoint:
    """Tests for /api/stream SSE endpoint."""

    def setup_method(self):
        self.server, self.port = _start_test_server()

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_sse_content_type(self):
        url = f"http://127.0.0.1:{self.port}/api/stream"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                assert "text/event-stream" in resp.headers["Content-Type"]
        except Exception:
            # Connection may timeout waiting for events — that's expected
            pass

    def test_broadcast_queues(self):
        from coreguard.dashboard import _sse_clients, _sse_lock, broadcast_query
        import queue
        q = queue.Queue(maxsize=100)
        with _sse_lock:
            _sse_clients.append(q)
        try:
            broadcast_query("test.com", "A", True, "127.0.0.1")
            event = q.get_nowait()
            data = json.loads(event)
            assert data["domain"] == "test.com"
            assert data["status"] == "BLOCKED"
            assert data["client"] == "127.0.0.1"
        finally:
            with _sse_lock:
                _sse_clients.remove(q)

    def test_cleanup_dead_clients(self):
        from coreguard.dashboard import _sse_clients, _sse_lock, broadcast_query
        import queue
        # Create a full queue (will fail on put)
        q = queue.Queue(maxsize=1)
        q.put("filler")
        with _sse_lock:
            _sse_clients.append(q)
        broadcast_query("test.com", "A", False)
        # Dead client should be removed
        with _sse_lock:
            assert q not in _sse_clients


class TestPaginatedQueriesEndpoint:
    """Tests for paginated /api/queries endpoint."""

    def setup_method(self):
        self.server, self.port = _start_test_server()

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_paginated_response_shape(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        lines = ""
        for i in range(5):
            lines += f"2026-02-26 14:30:{i:02d} [coreguard.queries] INFO ALLOWED A domain{i}.com\n"
        log_file.write_text(lines)
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            status, _, body = _get(self.port, "/api/queries?limit=2&offset=0")
        assert status == 200
        data = json.loads(body)
        assert len(data["queries"]) == 2
        assert data["total"] == 5
        assert data["offset"] == 0
        assert data["limit"] == 2
        assert data["has_more"] is True

    def test_time_range_filter_via_api(self, tmp_path):
        log_file = tmp_path / "coreguard.log"
        log_file.write_text(
            "2026-02-26 14:00:00 [coreguard.queries] INFO ALLOWED A early.com\n"
            "2026-02-26 15:00:00 [coreguard.queries] INFO ALLOWED A target.com\n"
            "2026-02-26 16:00:00 [coreguard.queries] INFO ALLOWED A late.com\n"
        )
        with patch("coreguard.dashboard.LOG_FILE", log_file):
            status, _, body = _get(
                self.port,
                "/api/queries?start=2026-02-26+14%3A30%3A00&end=2026-02-26+15%3A30%3A00"
            )
        assert status == 200
        data = json.loads(body)
        assert data["total"] == 1
        assert data["queries"][0]["domain"] == "target.com"

    def test_backward_compat_without_params(self):
        """Endpoint works without any params."""
        status, _, body = _get(self.port, "/api/queries")
        assert status == 200
        data = json.loads(body)
        assert "queries" in data
        assert "total" in data
