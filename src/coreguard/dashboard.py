import hmac
import json
import logging
import os
import re
import signal
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from coreguard.config import (
    CUSTOM_ALLOW_FILE,
    CUSTOM_BLOCK_FILE,
    LOG_FILE,
    TEMP_ALLOW_FILE,
    Config,
    load_config,
    save_config,
)
from coreguard.stats import Stats

logger = logging.getLogger("coreguard.dashboard")

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def _validate_domain(domain: str) -> str | None:
    """Normalize and validate a domain. Returns normalized domain or None."""
    domain = domain.lower().strip(".")
    if not domain or not _DOMAIN_RE.match(domain):
        return None
    return domain


def _remove_from_file(path: Path, domain: str) -> bool:
    """Remove a domain from a text file. Returns True if found and removed."""
    if not path.exists():
        return False
    lines = path.read_text().splitlines()
    filtered = [l for l in lines if l.strip().lower().strip(".") != domain]
    if len(filtered) < len(lines):
        path.write_text("\n".join(filtered) + "\n" if filtered else "")
        return True
    return False


def _parse_duration(s: str) -> int | None:
    """Parse a duration string like '5m', '1h', '30s' into seconds. Returns None on failure."""
    match = re.fullmatch(r"(\d+)([smh])", s)
    if not match:
        return None
    return int(match.group(1)) * _DURATION_UNITS[match.group(2)]


def _send_self_sighup() -> None:
    """Send SIGHUP to the current process to trigger filter reload."""
    try:
        os.kill(os.getpid(), signal.SIGHUP)
    except OSError:
        pass


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the coreguard dashboard."""

    stats: Stats = None
    cache = None
    config: Config = None
    token: str = ""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._serve_html()
        elif path == "/api/stats":
            self._serve_stats()
        elif path == "/api/queries":
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", ["100"])[0])
            self._serve_queries(limit)
        elif path == "/api/config":
            self._serve_config()
        elif path == "/api/domains":
            self._serve_domains()
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        routes = {
            "/api/auth/verify": self._handle_auth_verify,
            "/api/domains/allow": self._handle_domains_allow,
            "/api/domains/block": self._handle_domains_block,
            "/api/domains/unblock": self._handle_domains_unblock,
            "/api/lists/toggle": self._handle_lists_toggle,
            "/api/lists/add": self._handle_lists_add,
            "/api/lists/remove": self._handle_lists_remove,
            "/api/update": self._handle_update,
            "/api/cache/clear": self._handle_cache_clear,
            "/api/daemon/stop": self._handle_daemon_stop,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self.send_error(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        routes = {
            "/api/domains/allow": self._handle_delete_allow,
            "/api/domains/block": self._handle_delete_block,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    # --- Auth ---

    def _check_auth(self) -> bool:
        """Verify Bearer token. Sends 401 and returns False if invalid."""
        if not self.token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth[7:]
            if hmac.compare_digest(provided, self.token):
                return True
        self._json_response({"error": "Unauthorized"}, status=401)
        return False

    def _read_json_body(self) -> dict | None:
        """Read and parse JSON request body. Returns None and sends 400 on failure."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._json_response({"error": "Invalid JSON body"}, status=400)
            return None

    # --- JSON response ---

    def _json_response(self, data: dict | list, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    # --- GET handlers ---

    def _serve_stats(self) -> None:
        data = self.stats.to_dict() if self.stats else {}
        if self.cache:
            data["cache_size"] = self.cache.size
        self._json_response(data)

    def _serve_queries(self, limit: int = 100) -> None:
        limit = min(max(limit, 1), 500)
        queries = _read_recent_queries(limit)
        self._json_response(queries)

    def _serve_config(self) -> None:
        cfg = self.config
        if not cfg:
            self._json_response({})
            return
        data = {
            "upstream_mode": cfg.upstream_mode,
            "providers": [p.name for p in cfg.upstream_providers],
            "listen": f"{cfg.listen_address}:{cfg.listen_port}",
            "cache_enabled": cfg.cache_enabled,
            "cache_max_entries": cfg.cache_max_entries,
            "cache_max_ttl": cfg.cache_max_ttl,
            "cname_check_enabled": cfg.cname_check_enabled,
            "dashboard_port": cfg.dashboard_port,
            "filter_lists": [
                {"name": f["name"], "enabled": f.get("enabled", True)}
                for f in cfg.filter_lists
            ],
        }
        self._json_response(data)

    def _serve_domains(self) -> None:
        allowlist = []
        if CUSTOM_ALLOW_FILE.exists():
            allowlist = [
                line.strip()
                for line in CUSTOM_ALLOW_FILE.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

        blocklist = []
        if CUSTOM_BLOCK_FILE.exists():
            blocklist = [
                line.strip()
                for line in CUSTOM_BLOCK_FILE.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

        temp_allowlist = []
        if TEMP_ALLOW_FILE.exists():
            try:
                data = json.loads(TEMP_ALLOW_FILE.read_text())
                now = time.time()
                for domain, expires in data.items():
                    if expires > now:
                        temp_allowlist.append({
                            "domain": domain,
                            "expires": expires,
                            "expires_human": time.strftime(
                                "%H:%M:%S", time.localtime(expires)
                            ),
                        })
            except (json.JSONDecodeError, OSError):
                pass

        self._json_response({
            "allowlist": allowlist,
            "blocklist": blocklist,
            "temp_allowlist": temp_allowlist,
        })

    def _serve_html(self) -> None:
        body = DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- POST handlers ---

    def _handle_auth_verify(self) -> None:
        if not self._check_auth():
            return
        self._json_response({"status": "ok"})

    def _handle_domains_allow(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        domain = _validate_domain(body.get("domain", ""))
        if not domain:
            self._json_response({"error": "Invalid domain"}, status=400)
            return
        with open(CUSTOM_ALLOW_FILE, "a") as f:
            f.write(domain + "\n")
        _send_self_sighup()
        self._json_response({"status": "ok", "domain": domain})

    def _handle_domains_block(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        domain = _validate_domain(body.get("domain", ""))
        if not domain:
            self._json_response({"error": "Invalid domain"}, status=400)
            return
        with open(CUSTOM_BLOCK_FILE, "a") as f:
            f.write(domain + "\n")
        _send_self_sighup()
        self._json_response({"status": "ok", "domain": domain})

    def _handle_domains_unblock(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        domain = _validate_domain(body.get("domain", ""))
        if not domain:
            self._json_response({"error": "Invalid domain"}, status=400)
            return

        duration = body.get("duration")
        if duration:
            seconds = _parse_duration(duration)
            if seconds is None:
                self._json_response(
                    {"error": f"Invalid duration '{duration}'. Use e.g. 5m, 1h, 30s."},
                    status=400,
                )
                return
            # Temp unblock
            data = {}
            if TEMP_ALLOW_FILE.exists():
                try:
                    data = json.loads(TEMP_ALLOW_FILE.read_text())
                except (json.JSONDecodeError, OSError):
                    data = {}
            data[domain] = time.time() + seconds
            TEMP_ALLOW_FILE.write_text(json.dumps(data))
        else:
            # Permanent unblock: remove from block file, add to allow file
            _remove_from_file(CUSTOM_BLOCK_FILE, domain)
            existing = set()
            if CUSTOM_ALLOW_FILE.exists():
                existing = {
                    line.strip().lower().strip(".")
                    for line in CUSTOM_ALLOW_FILE.read_text().splitlines()
                    if line.strip() and not line.strip().startswith("#")
                }
            if domain not in existing:
                with open(CUSTOM_ALLOW_FILE, "a") as f:
                    f.write(domain + "\n")

        _send_self_sighup()
        self._json_response({"status": "ok", "domain": domain})

    def _handle_delete_allow(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        domain = _validate_domain(body.get("domain", ""))
        if not domain:
            self._json_response({"error": "Invalid domain"}, status=400)
            return
        removed = _remove_from_file(CUSTOM_ALLOW_FILE, domain)
        if not removed:
            self._json_response({"error": "Domain not found in allowlist"}, status=404)
            return
        _send_self_sighup()
        self._json_response({"status": "ok", "domain": domain})

    def _handle_delete_block(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        domain = _validate_domain(body.get("domain", ""))
        if not domain:
            self._json_response({"error": "Invalid domain"}, status=400)
            return
        removed = _remove_from_file(CUSTOM_BLOCK_FILE, domain)
        if not removed:
            self._json_response(
                {"error": "Domain not found in blocklist"}, status=404
            )
            return
        _send_self_sighup()
        self._json_response({"status": "ok", "domain": domain})

    # --- Lists handlers ---

    def _handle_lists_toggle(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        name = body.get("name", "")
        enabled = body.get("enabled")
        if not name or enabled is None:
            self._json_response(
                {"error": "Missing 'name' or 'enabled' field"}, status=400
            )
            return

        cfg = load_config()
        found = False
        for flist in cfg.filter_lists:
            if flist["name"] == name:
                flist["enabled"] = bool(enabled)
                found = True
                break
        if not found:
            self._json_response({"error": f"List '{name}' not found"}, status=404)
            return

        save_config(cfg)
        DashboardHandler.config = cfg
        self._json_response({"status": "ok", "name": name, "enabled": bool(enabled)})

    def _handle_lists_add(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        url = body.get("url", "").strip()
        name = body.get("name", "").strip()
        if not url or not name:
            self._json_response(
                {"error": "Missing 'url' or 'name' field"}, status=400
            )
            return

        cfg = load_config()
        for flist in cfg.filter_lists:
            if flist["url"] == url:
                self._json_response(
                    {"error": f"List with URL already exists: {flist['name']}"},
                    status=409,
                )
                return

        cfg.filter_lists.append({"name": name, "url": url, "enabled": True})
        save_config(cfg)
        DashboardHandler.config = cfg
        self._json_response({"status": "ok", "name": name, "url": url})

    def _handle_lists_remove(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        name = body.get("name", "")
        if not name:
            self._json_response({"error": "Missing 'name' field"}, status=400)
            return

        cfg = load_config()
        original_count = len(cfg.filter_lists)
        cfg.filter_lists = [f for f in cfg.filter_lists if f["name"] != name]

        if len(cfg.filter_lists) == original_count:
            self._json_response({"error": f"List '{name}' not found"}, status=404)
            return

        save_config(cfg)
        DashboardHandler.config = cfg
        self._json_response({"status": "ok", "name": name})

    # --- System handlers ---

    def _handle_update(self) -> None:
        if not self._check_auth():
            return
        _send_self_sighup()
        self._json_response({"status": "ok", "message": "Update triggered"})

    def _handle_cache_clear(self) -> None:
        if not self._check_auth():
            return
        if self.cache:
            self.cache.clear()
        self._json_response({"status": "ok", "message": "Cache cleared"})

    def _handle_daemon_stop(self) -> None:
        if not self._check_auth():
            return
        self._json_response({"status": "ok", "message": "Daemon stopping"})

        def _delayed_stop():
            time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGTERM)

        threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()

    def log_message(self, format, *args):
        # Suppress default stderr logging from http.server
        pass


def _read_recent_queries(limit: int) -> list[dict]:
    """Read and parse the last N query log entries."""
    if not LOG_FILE.exists():
        return []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except OSError:
        return []

    # Query log lines look like:
    # 2026-02-26 14:30:01 [coreguard.queries] INFO BLOCKED A ads.example.com
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(BLOCKED|ALLOWED)\s+(\S+)\s+(\S+)"
    )
    results = []
    for line in reversed(lines):
        m = pattern.match(line.strip())
        if m:
            results.append({
                "time": m.group(1),
                "status": m.group(2),
                "type": m.group(3),
                "domain": m.group(4),
            })
            if len(results) >= limit:
                break
    return results


def start_dashboard(config: Config, stats: Stats, cache=None) -> HTTPServer | None:
    """Start the dashboard web server in a background thread.

    Returns the server instance, or None if the dashboard is disabled.
    """
    if not config.dashboard_enabled:
        return None

    # Auto-generate token if empty
    if not config.dashboard_token:
        config.dashboard_token = uuid.uuid4().hex
        save_config(config)
        logger.info("Generated new dashboard token")

    DashboardHandler.stats = stats
    DashboardHandler.cache = cache
    DashboardHandler.config = config
    DashboardHandler.token = config.dashboard_token

    try:
        server = HTTPServer(("127.0.0.1", config.dashboard_port), DashboardHandler)
    except OSError as e:
        logger.warning("Could not start dashboard on port %d: %s", config.dashboard_port, e)
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Dashboard available at http://127.0.0.1:%d", config.dashboard_port)
    return server


DASHBOARD_HTML = ""  # Replaced below

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Coreguard Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9; max-width: 1200px; margin: 0 auto; padding: 0;
  }
  code, .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }

  /* --- Header --- */
  .header { padding: 20px 24px 0; display: flex; align-items: center; justify-content: space-between; }
  .header h1 { color: #58a6ff; font-size: 22px; }
  .header .subtitle { color: #8b949e; font-size: 13px; }

  /* --- Tabs --- */
  .tabs { display: flex; gap: 0; padding: 16px 24px 0; border-bottom: 1px solid #30363d; }
  .tab {
    padding: 8px 16px; cursor: pointer; color: #8b949e; font-size: 14px;
    border-bottom: 2px solid transparent; transition: color 0.2s;
  }
  .tab:hover { color: #c9d1d9; }
  .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }

  .tab-content { display: none; padding: 24px; }
  .tab-content.active { display: block; }

  /* --- Cards --- */
  .cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px; margin-bottom: 24px;
  }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px;
  }
  .card .label { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 26px; font-weight: 600; color: #f0f6fc; margin-top: 4px; }
  .card .value.green { color: #3fb950; }
  .card .value.red { color: #f85149; }
  .card .value.blue { color: #58a6ff; }

  /* --- Tables --- */
  .tables { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 700px) { .tables { grid-template-columns: 1fr; } }
  .section { margin-bottom: 24px; }
  .section h2 {
    font-size: 14px; color: #8b949e; margin-bottom: 8px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  table {
    width: 100%; border-collapse: collapse; background: #161b22;
    border: 1px solid #30363d; border-radius: 8px; overflow: hidden;
  }
  th {
    text-align: left; padding: 8px 12px; color: #8b949e;
    font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #30363d;
  }
  td { padding: 6px 12px; font-size: 13px; border-bottom: 1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600;
  }
  .badge.blocked { background: #f8514922; color: #f85149; }
  .badge.allowed { background: #3fb95022; color: #3fb950; }
  .domain {
    max-width: 400px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px;
  }
  .scroll-table {
    max-height: 500px; overflow-y: auto; background: #161b22;
    border: 1px solid #30363d; border-radius: 8px;
  }
  .scroll-table table { border: none; }

  /* --- Forms --- */
  .inline-form { display: flex; gap: 8px; margin-bottom: 12px; }
  input[type="text"], input[type="password"] {
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 6px 12px; color: #c9d1d9; font-size: 13px; flex: 1;
    font-family: "SF Mono", Menlo, Consolas, monospace;
  }
  input[type="text"]:focus, input[type="password"]:focus {
    outline: none; border-color: #58a6ff;
  }
  .search-input {
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 6px 12px; color: #c9d1d9; font-size: 13px; width: 250px;
  }
  .search-input:focus { outline: none; border-color: #58a6ff; }
  select {
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 6px 12px; color: #c9d1d9; font-size: 13px;
  }
  select:focus { outline: none; border-color: #58a6ff; }

  /* --- Buttons --- */
  .btn {
    padding: 6px 14px; border-radius: 6px; border: 1px solid #30363d;
    background: #21262d; color: #c9d1d9; font-size: 13px; cursor: pointer;
    transition: background 0.15s;
  }
  .btn:hover { background: #30363d; }
  .btn-primary { background: #238636; border-color: #2ea043; color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-danger { background: #da3633; border-color: #f85149; color: #fff; }
  .btn-danger:hover { background: #f85149; }
  .btn-sm { padding: 3px 8px; font-size: 12px; }

  /* --- Toggle switch --- */
  .toggle { position: relative; display: inline-block; width: 36px; height: 20px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle .slider {
    position: absolute; cursor: pointer; inset: 0; background: #30363d;
    border-radius: 20px; transition: background 0.2s;
  }
  .toggle .slider::before {
    content: ""; position: absolute; height: 14px; width: 14px; left: 3px; bottom: 3px;
    background: #8b949e; border-radius: 50%; transition: transform 0.2s, background 0.2s;
  }
  .toggle input:checked + .slider { background: #238636; }
  .toggle input:checked + .slider::before { transform: translateX(16px); background: #fff; }

  /* --- Domain list --- */
  .domain-list {
    max-height: 300px; overflow-y: auto; background: #161b22;
    border: 1px solid #30363d; border-radius: 8px;
  }
  .domain-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 6px 12px; border-bottom: 1px solid #21262d; font-size: 13px;
  }
  .domain-item:last-child { border-bottom: none; }
  .domain-item .name { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }
  .domain-item .meta { color: #8b949e; font-size: 11px; }
  .count-badge {
    display: inline-block; background: #30363d; color: #8b949e; padding: 1px 8px;
    border-radius: 10px; font-size: 11px; margin-left: 6px; font-weight: 600;
  }
  .empty-state { padding: 24px; text-align: center; color: #484f58; font-size: 13px; }

  /* --- Config card --- */
  .config-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px; margin-bottom: 16px;
  }
  .config-row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
  .config-row .key { color: #8b949e; }
  .config-row .val { color: #c9d1d9; font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }

  /* --- Login overlay --- */
  .login-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.8);
    display: flex; align-items: center; justify-content: center; z-index: 1000;
  }
  .login-overlay.hidden { display: none; }
  .login-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 32px; width: 380px; text-align: center;
  }
  .login-card h2 { color: #58a6ff; margin-bottom: 8px; font-size: 20px; }
  .login-card p { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
  .login-card input {
    width: 100%; margin-bottom: 12px; padding: 10px 12px; font-size: 14px;
  }
  .login-card .btn { width: 100%; padding: 10px; font-size: 14px; }
  .login-error { color: #f85149; font-size: 12px; margin-bottom: 8px; display: none; }

  /* --- Toast --- */
  .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 2000; }
  .toast {
    padding: 10px 16px; border-radius: 8px; color: #fff; font-size: 13px;
    margin-top: 8px; animation: fadeIn 0.2s; min-width: 200px;
  }
  .toast.success { background: #238636; }
  .toast.error { background: #da3633; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

  .actions { display: flex; gap: 8px; margin-top: 16px; }
  .refresh-note { color: #484f58; font-size: 11px; text-align: right; margin-bottom: 8px; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }
</style>
</head>
<body>

<!-- Login overlay -->
<div class="login-overlay hidden" id="login-overlay">
  <div class="login-card">
    <h2>Coreguard</h2>
    <p>Enter your dashboard token to manage settings</p>
    <div class="login-error" id="login-error">Invalid token</div>
    <input type="password" id="login-token" placeholder="Dashboard token" class="mono">
    <button class="btn btn-primary" onclick="doLogin()">Login</button>
  </div>
</div>

<!-- Toast container -->
<div class="toast-container" id="toasts"></div>

<div class="header">
  <div><h1>Coreguard</h1><span class="subtitle">DNS Ad &amp; Tracker Blocking</span></div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="overview">Overview</div>
  <div class="tab" data-tab="queries">Queries</div>
  <div class="tab" data-tab="domains">Domains</div>
  <div class="tab" data-tab="lists">Lists</div>
  <div class="tab" data-tab="settings">Settings</div>
</div>

<!-- Tab 1: Overview -->
<div class="tab-content active" id="tab-overview">
  <div class="cards">
    <div class="card"><div class="label">Total Queries</div><div class="value" id="total">-</div></div>
    <div class="card"><div class="label">Blocked</div><div class="value red" id="blocked">-</div></div>
    <div class="card"><div class="label">Block Rate</div><div class="value red" id="block-rate">-</div></div>
    <div class="card"><div class="label">Cache Hit Rate</div><div class="value green" id="cache-rate">-</div></div>
    <div class="card"><div class="label">Cache Size</div><div class="value blue" id="cache-size">-</div></div>
    <div class="card"><div class="label">CNAME Blocks</div><div class="value" id="cname">-</div></div>
  </div>
  <div class="tables">
    <div class="section">
      <h2>Top Blocked Domains</h2>
      <table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody id="top-blocked"></tbody></table>
    </div>
    <div class="section">
      <h2>Top Queried Domains</h2>
      <table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody id="top-queried"></tbody></table>
    </div>
  </div>
  <div class="refresh-note">Auto-refreshes every 5 seconds</div>
</div>

<!-- Tab 2: Queries -->
<div class="tab-content" id="tab-queries">
  <div class="filter-bar">
    <input type="text" class="search-input" id="query-search" placeholder="Filter domains...">
    <select id="query-status-filter">
      <option value="all">All</option>
      <option value="BLOCKED">Blocked</option>
      <option value="ALLOWED">Allowed</option>
    </select>
  </div>
  <div class="scroll-table">
    <table><thead><tr><th>Time</th><th>Status</th><th>Type</th><th>Domain</th></tr></thead><tbody id="queries"></tbody></table>
  </div>
  <div class="refresh-note">Auto-refreshes every 5 seconds</div>
</div>

<!-- Tab 3: Domains -->
<div class="tab-content" id="tab-domains">
  <div class="section">
    <h2>Allowlist <span class="count-badge" id="allow-count">0</span></h2>
    <div class="inline-form">
      <input type="text" id="allow-input" placeholder="example.com">
      <button class="btn btn-primary btn-sm" onclick="addDomain('allow')">Add</button>
    </div>
    <div class="domain-list" id="allow-list"></div>
  </div>
  <div class="section">
    <h2>Blocklist <span class="count-badge" id="block-count">0</span></h2>
    <div class="inline-form">
      <input type="text" id="block-input" placeholder="ads.example.com">
      <button class="btn btn-primary btn-sm" onclick="addDomain('block')">Add</button>
    </div>
    <div class="domain-list" id="block-list"></div>
  </div>
  <div class="section">
    <h2>Temporary Allows <span class="count-badge" id="temp-count">0</span></h2>
    <div class="inline-form">
      <input type="text" id="unblock-input" placeholder="example.com">
      <input type="text" id="unblock-duration" placeholder="5m" style="max-width:80px">
      <button class="btn btn-primary btn-sm" onclick="tempUnblock()">Temp Allow</button>
    </div>
    <div class="domain-list" id="temp-list"></div>
  </div>
</div>

<!-- Tab 4: Lists -->
<div class="tab-content" id="tab-lists">
  <div class="section">
    <h2>Filter Lists</h2>
    <div class="scroll-table">
      <table><thead><tr><th>Name</th><th>Enabled</th><th></th></tr></thead><tbody id="lists-table"></tbody></table>
    </div>
  </div>
  <div class="section">
    <h2>Add Filter List</h2>
    <div class="inline-form">
      <input type="text" id="list-url" placeholder="https://example.com/hosts.txt" style="flex:2">
      <input type="text" id="list-name" placeholder="Name">
      <button class="btn btn-primary btn-sm" onclick="addList()">Add</button>
    </div>
  </div>
  <div class="actions">
    <button class="btn" onclick="triggerUpdate()">Update All Lists</button>
  </div>
</div>

<!-- Tab 5: Settings -->
<div class="tab-content" id="tab-settings">
  <div class="section">
    <h2>Configuration</h2>
    <div class="config-card" id="config-card"></div>
  </div>
  <div class="section">
    <h2>Dashboard Token</h2>
    <div class="inline-form">
      <input type="text" id="token-display" readonly style="color:#8b949e">
      <button class="btn btn-sm" onclick="copyToken()">Copy</button>
    </div>
  </div>
  <div class="section">
    <h2>Actions</h2>
    <div class="actions">
      <button class="btn" onclick="clearCache()">Clear DNS Cache</button>
      <button class="btn btn-danger" onclick="stopDaemon()">Stop Daemon</button>
      <button class="btn" onclick="doLogout()">Logout</button>
    </div>
  </div>
</div>

<script>
// --- State ---
let token = localStorage.getItem('cg_token') || '';
let queriesData = [];

// --- Helpers ---
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}
function fmt(n) { return n != null ? n.toLocaleString() : '-'; }

function toast(msg, type) {
  const c = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'success');
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json();
  if (res.status === 401) {
    token = '';
    localStorage.removeItem('cg_token');
    showLogin();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// --- Login ---
function showLogin() { document.getElementById('login-overlay').classList.remove('hidden'); }
function hideLogin() { document.getElementById('login-overlay').classList.add('hidden'); }

async function doLogin() {
  const t = document.getElementById('login-token').value.trim();
  if (!t) return;
  token = t;
  try {
    await api('POST', '/api/auth/verify', {});
    localStorage.setItem('cg_token', token);
    hideLogin();
    document.getElementById('login-error').style.display = 'none';
  } catch (e) {
    token = '';
    document.getElementById('login-error').style.display = 'block';
  }
}

function doLogout() {
  token = '';
  localStorage.removeItem('cg_token');
  showLogin();
}

document.getElementById('login-token').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// --- Tabs ---
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// --- Overview ---
async function refreshOverview() {
  try {
    const [stats, queries] = await Promise.all([
      fetch('/api/stats').then(r => r.json()),
      fetch('/api/queries?limit=200').then(r => r.json())
    ]);
    queriesData = queries;

    document.getElementById('total').textContent = fmt(stats.total_queries);
    document.getElementById('blocked').textContent = fmt(stats.blocked_queries);
    document.getElementById('block-rate').textContent = (stats.blocked_percent || 0) + '%';
    document.getElementById('cache-rate').textContent = (stats.cache_hit_rate || 0) + '%';
    document.getElementById('cache-size').textContent = fmt(stats.cache_size || 0);
    document.getElementById('cname').textContent = fmt(stats.cname_blocks);

    document.getElementById('top-blocked').innerHTML = Object.entries(stats.top_blocked || {})
      .map(([d,c]) => '<tr><td class="domain">'+esc(d)+'</td><td>'+fmt(c)+'</td></tr>').join('');
    document.getElementById('top-queried').innerHTML = Object.entries(stats.top_queried || {})
      .map(([d,c]) => '<tr><td class="domain">'+esc(d)+'</td><td>'+fmt(c)+'</td></tr>').join('');

    renderQueries();
  } catch(e) { console.error('Refresh failed:', e); }
}

// --- Queries ---
function renderQueries() {
  const search = document.getElementById('query-search').value.toLowerCase();
  const statusFilter = document.getElementById('query-status-filter').value;
  const filtered = queriesData.filter(q => {
    if (search && !q.domain.toLowerCase().includes(search)) return false;
    if (statusFilter !== 'all' && q.status !== statusFilter) return false;
    return true;
  });
  document.getElementById('queries').innerHTML = filtered.map(q =>
    '<tr><td>'+esc(q.time)+'</td><td><span class="badge '+q.status.toLowerCase()+'">'+esc(q.status)+'</span></td><td>'+esc(q.type)+'</td><td class="domain">'+esc(q.domain)+'</td></tr>'
  ).join('');
}
document.getElementById('query-search').addEventListener('input', renderQueries);
document.getElementById('query-status-filter').addEventListener('change', renderQueries);

// --- Domains ---
async function refreshDomains() {
  try {
    const data = await fetch('/api/domains').then(r => r.json());
    const al = data.allowlist || [];
    const bl = data.blocklist || [];
    const tl = data.temp_allowlist || [];

    document.getElementById('allow-count').textContent = al.length;
    document.getElementById('block-count').textContent = bl.length;
    document.getElementById('temp-count').textContent = tl.length;

    document.getElementById('allow-list').innerHTML = al.length
      ? al.map(d => '<div class="domain-item"><span class="name">'+esc(d)+'</span><button class="btn btn-sm" onclick="removeDomain(&#39;allow&#39;,&#39;'+esc(d)+'&#39;)">Remove</button></div>').join('')
      : '<div class="empty-state">No custom allowed domains</div>';

    document.getElementById('block-list').innerHTML = bl.length
      ? bl.map(d => '<div class="domain-item"><span class="name">'+esc(d)+'</span><button class="btn btn-sm" onclick="removeDomain(&#39;block&#39;,&#39;'+esc(d)+'&#39;)">Remove</button></div>').join('')
      : '<div class="empty-state">No custom blocked domains</div>';

    const now = Date.now() / 1000;
    document.getElementById('temp-list').innerHTML = tl.length
      ? tl.map(t => {
          const rem = Math.max(0, Math.round(t.expires - now));
          const mins = Math.floor(rem / 60);
          const secs = rem % 60;
          return '<div class="domain-item"><span class="name">'+esc(t.domain)+'</span><span class="meta">expires in '+mins+'m '+secs+'s</span></div>';
        }).join('')
      : '<div class="empty-state">No temporary allows</div>';
  } catch(e) { console.error('Domains refresh failed:', e); }
}

async function addDomain(type) {
  const input = document.getElementById(type === 'allow' ? 'allow-input' : 'block-input');
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;
  try {
    await api('POST', '/api/domains/' + type, { domain });
    toast('Added ' + domain + ' to ' + type + 'list');
    input.value = '';
    refreshDomains();
  } catch(e) { toast(e.message, 'error'); }
}

async function removeDomain(type, domain) {
  try {
    await api('DELETE', '/api/domains/' + type, { domain });
    toast('Removed ' + domain + ' from ' + type + 'list');
    refreshDomains();
  } catch(e) { toast(e.message, 'error'); }
}

async function tempUnblock() {
  const domain = document.getElementById('unblock-input').value.trim().toLowerCase();
  const duration = document.getElementById('unblock-duration').value.trim() || '5m';
  if (!domain) return;
  try {
    await api('POST', '/api/domains/unblock', { domain, duration });
    toast('Temporarily allowed ' + domain + ' for ' + duration);
    document.getElementById('unblock-input').value = '';
    refreshDomains();
  } catch(e) { toast(e.message, 'error'); }
}

// --- Lists ---
async function refreshLists() {
  try {
    const data = await fetch('/api/config').then(r => r.json());
    const lists = data.filter_lists || [];
    document.getElementById('lists-table').innerHTML = lists.map(l =>
      '<tr><td>'+esc(l.name)+'</td><td><label class="toggle"><input type="checkbox" '+(l.enabled?'checked':'')+' onchange="toggleList(&#39;'+esc(l.name)+'&#39;,this.checked)"><span class="slider"></span></label></td><td><button class="btn btn-sm" onclick="removeList(&#39;'+esc(l.name)+'&#39;)">Remove</button></td></tr>'
    ).join('');
  } catch(e) { console.error('Lists refresh failed:', e); }
}

async function toggleList(name, enabled) {
  try {
    await api('POST', '/api/lists/toggle', { name, enabled });
    toast(name + ' ' + (enabled ? 'enabled' : 'disabled'));
  } catch(e) { toast(e.message, 'error'); refreshLists(); }
}

async function addList() {
  const url = document.getElementById('list-url').value.trim();
  const name = document.getElementById('list-name').value.trim();
  if (!url || !name) return;
  try {
    await api('POST', '/api/lists/add', { url, name });
    toast('Added list: ' + name);
    document.getElementById('list-url').value = '';
    document.getElementById('list-name').value = '';
    refreshLists();
  } catch(e) { toast(e.message, 'error'); }
}

async function removeList(name) {
  try {
    await api('POST', '/api/lists/remove', { name });
    toast('Removed list: ' + name);
    refreshLists();
  } catch(e) { toast(e.message, 'error'); }
}

async function triggerUpdate() {
  try {
    await api('POST', '/api/update', {});
    toast('Update triggered - filters will reload shortly');
  } catch(e) { toast(e.message, 'error'); }
}

// --- Settings ---
async function refreshSettings() {
  try {
    const data = await fetch('/api/config').then(r => r.json());
    const rows = [
      ['Upstream Mode', data.upstream_mode],
      ['Providers', (data.providers||[]).join(', ')],
      ['Listen Address', data.listen],
      ['Cache Enabled', data.cache_enabled ? 'Yes' : 'No'],
      ['Cache Max Entries', fmt(data.cache_max_entries)],
      ['Cache Max TTL', data.cache_max_ttl + 's'],
      ['CNAME Check', data.cname_check_enabled ? 'Yes' : 'No'],
      ['Dashboard Port', data.dashboard_port],
    ];
    document.getElementById('config-card').innerHTML = rows
      .map(([k,v]) => '<div class="config-row"><span class="key">'+esc(k)+'</span><span class="val">'+esc(String(v))+'</span></div>').join('');
    document.getElementById('token-display').value = token || '(not logged in)';
  } catch(e) { console.error('Settings refresh failed:', e); }
}

async function clearCache() {
  try {
    await api('POST', '/api/cache/clear', {});
    toast('DNS cache cleared');
  } catch(e) { toast(e.message, 'error'); }
}

async function stopDaemon() {
  if (!confirm('Are you sure you want to stop the coreguard daemon?')) return;
  try {
    await api('POST', '/api/daemon/stop', {});
    toast('Daemon stopping...');
  } catch(e) { toast(e.message, 'error'); }
}

function copyToken() {
  const el = document.getElementById('token-display');
  navigator.clipboard.writeText(el.value).then(() => toast('Token copied'));
}

// --- Init ---
async function init() {
  if (token) {
    try {
      await api('POST', '/api/auth/verify', {});
    } catch(e) { /* will show login if 401 */ }
  } else {
    showLogin();
  }
  refreshOverview();
  refreshDomains();
  refreshLists();
  refreshSettings();
}

init();
setInterval(() => {
  refreshOverview();
  // Only refresh domains/lists if their tab is active
  if (document.getElementById('tab-domains').classList.contains('active')) refreshDomains();
  if (document.getElementById('tab-lists').classList.contains('active')) refreshLists();
}, 5000);
</script>
</body>
</html>"""
