import csv
import hmac
import io
import json
import logging
import os
import queue
import re
import signal
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
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

# --- SSE event bus ---
_MAX_SSE_CLIENTS = 5
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def broadcast_query(domain: str, qtype: str, blocked: bool, client_ip: str | None = None) -> None:
    """Broadcast a query event to all connected SSE clients."""
    event = json.dumps({
        "domain": domain,
        "type": qtype,
        "status": "BLOCKED" if blocked else "ALLOWED",
        "client": client_ip or "",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

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


_history_cache: dict = {"data": None, "timestamp": 0}

_QUERY_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(BLOCKED|ALLOWED)\s+\S+\s+\S+"
)


def _read_query_history() -> list[dict]:
    """Parse log file and return 24h of query counts in 10-minute buckets.

    Returns a list of 144 dicts with keys: time, allowed, blocked.
    Uses a 60-second cache to avoid re-parsing on every request.
    """
    now = time.time()
    if _history_cache["data"] is not None and now - _history_cache["timestamp"] < 60:
        return _history_cache["data"]

    utcnow = datetime.now(timezone.utc).astimezone()  # local time
    # Round down to the current 10-minute boundary
    base_minute = (utcnow.minute // 10) * 10
    end = utcnow.replace(minute=base_minute, second=0, microsecond=0) + timedelta(
        minutes=10
    )
    start = end - timedelta(hours=24)

    # Build 144 empty buckets
    buckets: list[dict] = []
    bucket_map: dict[str, dict] = {}
    for i in range(144):
        t = start + timedelta(minutes=10 * i)
        key = t.strftime("%Y-%m-%d %H:%M")
        bucket = {"time": t.strftime("%Y-%m-%dT%H:%M:%S"), "allowed": 0, "blocked": 0}
        buckets.append(bucket)
        bucket_map[key] = bucket

    if not LOG_FILE.exists():
        _history_cache["data"] = buckets
        _history_cache["timestamp"] = now
        return buckets

    start_str = start.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                # Quick prefix check before regex
                if len(line) < 19:
                    continue
                ts_str = line[:19]
                if ts_str < start_str:
                    continue
                m = _QUERY_LOG_RE.match(line)
                if not m:
                    continue
                # Bucket key: YYYY-MM-DD HH:M0 (floor to 10-min)
                minute_part = ts_str[14:16]
                bucket_key = ts_str[:14] + str(int(minute_part) // 10 * 10).zfill(2)
                bucket = bucket_map.get(bucket_key)
                if bucket is None:
                    continue
                if m.group(2) == "BLOCKED":
                    bucket["blocked"] += 1
                else:
                    bucket["allowed"] += 1
    except OSError:
        pass

    _history_cache["data"] = buckets
    _history_cache["timestamp"] = now
    return buckets


def _send_self_sighup() -> None:
    """Send SIGHUP to the current process to trigger filter reload."""
    try:
        os.kill(os.getpid(), signal.SIGHUP)
    except OSError:
        pass


def _format_prometheus_metrics(stats: Stats, cache=None, domain_filter=None) -> list[str]:
    """Format all metrics in Prometheus text exposition format."""
    lines: list[str] = []

    def _counter(name: str, help_text: str, value) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")

    def _gauge(name: str, help_text: str, value) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")

    with stats._lock:
        _counter("coreguard_queries_total",
                 "Total DNS queries received.", stats.total_queries)
        _counter("coreguard_queries_blocked_total",
                 "Total DNS queries blocked.", stats.blocked_queries)
        _counter("coreguard_queries_errors_total",
                 "Total DNS queries that resulted in errors.", stats.error_queries)
        _counter("coreguard_cache_hits_total",
                 "Total cache hits.", stats.cache_hits)
        _counter("coreguard_cache_misses_total",
                 "Total cache misses.", stats.cache_misses)
        _counter("coreguard_cname_blocks_total",
                 "Total CNAME-chain blocks.", stats.cname_blocks)

        # Labeled counter: query types
        lines.append("# HELP coreguard_queries_by_type Total queries by DNS record type.")
        lines.append("# TYPE coreguard_queries_by_type counter")
        for qtype, count in stats.query_types.items():
            lines.append(f'coreguard_queries_by_type{{qtype="{qtype}"}} {count}')

        # Latency histogram snapshot
        snap_buckets = list(stats._latency_buckets)
        snap_counts = list(stats._latency_counts)
        snap_sum = stats._latency_sum
        snap_total = stats._latency_total

    # Histogram (outside the lock — we have a snapshot)
    lines.append("# HELP coreguard_upstream_latency_seconds Upstream DNS resolution latency.")
    lines.append("# TYPE coreguard_upstream_latency_seconds histogram")
    cumulative = 0
    for bound, count in zip(snap_buckets, snap_counts):
        cumulative += count
        lines.append(f'coreguard_upstream_latency_seconds_bucket{{le="{bound}"}} {cumulative}')
    lines.append(f'coreguard_upstream_latency_seconds_bucket{{le="+Inf"}} {snap_total}')
    lines.append(f"coreguard_upstream_latency_seconds_sum {snap_sum}")
    lines.append(f"coreguard_upstream_latency_seconds_count {snap_total}")

    # Gauges
    if cache is not None:
        _gauge("coreguard_cache_size",
               "Current number of entries in the DNS cache.", cache.size)
        _gauge("coreguard_cache_max_entries",
               "Maximum cache capacity.", cache.max_entries)

    if domain_filter is not None:
        _gauge("coreguard_blocklist_size",
               "Number of domains in the blocklist.", domain_filter.blocked_count)
        _gauge("coreguard_allowlist_size",
               "Number of domains in the allowlist.", domain_filter.allowed_count)
        _gauge("coreguard_regex_patterns",
               "Number of active regex patterns.", domain_filter.regex_count)

    return lines


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the coreguard dashboard."""

    stats: Stats = None
    cache = None
    config: Config = None
    token: str = ""
    domain_filter = None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        if path == "/":
            self._serve_html()
        elif path == "/api/stats":
            self._serve_stats()
        elif path == "/api/queries":
            self._serve_queries(params)
        elif path == "/api/queries/export":
            self._serve_export(params)
        elif path == "/api/config":
            self._serve_config()
        elif path == "/api/domains":
            self._serve_domains()
        elif path == "/api/history":
            self._serve_history()
        elif path == "/api/clients":
            self._serve_clients()
        elif path == "/api/stream":
            self._serve_sse()
        elif path == "/metrics":
            self._serve_metrics()
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
            "/api/parental": self._handle_parental,
            "/api/schedules/add": self._handle_schedule_add,
            "/api/schedules/remove": self._handle_schedule_remove,
            "/api/schedules/toggle": self._handle_schedule_toggle,
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
        # Derive sparkline data from history cache — last 12 buckets (2 hours)
        history = _read_query_history()
        if history:
            last_12 = history[-12:]
            data["sparkline"] = {
                "total": [b["allowed"] + b["blocked"] for b in last_12],
                "blocked": [b["blocked"] for b in last_12],
                "allowed": [b["allowed"] for b in last_12],
            }
        self._json_response(data)

    def _serve_queries(self, params: dict) -> None:
        limit = min(max(int(params.get("limit", ["100"])[0]), 1), 500)
        offset = max(int(params.get("offset", ["0"])[0]), 0)
        start = params.get("start", [None])[0]
        end = params.get("end", [None])[0]
        domain = params.get("domain", [None])[0]
        client = params.get("client", [None])[0]
        status = params.get("status", [None])[0]
        queries, total = _read_recent_queries(
            limit, offset=offset, start=start, end=end,
            domain=domain, client=client, status=status,
        )
        self._json_response({
            "queries": queries,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total,
        })

    def _serve_config(self) -> None:
        cfg = self.config
        if not cfg:
            self._json_response({})
            return

        from coreguard.schedule import is_schedule_active

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
            "schedules": [
                {
                    "name": s.name,
                    "start": s.start,
                    "end": s.end,
                    "days": s.days,
                    "block_domains": s.block_domains,
                    "block_patterns": s.block_patterns,
                    "enabled": s.enabled,
                    "active": is_schedule_active(s),
                }
                for s in cfg.schedules
            ],
            "parental": {
                "safe_search_enabled": cfg.safe_search_enabled,
                "safe_search_youtube_restrict": cfg.safe_search_youtube_restrict,
                "content_categories": cfg.content_categories,
            },
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

    def _serve_history(self) -> None:
        buckets = _read_query_history()
        self._json_response({"buckets": buckets, "bucket_minutes": 10})

    def _serve_clients(self) -> None:
        data = self.stats.to_dict() if self.stats else {}
        self._json_response({"clients": data.get("top_clients", {})})

    def _serve_export(self, params: dict) -> None:
        fmt = params.get("format", ["json"])[0]
        queries, _ = _read_recent_queries(10000)
        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["time", "status", "type", "domain", "client"])
            for q in queries:
                writer.writerow([q["time"], q["status"], q["type"], q["domain"], q.get("client", "")])
            body = output.getvalue().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", "attachment; filename=coreguard-queries.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = json.dumps(queries, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=coreguard-queries.json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _serve_sse(self) -> None:
        """Server-Sent Events endpoint for real-time query streaming."""
        with _sse_lock:
            if len(_sse_clients) >= _MAX_SSE_CLIENTS:
                self._json_response({"error": "Too many SSE clients"}, status=429)
                return
            q = queue.Queue(maxsize=100)
            _sse_clients.append(q)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            while True:
                try:
                    event = q.get(timeout=30)
                    self.wfile.write(f"data: {event}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Send keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    def _serve_metrics(self) -> None:
        """Serve Prometheus exposition format metrics."""
        lines = _format_prometheus_metrics(
            self.stats, self.cache, self.domain_filter
        )
        body = "\n".join(lines).encode("utf-8") + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        is_regex = body.get("regex", False)
        if is_regex:
            pattern = body.get("domain", "")
            if not pattern:
                self._json_response({"error": "Missing regex pattern"}, status=400)
                return
            try:
                re.compile(pattern)
            except re.error as e:
                self._json_response({"error": f"Invalid regex: {e}"}, status=400)
                return
            with open(CUSTOM_ALLOW_FILE, "a") as f:
                f.write(f"regex:{pattern}\n")
            _send_self_sighup()
            self._json_response({"status": "ok", "pattern": pattern, "type": "regex"})
        else:
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
        is_regex = body.get("regex", False)
        if is_regex:
            pattern = body.get("domain", "")
            if not pattern:
                self._json_response({"error": "Missing regex pattern"}, status=400)
                return
            try:
                re.compile(pattern)
            except re.error as e:
                self._json_response({"error": f"Invalid regex: {e}"}, status=400)
                return
            with open(CUSTOM_BLOCK_FILE, "a") as f:
                f.write(f"regex:{pattern}\n")
            _send_self_sighup()
            self._json_response({"status": "ok", "pattern": pattern, "type": "regex"})
        else:
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

    def _handle_parental(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return

        cfg = load_config()

        if "safe_search_enabled" in body:
            cfg.safe_search_enabled = bool(body["safe_search_enabled"])
        if "safe_search_youtube_restrict" in body:
            restrict = body["safe_search_youtube_restrict"]
            if restrict in ("moderate", "strict"):
                cfg.safe_search_youtube_restrict = restrict
        if "content_categories" in body:
            from coreguard.safesearch import CONTENT_CATEGORY_LISTS
            cats = [c for c in body["content_categories"] if c in CONTENT_CATEGORY_LISTS]
            cfg.content_categories = cats

        save_config(cfg)
        _send_self_sighup()
        self._json_response({
            "status": "ok",
            "safe_search_enabled": cfg.safe_search_enabled,
            "safe_search_youtube_restrict": cfg.safe_search_youtube_restrict,
            "content_categories": cfg.content_categories,
        })

    def _handle_schedule_add(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return

        name = body.get("name", "").strip()
        if not name:
            self._json_response({"error": "Missing schedule name"}, status=400)
            return

        from coreguard.config import Schedule
        from coreguard.schedule import parse_time

        start = body.get("start", "00:00")
        end = body.get("end", "23:59")
        try:
            parse_time(start)
            parse_time(end)
        except (ValueError, IndexError):
            self._json_response({"error": "Invalid time format. Use HH:MM."}, status=400)
            return

        all_days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        days = body.get("days", all_days)
        if not isinstance(days, list) or not all(d in all_days for d in days):
            self._json_response({"error": "Invalid days list"}, status=400)
            return

        cfg = load_config()
        for s in cfg.schedules:
            if s.name == name:
                self._json_response({"error": f"Schedule '{name}' already exists"}, status=409)
                return

        new_schedule = Schedule(
            name=name,
            start=start,
            end=end,
            days=days,
            block_domains=body.get("block_domains", []),
            block_patterns=body.get("block_patterns", []),
            enabled=body.get("enabled", True),
        )
        cfg.schedules.append(new_schedule)
        save_config(cfg)
        _send_self_sighup()
        self._json_response({"status": "ok", "name": name, "action": "added"})

    def _handle_schedule_remove(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return

        name = body.get("name", "").strip()
        if not name:
            self._json_response({"error": "Missing schedule name"}, status=400)
            return

        cfg = load_config()
        original = len(cfg.schedules)
        cfg.schedules = [s for s in cfg.schedules if s.name != name]
        if len(cfg.schedules) == original:
            self._json_response({"error": f"Schedule '{name}' not found"}, status=404)
            return

        save_config(cfg)
        _send_self_sighup()
        self._json_response({"status": "ok", "name": name, "action": "removed"})

    def _handle_schedule_toggle(self) -> None:
        if not self._check_auth():
            return
        body = self._read_json_body()
        if body is None:
            return

        name = body.get("name", "").strip()
        enabled = body.get("enabled")
        if not name or enabled is None:
            self._json_response({"error": "Missing 'name' or 'enabled' field"}, status=400)
            return

        cfg = load_config()
        found = False
        for s in cfg.schedules:
            if s.name == name:
                s.enabled = bool(enabled)
                found = True
                break
        if not found:
            self._json_response({"error": f"Schedule '{name}' not found"}, status=404)
            return

        save_config(cfg)
        _send_self_sighup()
        self._json_response({"status": "ok", "name": name, "enabled": bool(enabled)})

    def log_message(self, format, *args):
        # Suppress default stderr logging from http.server
        pass


_QUERY_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(BLOCKED|ALLOWED)\s+(\S+)\s+(\S+)(?:\s+(\S+))?"
)


def _read_recent_queries(
    limit: int,
    offset: int = 0,
    start: str | None = None,
    end: str | None = None,
    domain: str | None = None,
    client: str | None = None,
    status: str | None = None,
) -> tuple[list[dict], int]:
    """Read and parse query log entries with filtering and pagination.

    Returns (entries, total_matching_count).
    """
    if not LOG_FILE.exists():
        return [], 0
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except OSError:
        return [], 0

    results = []
    for line in reversed(lines):
        m = _QUERY_PATTERN.match(line.strip())
        if not m:
            continue
        ts = m.group(1)
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        entry_status = m.group(2)
        if status and status != "all" and entry_status != status:
            continue
        entry_domain = m.group(4)
        if domain and domain.lower() not in entry_domain.lower():
            continue
        entry_client = m.group(5) or ""
        if client and client != entry_client:
            continue
        results.append({
            "time": ts,
            "status": entry_status,
            "type": m.group(3),
            "domain": entry_domain,
            "client": entry_client,
        })
    total = len(results)
    return results[offset:offset + limit], total


class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread (needed for SSE)."""
    daemon_threads = True


def start_dashboard(config: Config, stats: Stats, cache=None, domain_filter=None) -> HTTPServer | None:
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
    DashboardHandler.domain_filter = domain_filter

    try:
        server = _ThreadedHTTPServer(("127.0.0.1", config.dashboard_port), DashboardHandler)
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
    border-bottom: 2px solid transparent; transition: color 0.2s; position: relative;
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
    position: relative; overflow: hidden;
  }
  .card .label { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 26px; font-weight: 600; color: #f0f6fc; margin-top: 4px; }
  .card .value.green { color: #3fb950; }
  .card .value.red { color: #f85149; }
  .card .value.blue { color: #58a6ff; }
  .card canvas.sparkline {
    position: absolute; bottom: 4px; right: 8px; width: 60px; height: 20px; opacity: 0.6;
  }

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
  .domain.clickable { cursor: pointer; }
  .domain.clickable:hover { color: #58a6ff; text-decoration: underline; }
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
  .regex-tag { display: inline-block; background: #1f6feb; color: #fff; padding: 1px 5px; border-radius: 3px; font-size: 10px; margin-right: 6px; font-weight: 600; }
  .regex-toggle { display: flex; align-items: center; gap: 4px; font-size: 12px; color: #8b949e; cursor: pointer; white-space: nowrap; }
  .regex-toggle input { margin: 0; }
  .help-text { color: #8b949e; font-size: 12px; margin: 4px 0 12px; }
  .form-grid { display: flex; flex-direction: column; gap: 10px; }
  .form-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .form-row label { color: #8b949e; font-size: 12px; min-width: 100px; }
  .form-row input { flex: 1; }
  .day-picks { display: flex; gap: 6px; flex-wrap: wrap; }
  .day-pick { display: flex; align-items: center; gap: 3px; font-size: 12px; color: #c9d1d9; cursor: pointer; }
  .day-pick input { margin: 0; }
  .sched-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 14px; margin-bottom: 10px;
  }
  .sched-card .sched-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .sched-card .sched-name { font-weight: 600; font-size: 14px; }
  .sched-card .sched-time { color: #8b949e; font-size: 12px; font-family: "SF Mono", Menlo, Consolas, monospace; }
  .sched-card .sched-days { color: #8b949e; font-size: 11px; margin-bottom: 4px; }
  .sched-card .sched-rules { font-size: 12px; color: #c9d1d9; font-family: "SF Mono", Menlo, Consolas, monospace; }
  .sched-card .active-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .sched-card .active-dot.on { background: #3fb950; }
  .sched-card .active-dot.off { background: #484f58; }

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
  .filter-bar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }

  /* --- Filter chip --- */
  .filter-chip {
    display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px;
    background: #1f2937; border: 1px solid #58a6ff; border-radius: 12px;
    font-size: 11px; color: #58a6ff;
  }
  .filter-chip .dismiss { cursor: pointer; font-weight: bold; margin-left: 4px; }
  .filter-chip .dismiss:hover { color: #f85149; }

  /* --- History chart --- */
  .history-chart {
    position: relative; background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px; margin-bottom: 24px;
  }
  .history-chart h2 {
    font-size: 14px; color: #8b949e; margin-bottom: 12px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .history-chart canvas { width: 100%; height: 200px; display: block; cursor: crosshair; }
  .chart-tooltip {
    position: fixed; display: none; background: #1c2128; border: 1px solid #30363d;
    border-radius: 6px; padding: 8px 12px; font-size: 12px; color: #c9d1d9;
    pointer-events: none; z-index: 10; white-space: nowrap;
  }
  .chart-tooltip .tt-time { color: #8b949e; margin-bottom: 4px; }
  .chart-tooltip .tt-allowed { color: #3fb950; }
  .chart-tooltip .tt-blocked { color: #f85149; }

  /* --- Donut chart --- */
  .donut-chart {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px; margin-bottom: 24px;
  }
  .donut-chart h2 {
    font-size: 14px; color: #8b949e; margin-bottom: 12px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .donut-container { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
  .donut-container canvas { flex-shrink: 0; }
  .donut-legend { display: flex; flex-direction: column; gap: 6px; }
  .donut-legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
  .donut-legend-color { width: 12px; height: 12px; border-radius: 3px; }

  /* --- Pagination --- */
  .pagination {
    display: flex; align-items: center; justify-content: center;
    gap: 12px; margin-top: 12px; font-size: 13px;
  }
  .pagination .btn:disabled { opacity: 0.4; cursor: not-allowed; }

  /* --- SSE Live badge --- */
  .live-badge {
    display: inline-block; background: #f85149; color: #fff; font-size: 9px;
    padding: 1px 5px; border-radius: 4px; font-weight: 700; vertical-align: top;
    margin-left: 4px; animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
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
  <div class="tab" data-tab="queries">Queries <span class="live-badge" id="live-badge" style="display:none">LIVE</span></div>
  <div class="tab" data-tab="domains">Domains</div>
  <div class="tab" data-tab="lists">Lists</div>
  <div class="tab" data-tab="schedules">Schedules</div>
  <div class="tab" data-tab="parental">Parental</div>
  <div class="tab" data-tab="settings">Settings</div>
</div>

<!-- Tab 1: Overview -->
<div class="tab-content active" id="tab-overview">
  <div class="cards">
    <div class="card"><div class="label">Total Queries</div><div class="value" id="total">-</div><canvas class="sparkline" id="spark-total"></canvas></div>
    <div class="card"><div class="label">Blocked</div><div class="value red" id="blocked">-</div><canvas class="sparkline" id="spark-blocked"></canvas></div>
    <div class="card"><div class="label">Block Rate</div><div class="value red" id="block-rate">-</div></div>
    <div class="card"><div class="label">Cache Hit Rate</div><div class="value green" id="cache-rate">-</div></div>
    <div class="card"><div class="label">Cache Size</div><div class="value blue" id="cache-size">-</div></div>
    <div class="card"><div class="label">CNAME Blocks</div><div class="value" id="cname">-</div></div>
  </div>
  <div class="history-chart">
    <h2>Queries over last 24 hours</h2>
    <canvas id="history-canvas" height="200"></canvas>
    <div class="chart-tooltip" id="chart-tooltip">
      <div class="tt-time" id="tt-time"></div>
      <div class="tt-allowed" id="tt-allowed"></div>
      <div class="tt-blocked" id="tt-blocked"></div>
    </div>
  </div>
  <div class="donut-chart">
    <h2>Query Type Breakdown</h2>
    <div class="donut-container">
      <canvas id="donut-canvas" width="150" height="150"></canvas>
      <div class="donut-legend" id="donut-legend"></div>
    </div>
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
  <div class="section">
    <h2>Top Clients</h2>
    <table><thead><tr><th>Client IP</th><th>Queries</th></tr></thead><tbody id="top-clients"></tbody></table>
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
    <button class="btn btn-sm" onclick="exportQueries('csv')">Export CSV</button>
    <button class="btn btn-sm" onclick="exportQueries('json')">Export JSON</button>
    <span id="time-filter-chip"></span>
  </div>
  <div class="scroll-table">
    <table><thead><tr><th>Time</th><th>Status</th><th>Type</th><th>Domain</th><th>Client</th></tr></thead><tbody id="queries"></tbody></table>
  </div>
  <div class="pagination">
    <button class="btn btn-sm" id="prev-page" onclick="prevPage()">Previous</button>
    <span id="page-info">Page 1</span>
    <button class="btn btn-sm" id="next-page" onclick="nextPage()">Next</button>
  </div>
  <div class="refresh-note">Auto-refreshes every 5 seconds</div>
</div>

<!-- Tab 3: Domains -->
<div class="tab-content" id="tab-domains">
  <div class="section">
    <h2>Allowlist <span class="count-badge" id="allow-count">0</span></h2>
    <div class="inline-form">
      <input type="text" id="allow-input" placeholder="example.com or regex pattern">
      <label class="regex-toggle"><input type="checkbox" id="allow-regex-toggle"><span>Regex</span></label>
      <button class="btn btn-primary btn-sm" onclick="addDomain('allow')">Add</button>
    </div>
    <div class="domain-list" id="allow-list"></div>
  </div>
  <div class="section">
    <h2>Blocklist <span class="count-badge" id="block-count">0</span></h2>
    <div class="inline-form">
      <input type="text" id="block-input" placeholder="ads.example.com or regex pattern">
      <label class="regex-toggle"><input type="checkbox" id="block-regex-toggle"><span>Regex</span></label>
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

<!-- Tab 5: Schedules -->
<div class="tab-content" id="tab-schedules">
  <div class="section">
    <h2>Filtering Schedules <span class="count-badge" id="sched-count">0</span></h2>
    <div id="sched-list"></div>
  </div>
  <div class="section">
    <h2>Add Schedule</h2>
    <div class="form-grid">
      <div class="form-row">
        <label>Name</label>
        <input type="text" id="sched-name" placeholder="work-hours">
      </div>
      <div class="form-row">
        <label>Start</label>
        <input type="text" id="sched-start" placeholder="09:00" style="max-width:100px">
        <label style="margin-left:12px">End</label>
        <input type="text" id="sched-end" placeholder="17:00" style="max-width:100px">
      </div>
      <div class="form-row">
        <label>Days</label>
        <div class="day-picks">
          <label class="day-pick"><input type="checkbox" value="mon" checked><span>Mon</span></label>
          <label class="day-pick"><input type="checkbox" value="tue" checked><span>Tue</span></label>
          <label class="day-pick"><input type="checkbox" value="wed" checked><span>Wed</span></label>
          <label class="day-pick"><input type="checkbox" value="thu" checked><span>Thu</span></label>
          <label class="day-pick"><input type="checkbox" value="fri" checked><span>Fri</span></label>
          <label class="day-pick"><input type="checkbox" value="sat" checked><span>Sat</span></label>
          <label class="day-pick"><input type="checkbox" value="sun" checked><span>Sun</span></label>
        </div>
      </div>
      <div class="form-row">
        <label>Block domains</label>
        <input type="text" id="sched-domains" placeholder="reddit.com, twitter.com (comma-separated)">
      </div>
      <div class="form-row">
        <label>Block patterns</label>
        <input type="text" id="sched-patterns" placeholder="*.tiktok.com, regex:^game.*$ (comma-separated)">
      </div>
    </div>
    <div class="actions" style="margin-top:12px">
      <button class="btn btn-primary" onclick="addSchedule()">Add Schedule</button>
    </div>
  </div>
</div>

<!-- Tab 6: Parental -->
<div class="tab-content" id="tab-parental">
  <div class="section">
    <h2>Safe Search</h2>
    <p class="help-text">When enabled, search engines are redirected to their safe variants via DNS (Google, YouTube, Bing, DuckDuckGo).</p>
    <div class="config-row" style="margin:12px 0">
      <span class="key">Safe Search</span>
      <label class="toggle"><input type="checkbox" id="safesearch-toggle" onchange="toggleSafeSearch(this.checked)"><span class="slider"></span></label>
    </div>
    <div class="config-row" style="margin:12px 0">
      <span class="key">YouTube Restriction</span>
      <select id="yt-restrict" onchange="setYoutubeRestrict(this.value)" style="background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 8px">
        <option value="moderate">Moderate</option>
        <option value="strict">Strict</option>
      </select>
    </div>
  </div>
  <div class="section">
    <h2>Content Categories</h2>
    <p class="help-text">Block entire categories of websites using curated filter lists.</p>
    <div id="cat-list">
      <div class="config-row" style="margin:8px 0">
        <span class="key">Adult content</span>
        <label class="toggle"><input type="checkbox" id="cat-adult" onchange="toggleCategory()"><span class="slider"></span></label>
      </div>
      <div class="config-row" style="margin:8px 0">
        <span class="key">Gambling</span>
        <label class="toggle"><input type="checkbox" id="cat-gambling" onchange="toggleCategory()"><span class="slider"></span></label>
      </div>
      <div class="config-row" style="margin:8px 0">
        <span class="key">Social media</span>
        <label class="toggle"><input type="checkbox" id="cat-social" onchange="toggleCategory()"><span class="slider"></span></label>
      </div>
    </div>
  </div>
</div>

<!-- Tab 7: Settings -->
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
let queryOffset = 0;
let queryLimit = 100;
let queryTotal = 0;
let queryHasMore = false;
let timeFilterStart = null;
let timeFilterEnd = null;
let prevStats = {};
let sseConnected = false;
let pollInterval = 5000;

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

// --- Live counter animation ---
function animateValue(el, from, to, duration, suffix) {
  if (from === to) return;
  const start = performance.now();
  suffix = suffix || '';
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3); // ease-out cubic
    const val = Math.round(from + (to - from) * ease);
    el.textContent = val.toLocaleString() + suffix;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// --- Dynamic favicon ---
function updateFavicon(blockedPercent) {
  const canvas = document.createElement('canvas');
  canvas.width = 32; canvas.height = 32;
  const ctx = canvas.getContext('2d');
  ctx.beginPath();
  ctx.arc(16, 16, 14, 0, Math.PI * 2);
  ctx.fillStyle = blockedPercent < 50 ? '#3fb950' : '#f85149';
  ctx.fill();
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 14px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(Math.round(blockedPercent) + '', 16, 17);
  let link = document.querySelector('link[rel="icon"]');
  if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.head.appendChild(link); }
  link.href = canvas.toDataURL();
}

// --- Sparklines ---
function drawSparkline(canvas, data, color) {
  if (!canvas || !data || !data.length) return;
  const w = 60, h = 20;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...data, 1);
  const step = w / (data.length - 1 || 1);
  ctx.beginPath();
  ctx.moveTo(0, h - (data[0] / max) * h);
  for (let i = 1; i < data.length; i++) {
    ctx.lineTo(i * step, h - (data[i] / max) * h);
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.stroke();
  // Fill area
  ctx.lineTo((data.length - 1) * step, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = color + '22';
  ctx.fill();
}

// --- Donut chart ---
function drawDonutChart(queryTypes) {
  const canvas = document.getElementById('donut-canvas');
  const legend = document.getElementById('donut-legend');
  if (!canvas || !legend) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 150 * dpr;
  canvas.height = 150 * dpr;
  canvas.style.width = '150px';
  canvas.style.height = '150px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, 150, 150);

  const colors = { A: '#3fb950', AAAA: '#58a6ff', CNAME: '#d2a8ff', MX: '#f0883e', TXT: '#ffa657' };
  const defaultColor = '#8b949e';
  const entries = Object.entries(queryTypes || {});
  const total = entries.reduce((s, [, v]) => s + v, 0);
  if (total === 0) {
    ctx.beginPath();
    ctx.arc(75, 75, 55, 0, Math.PI * 2);
    ctx.strokeStyle = '#30363d';
    ctx.lineWidth = 20;
    ctx.stroke();
    legend.innerHTML = '<div style="color:#484f58;font-size:12px">No data</div>';
    return;
  }

  // Sort by count descending
  entries.sort((a, b) => b[1] - a[1]);
  let angle = -Math.PI / 2;
  let legendHtml = '';
  for (const [type, count] of entries) {
    const slice = (count / total) * Math.PI * 2;
    const color = colors[type] || defaultColor;
    ctx.beginPath();
    ctx.arc(75, 75, 55, angle, angle + slice);
    ctx.strokeStyle = color;
    ctx.lineWidth = 20;
    ctx.stroke();
    angle += slice;
    const pct = ((count / total) * 100).toFixed(1);
    legendHtml += '<div class="donut-legend-item"><span class="donut-legend-color" style="background:'+color+'"></span><span>'+esc(type)+': '+fmt(count)+' ('+pct+'%)</span></div>';
  }
  legend.innerHTML = legendHtml;
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
function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  const tab = document.querySelector('.tab[data-tab="'+tabName+'"]');
  if (tab) tab.classList.add('active');
  document.getElementById('tab-' + tabName).classList.add('active');
}
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

// --- Per-domain drill-down ---
function drillDomain(domain) {
  document.getElementById('query-search').value = domain;
  switchTab('queries');
  queryOffset = 0;
  fetchQueries();
}

// --- Click-to-filter from chart ---
function filterByTimeRange(startTime, endTime) {
  timeFilterStart = startTime;
  timeFilterEnd = endTime;
  queryOffset = 0;
  switchTab('queries');
  updateTimeFilterChip();
  fetchQueries();
}

function clearTimeFilter() {
  timeFilterStart = null;
  timeFilterEnd = null;
  document.getElementById('time-filter-chip').innerHTML = '';
  queryOffset = 0;
  fetchQueries();
}

function updateTimeFilterChip() {
  const el = document.getElementById('time-filter-chip');
  if (timeFilterStart && timeFilterEnd) {
    el.innerHTML = '<span class="filter-chip">'+esc(timeFilterStart)+' to '+esc(timeFilterEnd)+' <span class="dismiss" onclick="clearTimeFilter()">x</span></span>';
  } else {
    el.innerHTML = '';
  }
}

// --- Overview ---
async function refreshOverview() {
  try {
    const stats = await fetch('/api/stats').then(r => r.json());

    // Animate stat values
    const fields = [
      {id: 'total', key: 'total_queries'},
      {id: 'blocked', key: 'blocked_queries'},
      {id: 'cache-size', key: 'cache_size'},
      {id: 'cname', key: 'cname_blocks'},
    ];
    for (const f of fields) {
      const el = document.getElementById(f.id);
      const oldVal = prevStats[f.key] || 0;
      const newVal = stats[f.key] || 0;
      if (oldVal !== newVal) animateValue(el, oldVal, newVal, 500);
      else el.textContent = fmt(newVal);
    }
    // Percentage fields (no animation, just update)
    document.getElementById('block-rate').textContent = (stats.blocked_percent || 0) + '%';
    document.getElementById('cache-rate').textContent = (stats.cache_hit_rate || 0) + '%';
    prevStats = stats;

    // Favicon
    updateFavicon(stats.blocked_percent || 0);

    // Sparklines
    if (stats.sparkline) {
      drawSparkline(document.getElementById('spark-total'), stats.sparkline.total, '#f0f6fc');
      drawSparkline(document.getElementById('spark-blocked'), stats.sparkline.blocked, '#f85149');
    }

    // Donut chart
    drawDonutChart(stats.query_types);

    // Top blocked/queried with clickable domains
    document.getElementById('top-blocked').innerHTML = Object.entries(stats.top_blocked || {})
      .map(([d,c]) => '<tr><td class="domain clickable" onclick="drillDomain(&#39;'+esc(d)+'&#39;)">'+esc(d)+'</td><td>'+fmt(c)+'</td></tr>').join('');
    document.getElementById('top-queried').innerHTML = Object.entries(stats.top_queried || {})
      .map(([d,c]) => '<tr><td class="domain clickable" onclick="drillDomain(&#39;'+esc(d)+'&#39;)">'+esc(d)+'</td><td>'+fmt(c)+'</td></tr>').join('');

    // Top clients
    const clients = stats.top_clients || {};
    document.getElementById('top-clients').innerHTML = Object.entries(clients)
      .map(([ip,c]) => '<tr><td class="domain clickable" onclick="filterByClient(&#39;'+esc(ip)+'&#39;)">'+esc(ip)+'</td><td>'+fmt(c)+'</td></tr>').join('') || '<tr><td colspan="2" class="empty-state">No client data</td></tr>';

  } catch(e) { console.error('Refresh failed:', e); }
}

function filterByClient(ip) {
  document.getElementById('query-search').value = '';
  switchTab('queries');
  queryOffset = 0;
  // Use the client filter param
  fetchQueries({client: ip});
}

// --- Queries (paginated) ---
async function fetchQueries(extra) {
  try {
    const search = document.getElementById('query-search').value.trim();
    const statusFilter = document.getElementById('query-status-filter').value;
    let url = '/api/queries?limit='+queryLimit+'&offset='+queryOffset;
    if (search) url += '&domain=' + encodeURIComponent(search);
    if (statusFilter && statusFilter !== 'all') url += '&status=' + encodeURIComponent(statusFilter);
    if (timeFilterStart) url += '&start=' + encodeURIComponent(timeFilterStart);
    if (timeFilterEnd) url += '&end=' + encodeURIComponent(timeFilterEnd);
    if (extra && extra.client) url += '&client=' + encodeURIComponent(extra.client);
    const data = await fetch(url).then(r => r.json());
    queriesData = data.queries || [];
    queryTotal = data.total || 0;
    queryHasMore = data.has_more || false;
    renderQueries();
    updatePagination();
  } catch(e) { console.error('Queries fetch failed:', e); }
}

function renderQueries() {
  document.getElementById('queries').innerHTML = queriesData.map(q =>
    '<tr><td>'+esc(q.time)+'</td><td><span class="badge '+q.status.toLowerCase()+'">'+esc(q.status)+'</span></td><td>'+esc(q.type)+'</td><td class="domain clickable" onclick="drillDomain(&#39;'+esc(q.domain)+'&#39;)">'+esc(q.domain)+'</td><td>'+esc(q.client || '')+'</td></tr>'
  ).join('');
}

function updatePagination() {
  const page = Math.floor(queryOffset / queryLimit) + 1;
  const totalPages = Math.max(1, Math.ceil(queryTotal / queryLimit));
  document.getElementById('page-info').textContent = 'Page ' + page + ' of ' + totalPages;
  document.getElementById('prev-page').disabled = queryOffset === 0;
  document.getElementById('next-page').disabled = !queryHasMore;
}

function prevPage() {
  queryOffset = Math.max(0, queryOffset - queryLimit);
  fetchQueries();
}

function nextPage() {
  if (queryHasMore) {
    queryOffset += queryLimit;
    fetchQueries();
  }
}

document.getElementById('query-search').addEventListener('input', () => { queryOffset = 0; fetchQueries(); });
document.getElementById('query-status-filter').addEventListener('change', () => { queryOffset = 0; fetchQueries(); });

// --- Export ---
function exportQueries(format) {
  window.open('/api/queries/export?format=' + format, '_blank');
}

// --- Domains ---
function renderDomainEntry(d, type) {
  const isRegex = d.startsWith('regex:');
  const display = isRegex ? d.substring(6) : d;
  const tag = isRegex ? '<span class="regex-tag">regex</span>' : '';
  const click = isRegex ? '' : ' clickable" onclick="drillDomain(&#39;'+esc(d)+'&#39;)';
  return '<div class="domain-item"><span class="name'+click+'">'+tag+esc(display)+'</span><button class="btn btn-sm" onclick="removeDomain(&#39;'+type+'&#39;,&#39;'+esc(d)+'&#39;)">Remove</button></div>';
}

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
      ? al.map(d => renderDomainEntry(d, 'allow')).join('')
      : '<div class="empty-state">No custom allowed domains</div>';

    document.getElementById('block-list').innerHTML = bl.length
      ? bl.map(d => renderDomainEntry(d, 'block')).join('')
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
  const regexCheck = document.getElementById(type + '-regex-toggle');
  const isRegex = regexCheck && regexCheck.checked;
  const domain = input.value.trim();
  if (!domain) return;
  try {
    const body = isRegex ? { domain, regex: true } : { domain: domain.toLowerCase() };
    await api('POST', '/api/domains/' + type, body);
    toast('Added ' + (isRegex ? 'regex ' : '') + domain + ' to ' + type + 'list');
    input.value = '';
    if (regexCheck) regexCheck.checked = false;
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
// --- Schedules ---
async function refreshSchedules() {
  try {
    const data = await fetch('/api/config').then(r => r.json());
    const schedules = data.schedules || [];
    document.getElementById('sched-count').textContent = schedules.length;

    if (!schedules.length) {
      document.getElementById('sched-list').innerHTML = '<div class="empty-state">No schedules configured</div>';
      return;
    }

    document.getElementById('sched-list').innerHTML = schedules.map(s => {
      const dotClass = s.active ? 'on' : 'off';
      const statusText = s.active ? 'Active' : (s.enabled ? 'Inactive' : 'Disabled');
      const rules = [...(s.block_domains||[]), ...(s.block_patterns||[])];
      return '<div class="sched-card">'
        + '<div class="sched-header">'
        +   '<div><span class="active-dot '+dotClass+'"></span><span class="sched-name">'+esc(s.name)+'</span> <span style="color:#8b949e;font-size:11px">('+statusText+')</span></div>'
        +   '<div style="display:flex;gap:6px;align-items:center">'
        +     '<label class="toggle"><input type="checkbox" '+(s.enabled?'checked':'')+' onchange="toggleSchedule(&#39;'+esc(s.name)+'&#39;,this.checked)"><span class="slider"></span></label>'
        +     '<button class="btn btn-sm" onclick="removeSchedule(&#39;'+esc(s.name)+'&#39;)">Remove</button>'
        +   '</div>'
        + '</div>'
        + '<div class="sched-time">'+esc(s.start)+' – '+esc(s.end)+'</div>'
        + '<div class="sched-days">'+esc((s.days||[]).join(', '))+'</div>'
        + (rules.length ? '<div class="sched-rules">'+rules.map(r => esc(r)).join(', ')+'</div>' : '')
        + '</div>';
    }).join('');
  } catch(e) { console.error('Schedules refresh failed:', e); }
}

async function addSchedule() {
  const name = document.getElementById('sched-name').value.trim();
  const start = document.getElementById('sched-start').value.trim();
  const end = document.getElementById('sched-end').value.trim();
  if (!name || !start || !end) { toast('Name, start, and end time are required', 'error'); return; }

  const dayBoxes = document.querySelectorAll('.day-picks input[type=checkbox]');
  const days = [];
  dayBoxes.forEach(cb => { if (cb.checked) days.push(cb.value); });
  if (!days.length) { toast('Select at least one day', 'error'); return; }

  const domainsRaw = document.getElementById('sched-domains').value.trim();
  const patternsRaw = document.getElementById('sched-patterns').value.trim();
  const block_domains = domainsRaw ? domainsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
  const block_patterns = patternsRaw ? patternsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

  try {
    await api('POST', '/api/schedules/add', { name, start, end, days, block_domains, block_patterns });
    toast('Schedule "' + name + '" added');
    document.getElementById('sched-name').value = '';
    document.getElementById('sched-start').value = '';
    document.getElementById('sched-end').value = '';
    document.getElementById('sched-domains').value = '';
    document.getElementById('sched-patterns').value = '';
    refreshSchedules();
  } catch(e) { toast(e.message, 'error'); }
}

async function removeSchedule(name) {
  if (!confirm('Remove schedule "' + name + '"?')) return;
  try {
    await api('POST', '/api/schedules/remove', { name });
    toast('Schedule "' + name + '" removed');
    refreshSchedules();
  } catch(e) { toast(e.message, 'error'); }
}

async function toggleSchedule(name, enabled) {
  try {
    await api('POST', '/api/schedules/toggle', { name, enabled });
    toast('Schedule "' + name + '" ' + (enabled ? 'enabled' : 'disabled'));
    refreshSchedules();
  } catch(e) { toast(e.message, 'error'); refreshSchedules(); }
}

// --- Parental Controls ---
async function refreshParental() {
  try {
    const data = await fetch('/api/config').then(r => r.json());
    const p = data.parental || {};
    document.getElementById('safesearch-toggle').checked = !!p.safe_search_enabled;
    document.getElementById('yt-restrict').value = p.safe_search_youtube_restrict || 'moderate';
    const cats = p.content_categories || [];
    document.getElementById('cat-adult').checked = cats.includes('adult');
    document.getElementById('cat-gambling').checked = cats.includes('gambling');
    document.getElementById('cat-social').checked = cats.includes('social');
  } catch(e) { console.error('Parental refresh failed:', e); }
}

async function toggleSafeSearch(enabled) {
  try {
    await api('POST', '/api/parental', { safe_search_enabled: enabled });
    toast('Safe search ' + (enabled ? 'enabled' : 'disabled'));
  } catch(e) { toast(e.message, 'error'); refreshParental(); }
}

async function setYoutubeRestrict(level) {
  try {
    await api('POST', '/api/parental', { safe_search_youtube_restrict: level });
    toast('YouTube restriction set to ' + level);
  } catch(e) { toast(e.message, 'error'); refreshParental(); }
}

async function toggleCategory() {
  const cats = [];
  if (document.getElementById('cat-adult').checked) cats.push('adult');
  if (document.getElementById('cat-gambling').checked) cats.push('gambling');
  if (document.getElementById('cat-social').checked) cats.push('social');
  try {
    await api('POST', '/api/parental', { content_categories: cats });
    toast('Content categories updated');
  } catch(e) { toast(e.message, 'error'); refreshParental(); }
}

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

// --- History chart ---
let historyData = [];

function drawHistoryChart() {
  const canvas = document.getElementById('history-canvas');
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = rect.width - 32;
  canvas.width = w * dpr;
  canvas.height = 200 * dpr;
  canvas.style.width = w + 'px';
  canvas.style.height = '200px';

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, 200);

  if (!historyData.length) return;

  const pad = {top: 10, right: 10, bottom: 25, left: 45};
  const cw = w - pad.left - pad.right;
  const ch = 200 - pad.top - pad.bottom;

  let maxVal = 0;
  for (const b of historyData) {
    const total = b.allowed + b.blocked;
    if (total > maxVal) maxVal = total;
  }
  if (maxVal === 0) maxVal = 1;

  const gridCount = 4;
  const step = Math.ceil(maxVal / gridCount);
  const yMax = step * gridCount;

  ctx.strokeStyle = '#30363d';
  ctx.lineWidth = 0.5;
  ctx.fillStyle = '#484f58';
  ctx.font = '10px -apple-system, BlinkMacSystemFont, sans-serif';
  ctx.textAlign = 'right';
  for (let i = 0; i <= gridCount; i++) {
    const y = pad.top + ch - (i / gridCount) * ch;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(w - pad.right, y);
    ctx.stroke();
    ctx.fillText(String(step * i), pad.left - 6, y + 3);
  }

  const barW = Math.max(1, cw / historyData.length - 0.5);
  const gap = cw / historyData.length;
  for (let i = 0; i < historyData.length; i++) {
    const b = historyData[i];
    const x = pad.left + i * gap;
    const allowedH = (b.allowed / yMax) * ch;
    const blockedH = (b.blocked / yMax) * ch;
    ctx.fillStyle = '#3fb950';
    ctx.fillRect(x, pad.top + ch - allowedH - blockedH, barW, allowedH);
    ctx.fillStyle = '#f85149';
    ctx.fillRect(x, pad.top + ch - blockedH, barW, blockedH);
  }

  ctx.fillStyle = '#484f58';
  ctx.textAlign = 'center';
  ctx.font = '10px -apple-system, BlinkMacSystemFont, sans-serif';
  for (let i = 0; i < historyData.length; i += 18) {
    const b = historyData[i];
    const x = pad.left + i * gap + barW / 2;
    const t = new Date(b.time);
    const label = t.getHours().toString().padStart(2,'0') + ':' + t.getMinutes().toString().padStart(2,'0');
    ctx.fillText(label, x, 200 - 5);
  }
}

function setupChartInteraction() {
  const canvas = document.getElementById('history-canvas');
  const tooltip = document.getElementById('chart-tooltip');
  if (!canvas || !tooltip) return;

  function getBucketIndex(e) {
    if (!historyData.length) return -1;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const pad = {left: 45, right: 10};
    const cw = rect.width - pad.left - pad.right;
    const gap = cw / historyData.length;
    return Math.floor((x - pad.left) / gap);
  }

  canvas.addEventListener('mousemove', function(e) {
    const idx = getBucketIndex(e);
    if (idx < 0 || idx >= historyData.length) { tooltip.style.display = 'none'; return; }
    const b = historyData[idx];
    const t = new Date(b.time);
    const end = new Date(t.getTime() + 10*60*1000);
    const tfmt = t2 => t2.getHours().toString().padStart(2,'0') + ':' + t2.getMinutes().toString().padStart(2,'0');
    document.getElementById('tt-time').textContent = tfmt(t) + ' \\u2013 ' + tfmt(end);
    document.getElementById('tt-allowed').textContent = 'Allowed: ' + b.allowed;
    document.getElementById('tt-blocked').textContent = 'Blocked: ' + b.blocked;
    tooltip.style.display = 'block';
    let tx = e.clientX + 12;
    let ty = e.clientY - 10;
    if (tx + 160 > window.innerWidth) tx = e.clientX - 170;
    tooltip.style.left = tx + 'px';
    tooltip.style.top = ty + 'px';
  });

  canvas.addEventListener('mouseleave', function() {
    tooltip.style.display = 'none';
  });

  // Click-to-filter: click a bar to filter queries to that time range
  canvas.addEventListener('click', function(e) {
    const idx = getBucketIndex(e);
    if (idx < 0 || idx >= historyData.length) return;
    const b = historyData[idx];
    const t = new Date(b.time);
    const end = new Date(t.getTime() + 10*60*1000);
    const pad2 = n => String(n).padStart(2, '0');
    const fmtDT = d => d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+' '+pad2(d.getHours())+':'+pad2(d.getMinutes())+':'+pad2(d.getSeconds());
    filterByTimeRange(fmtDT(t), fmtDT(end));
  });
}

async function refreshHistory() {
  try {
    const data = await fetch('/api/history').then(r => r.json());
    historyData = data.buckets || [];
    drawHistoryChart();
  } catch(e) { console.error('History refresh failed:', e); }
}

window.addEventListener('resize', drawHistoryChart);

// --- Server-Sent Events ---
function connectSSE() {
  try {
    const es = new EventSource('/api/stream');
    es.onopen = function() {
      sseConnected = true;
      document.getElementById('live-badge').style.display = '';
      pollInterval = 30000;
    };
    es.onmessage = function(e) {
      try {
        const q = JSON.parse(e.data);
        queriesData.unshift(q);
        if (queriesData.length > queryLimit) queriesData.pop();
        if (document.getElementById('tab-queries').classList.contains('active')) {
          renderQueries();
        }
      } catch(err) {}
    };
    es.onerror = function() {
      sseConnected = false;
      document.getElementById('live-badge').style.display = 'none';
      pollInterval = 5000;
      es.close();
      // Reconnect after 5s
      setTimeout(connectSSE, 5000);
    };
  } catch(e) {
    // SSE not supported or failed
  }
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
  refreshHistory();
  setupChartInteraction();
  fetchQueries();
  refreshDomains();
  refreshLists();
  refreshSchedules();
  refreshParental();
  refreshSettings();
  connectSSE();
}

init();
setInterval(() => {
  refreshOverview();
  if (document.getElementById('tab-queries').classList.contains('active') && !sseConnected) fetchQueries();
  if (document.getElementById('tab-domains').classList.contains('active')) refreshDomains();
  if (document.getElementById('tab-lists').classList.contains('active')) refreshLists();
  if (document.getElementById('tab-schedules').classList.contains('active')) refreshSchedules();
  if (document.getElementById('tab-parental').classList.contains('active')) refreshParental();
}, pollInterval);
setInterval(refreshHistory, 60000);
</script>
</body>
</html>"""
