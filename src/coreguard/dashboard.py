import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from coreguard.config import LOG_FILE, Config
from coreguard.stats import Stats

logger = logging.getLogger("coreguard.dashboard")


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the coreguard dashboard."""

    stats: Stats = None
    cache = None
    config: Config = None

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
        else:
            self.send_error(404)

    def _json_response(self, data: dict | list, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

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
            "cname_check_enabled": cfg.cname_check_enabled,
            "dashboard_port": cfg.dashboard_port,
            "filter_lists": [
                {"name": f["name"], "enabled": f.get("enabled", True)}
                for f in cfg.filter_lists
            ],
        }
        self._json_response(data)

    def _serve_html(self) -> None:
        body = DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

    DashboardHandler.stats = stats
    DashboardHandler.cache = cache
    DashboardHandler.config = config

    try:
        server = HTTPServer(("127.0.0.1", config.dashboard_port), DashboardHandler)
    except OSError as e:
        logger.warning("Could not start dashboard on port %d: %s", config.dashboard_port, e)
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Dashboard available at http://127.0.0.1:%d", config.dashboard_port)
    return server


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Coreguard Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, monospace;
    background: #0d1117;
    color: #c9d1d9;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
  }
  h1 { color: #58a6ff; font-size: 22px; margin-bottom: 4px; }
  .subtitle { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
  }
  .card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 28px; font-weight: 600; color: #f0f6fc; margin-top: 4px; }
  .card .value.green { color: #3fb950; }
  .card .value.red { color: #f85149; }
  .card .value.blue { color: #58a6ff; }
  .section { margin-bottom: 24px; }
  .section h2 { font-size: 15px; color: #8b949e; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .tables { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 700px) { .tables { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  th { text-align: left; padding: 8px 12px; color: #8b949e; font-size: 12px; text-transform: uppercase; border-bottom: 1px solid #30363d; }
  td { padding: 6px 12px; font-size: 13px; border-bottom: 1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge.blocked { background: #f8514922; color: #f85149; }
  .badge.allowed { background: #3fb95022; color: #3fb950; }
  .query-table { max-height: 400px; overflow-y: auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
  .query-table table { border: none; }
  .domain { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .refresh-note { color: #484f58; font-size: 11px; text-align: right; margin-bottom: 8px; }
</style>
</head>
<body>
<h1>Coreguard</h1>
<p class="subtitle">DNS Ad &amp; Tracker Blocking</p>

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

<div class="section">
  <h2>Recent Queries</h2>
  <div class="refresh-note">Auto-refreshes every 5 seconds</div>
  <div class="query-table">
    <table><thead><tr><th>Time</th><th>Status</th><th>Type</th><th>Domain</th></tr></thead><tbody id="queries"></tbody></table>
  </div>
</div>

<script>
function fmt(n) { return n != null ? n.toLocaleString() : '-'; }

async function refresh() {
  try {
    const [statsRes, queriesRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/queries?limit=200')
    ]);
    const stats = await statsRes.json();
    const queries = await queriesRes.json();

    document.getElementById('total').textContent = fmt(stats.total_queries);
    document.getElementById('blocked').textContent = fmt(stats.blocked_queries);
    document.getElementById('block-rate').textContent = (stats.blocked_percent || 0) + '%';
    document.getElementById('cache-rate').textContent = (stats.cache_hit_rate || 0) + '%';
    document.getElementById('cache-size').textContent = fmt(stats.cache_size || 0);
    document.getElementById('cname').textContent = fmt(stats.cname_blocks);

    const blockedTbody = document.getElementById('top-blocked');
    blockedTbody.innerHTML = Object.entries(stats.top_blocked || {})
      .map(([d, c]) => `<tr><td class="domain">${esc(d)}</td><td>${fmt(c)}</td></tr>`).join('');

    const queriedTbody = document.getElementById('top-queried');
    queriedTbody.innerHTML = Object.entries(stats.top_queried || {})
      .map(([d, c]) => `<tr><td class="domain">${esc(d)}</td><td>${fmt(c)}</td></tr>`).join('');

    const qTbody = document.getElementById('queries');
    qTbody.innerHTML = queries
      .map(q => `<tr>
        <td>${esc(q.time)}</td>
        <td><span class="badge ${q.status.toLowerCase()}">${esc(q.status)}</span></td>
        <td>${esc(q.type)}</td>
        <td class="domain">${esc(q.domain)}</td>
      </tr>`).join('');
  } catch (e) {
    console.error('Refresh failed:', e);
  }
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
