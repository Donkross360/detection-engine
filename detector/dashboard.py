import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional


def _read_cpu_percent() -> float:
    # Lightweight fallback: use 1-minute load average as proxy percentage.
    # This avoids external dependencies and still provides useful system pressure visibility.
    load1, _, _ = os.getloadavg()
    cpu_count = os.cpu_count() or 1
    return max(0.0, min(100.0, (load1 / cpu_count) * 100.0))


def _read_memory_percent() -> float:
    try:
        mem_total_kb = 0
        mem_available_kb = 0
        with open("/proc/meminfo", "r", encoding="utf-8") as meminfo:
            for line in meminfo:
                if line.startswith("MemTotal:"):
                    mem_total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available_kb = int(line.split()[1])
        if mem_total_kb <= 0:
            return 0.0
        used_kb = mem_total_kb - mem_available_kb
        return max(0.0, min(100.0, (used_kb / mem_total_kb) * 100.0))
    except Exception:
        return 0.0


class DashboardServer:
    def __init__(
        self,
        host: str,
        port: int,
        refresh_seconds: int,
        get_metrics: Callable[[], Dict[str, Any]],
    ) -> None:
        self.host = host
        self.port = port
        self.refresh_seconds = max(1, refresh_seconds)
        self.get_metrics = get_metrics
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _html_template(self) -> str:
        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Detector Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background: #0f172a; color: #e2e8f0; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, minmax(220px, 1fr)); gap: 12px; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 12px; }}
    h1, h2 {{ margin: 0 0 10px 0; }}
    ul {{ margin: 0; padding-left: 20px; }}
    code {{ color: #93c5fd; }}
    .small {{ color: #94a3b8; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>Anomaly Detector Metrics</h1>
  <p class="small">Auto-refresh: every {self.refresh_seconds}s</p>
  <div class="grid">
    <div class="card"><h2>Global Req/s</h2><div id="global_rps">-</div></div>
    <div class="card"><h2>CPU Usage</h2><div id="cpu">-</div></div>
    <div class="card"><h2>Memory Usage</h2><div id="memory">-</div></div>
    <div class="card"><h2>Effective Mean</h2><div id="mean">-</div></div>
    <div class="card"><h2>Effective Stddev</h2><div id="stddev">-</div></div>
    <div class="card"><h2>Uptime</h2><div id="uptime">-</div></div>
  </div>
  <div class="grid" style="margin-top:12px;">
    <div class="card">
      <h2>Banned IPs</h2>
      <ul id="banned_ips"></ul>
    </div>
    <div class="card" style="grid-column: span 2;">
      <h2>Top 10 Source IPs</h2>
      <ul id="top_ips"></ul>
    </div>
  </div>
  <p class="small">Updated: <span id="updated">-</span></p>
  <script>
    async function refresh() {{
      const res = await fetch('/metrics');
      const m = await res.json();
      document.getElementById('global_rps').textContent = m.global_rps.toFixed(4);
      document.getElementById('cpu').textContent = m.cpu_percent.toFixed(2) + '%';
      document.getElementById('memory').textContent = m.memory_percent.toFixed(2) + '%';
      document.getElementById('mean').textContent = m.effective_mean.toFixed(4);
      document.getElementById('stddev').textContent = m.effective_stddev.toFixed(4);
      document.getElementById('uptime').textContent = m.uptime_seconds + 's';
      document.getElementById('updated').textContent = m.timestamp;

      const banned = document.getElementById('banned_ips');
      banned.innerHTML = '';
      if (!m.banned_ips.length) {{
        const li = document.createElement('li');
        li.textContent = 'None';
        banned.appendChild(li);
      }} else {{
        m.banned_ips.forEach((b) => {{
          const li = document.createElement('li');
          li.textContent = b.ip + ' (offense=' + b.offense_count + ', duration=' + b.duration + ')';
          banned.appendChild(li);
        }});
      }}

      const top = document.getElementById('top_ips');
      top.innerHTML = '';
      if (!m.top_ips.length) {{
        const li = document.createElement('li');
        li.textContent = 'No active IPs';
        top.appendChild(li);
      }} else {{
        m.top_ips.forEach((i) => {{
          const li = document.createElement('li');
          li.textContent = i.ip + ' | rps=' + i.rps.toFixed(4) + ' | count=' + i.count;
          top.appendChild(li);
        }});
      }}
    }}
    refresh();
    setInterval(refresh, {self.refresh_seconds * 1000});
  </script>
</body>
</html>
"""

    def start(self) -> None:
        parent = self
        html = self._html_template().encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/metrics":
                    payload = parent.get_metrics()
                    body = json.dumps(payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                    return

                self.send_response(404)
                self.end_headers()

            def log_message(self, _format: str, *_args: Any) -> None:
                # Keep detector terminal output focused on detector events.
                return

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="dashboard-server",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def build_metrics(
    window_snapshot: Dict[str, Any],
    baseline_snapshot: Dict[str, Any],
    banned_ips: list[Dict[str, Any]],
    started_at_monotonic: float,
) -> Dict[str, Any]:
    uptime_seconds = int(max(0.0, time.monotonic() - started_at_monotonic))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "global_rps": float(window_snapshot.get("global_rps", 0.0)),
        "top_ips": window_snapshot.get("top_ips", []),
        "banned_ips": banned_ips,
        "effective_mean": float(baseline_snapshot.get("effective_mean", 0.0)),
        "effective_stddev": float(baseline_snapshot.get("effective_stddev", 0.0)),
        "uptime_seconds": uptime_seconds,
        "cpu_percent": _read_cpu_percent(),
        "memory_percent": _read_memory_percent(),
    }
