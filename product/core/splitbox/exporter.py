#!/usr/bin/env python3
"""Prometheus-экспортер трафика sing-box через clash_api.

Порт vm/container/singbox-exporter.py без изменений логики. Зачем свой:
официальная сборка sing-box идёт без v2ray_api, а clash_api отдаёт только
живые соединения без накопительных сумм по outbound. Экспортер опрашивает
/connections раз в POLL_SEC, копит дельты по каждому соединению и
раскладывает их по последнему элементу chains — конкретному outbound.

Байты, набежавшие между последним опросом и закрытием соединения, теряются —
осознанная цена простоты; при опросе в 2 с недоучёт незначим.

Метрики на :9550/metrics (слушает только внутри netns стека):
  singbox_outbound_upload_bytes_total{outbound=}
  singbox_outbound_download_bytes_total{outbound=}
  singbox_outbound_connections{outbound=}
  singbox_traffic_upload_bytes_total / download
  singbox_up                        1 = clash_api отвечает
"""
import json
import threading
import time
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLASH = "http://127.0.0.1:9090/connections"
LISTEN = ("127.0.0.1", 9550)
POLL_SEC = 2

lock = threading.Lock()
up_total = defaultdict(int)      # outbound -> bytes
down_total = defaultdict(int)
active = defaultdict(int)        # outbound -> живые соединения
global_up = 0
global_down = 0
api_up = 0
seen = {}                        # conn id -> (upload, download)


def outbound_of(conn):
    chains = conn.get("chains") or ["unknown"]
    # chains: [конечный outbound, ..., входная точка].
    return chains[0]


def poll_once():
    global global_up, global_down, api_up
    try:
        with urllib.request.urlopen(CLASH, timeout=5) as fh:
            data = json.load(fh)
    except Exception:
        with lock:
            api_up = 0
            active.clear()
        return
    conns = data.get("connections") or []
    with lock:
        api_up = 1
        global_up = data.get("uploadTotal", 0)
        global_down = data.get("downloadTotal", 0)
        active.clear()
        alive = set()
        for c in conns:
            cid = c.get("id")
            ob = outbound_of(c)
            u, d = c.get("upload", 0), c.get("download", 0)
            pu, pd = seen.get(cid, (0, 0))
            up_total[ob] += u - pu if u >= pu else u
            down_total[ob] += d - pd if d >= pd else d
            seen[cid] = (u, d)
            alive.add(cid)
            active[ob] += 1
        for cid in list(seen):
            if cid not in alive:
                del seen[cid]


def render_metrics():
    lines = [
        "# TYPE singbox_outbound_upload_bytes_total counter",
        "# TYPE singbox_outbound_download_bytes_total counter",
        "# TYPE singbox_outbound_connections gauge",
        "# TYPE singbox_traffic_upload_bytes_total counter",
        "# TYPE singbox_traffic_download_bytes_total counter",
        "# TYPE singbox_up gauge",
    ]
    with lock:
        for ob in sorted(set(up_total) | set(down_total)):
            lines.append(f'singbox_outbound_upload_bytes_total{{outbound="{ob}"}} {up_total[ob]}')
            lines.append(f'singbox_outbound_download_bytes_total{{outbound="{ob}"}} {down_total[ob]}')
        for ob, n in sorted(active.items()):
            lines.append(f'singbox_outbound_connections{{outbound="{ob}"}} {n}')
        lines.append(f"singbox_traffic_upload_bytes_total {global_up}")
        lines.append(f"singbox_traffic_download_bytes_total {global_down}")
        lines.append(f"singbox_up {api_up}")
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = render_metrics().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    server = ThreadingHTTPServer(LISTEN, Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        poll_once()
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
