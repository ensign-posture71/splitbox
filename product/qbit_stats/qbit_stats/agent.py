#!/usr/bin/env python3
"""Локальный сборщик статистики qBittorrent.

Сервис запускается на том же хосте, что и qBittorrent, опрашивает только
loopback API и публикует небольшой read-only HTTP API для Splitbox.

Что сохраняется: глобальные счётчики, скорость, число торрентов и агрегаты
по категориям/меткам. Названия, magnet-ссылки, трекеры и пути не читаются
из API и не попадают в базу.
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import secrets
import signal
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
MAX_HOURS = 24 * 90
EMPTY_CATEGORY = "Без категории"
EMPTY_TAG = "Без метки"
UNKNOWN_CATEGORY = "Не определено"

log = logging.getLogger("qbit-stats")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS samples(
  ts INTEGER PRIMARY KEY,
  status TEXT NOT NULL,
  up_speed INTEGER NOT NULL DEFAULT 0,
  down_speed INTEGER NOT NULL DEFAULT 0,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  session_up INTEGER NOT NULL DEFAULT 0,
  session_down INTEGER NOT NULL DEFAULT 0,
  alltime_up INTEGER NOT NULL DEFAULT 0,
  alltime_down INTEGER NOT NULL DEFAULT 0,
  connections INTEGER NOT NULL DEFAULT 0,
  dht_nodes INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 0,
  downloading INTEGER NOT NULL DEFAULT 0,
  seeding INTEGER NOT NULL DEFAULT 0,
  seen_24h INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS breakdown(
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(ts, kind, label)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS metadata(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
"""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    qbit_url: str = "http://127.0.0.1:8090"
    db_path: str = "/var/lib/qbit-stats/stats.db"
    listen: str = "127.0.0.1"
    port: int = 8092
    token: str = ""
    poll_sec: int = 60
    keep_days: int = 90
    qbit_timeout: float = 10.0

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.environ.get("QBIT_STATS_TOKEN", "").strip()
        if len(token) < 24:
            raise ValueError("QBIT_STATS_TOKEN должен содержать не менее 24 символов")
        poll_sec = max(15, _env_int("QBIT_STATS_POLL_SEC", 60))
        keep_days = max(1, _env_int("QBIT_STATS_KEEP_DAYS", 90))
        port = min(max(_env_int("QBIT_STATS_PORT", 8092), 1024), 65535)
        return cls(
            qbit_url=os.environ.get("QBIT_URL", cls.qbit_url).rstrip("/"),
            db_path=os.environ.get("QBIT_STATS_DB", cls.db_path),
            listen=os.environ.get("QBIT_STATS_LISTEN", cls.listen),
            port=port,
            token=token,
            poll_sec=poll_sec,
            keep_days=keep_days,
            qbit_timeout=max(1.0, _env_float("QBIT_TIMEOUT", 10.0)),
        )


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


@dataclass(frozen=True)
class TorrentCounter:
    identity: str
    category: str
    tags: tuple[str, ...]
    up: int
    down: int
    state: str
    up_speed: int
    down_speed: int
    last_activity: int


@dataclass(frozen=True)
class QbitSnapshot:
    status: str
    up_speed: int
    down_speed: int
    session_up: int
    session_down: int
    alltime_up: int
    alltime_down: int
    connections: int
    dht_nodes: int
    torrents: tuple[TorrentCounter, ...]
    version: str = ""


@dataclass
class Aggregate:
    up: int = 0
    down: int = 0
    categories: dict[str, tuple[int, int]] = field(default_factory=dict)
    tags: dict[str, tuple[int, int]] = field(default_factory=dict)
    active: int = 0
    downloading: int = 0
    seeding: int = 0
    seen_24h: int = 0


class QbitClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._version = ""
        self._version_at = 0.0

    def _get_json(self, path: str) -> Any:
        req = urllib.request.Request(
            self.base_url + path,
            headers={"Accept": "application/json", "User-Agent": f"qbit-stats/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            return json.load(response)

    def version(self) -> str:
        now = time.time()
        if self._version and now - self._version_at < 3600:
            return self._version
        try:
            value = self._get_json("/api/v2/app/version")
            self._version = str(value)[:80]
            self._version_at = now
        except (OSError, ValueError, TypeError):
            pass
        return self._version

    def snapshot(self) -> QbitSnapshot:
        data = self._get_json("/api/v2/sync/maindata")
        if not isinstance(data, dict):
            raise ValueError("qBittorrent вернул неожиданный JSON")
        state = data.get("server_state") or {}
        if not isinstance(state, dict):
            state = {}

        torrents: list[TorrentCounter] = []
        raw_torrents = data.get("torrents") or {}
        if isinstance(raw_torrents, dict):
            for identity, raw in raw_torrents.items():
                if not isinstance(raw, dict):
                    continue
                tags = tuple(
                    tag.strip()[:80]
                    for tag in str(raw.get("tags") or "").split(",")
                    if tag.strip()
                )[:20]
                torrents.append(TorrentCounter(
                    identity=str(identity),
                    category=(str(raw.get("category") or "").strip()[:80]
                              or EMPTY_CATEGORY),
                    tags=tags,
                    up=max(0, int(raw.get("uploaded") or 0)),
                    down=max(0, int(raw.get("downloaded") or 0)),
                    state=str(raw.get("state") or "")[:40],
                    up_speed=max(0, int(raw.get("upspeed") or 0)),
                    down_speed=max(0, int(raw.get("dlspeed") or 0)),
                    last_activity=max(0, int(raw.get("last_activity") or 0)),
                ))

        return QbitSnapshot(
            status=str(state.get("connection_status") or "unknown")[:40],
            up_speed=max(0, int(state.get("up_info_speed") or 0)),
            down_speed=max(0, int(state.get("dl_info_speed") or 0)),
            session_up=max(0, int(state.get("up_info_data") or 0)),
            session_down=max(0, int(state.get("dl_info_data") or 0)),
            alltime_up=max(0, int(state.get("alltime_ul") or 0)),
            alltime_down=max(0, int(state.get("alltime_dl") or 0)),
            connections=max(0, int(state.get("total_peer_connections") or 0)),
            dht_nodes=max(0, int(state.get("dht_nodes") or 0)),
            torrents=tuple(torrents),
            version=self.version(),
        )


def counter_delta(current: int, previous: int | None) -> int:
    """Прирост накопительного счётчика; сброс считается новым стартом."""
    if previous is None or current < previous:
        return max(0, current)
    return max(0, current - previous)


class DeltaTracker:
    """Считает приросты и раскладывает их только по разрешённым агрегатам."""

    def __init__(self) -> None:
        self._previous_alltime: tuple[int, int] | None = None
        self._previous_torrents: dict[str, TorrentCounter] = {}
        self._initialized = False

    @staticmethod
    def _add(bucket: dict[str, tuple[int, int]], label: str,
             up: int, down: int) -> None:
        if not up and not down:
            return
        old_up, old_down = bucket.get(label, (0, 0))
        bucket[label] = (old_up + up, old_down + down)

    def add(self, snapshot: QbitSnapshot, now: float) -> Aggregate:
        previous_alltime = self._previous_alltime
        if previous_alltime is None:
            up_total = down_total = 0
        else:
            up_total = counter_delta(snapshot.alltime_up, previous_alltime[0])
            down_total = counter_delta(snapshot.alltime_down, previous_alltime[1])

        categories: dict[str, tuple[int, int]] = {}
        tag_totals: dict[str, tuple[int, int]] = {}
        next_torrents: dict[str, TorrentCounter] = {}
        active = downloading = seeding = seen_24h = 0
        activity_edge = int(now - 86400)

        for torrent in snapshot.torrents:
            next_torrents[torrent.identity] = torrent
            previous = self._previous_torrents.get(torrent.identity)
            if previous is None:
                # На первом срезе после установки история неизвестна. Новый
                # торрент на последующих срезах уже можно отнести к категории.
                up = torrent.up if self._initialized else 0
                down = torrent.down if self._initialized else 0
            else:
                up = counter_delta(torrent.up, previous.up)
                down = counter_delta(torrent.down, previous.down)

            self._add(categories, torrent.category, up, down)
            if torrent.tags:
                for tag in torrent.tags:
                    self._add(tag_totals, tag, up, down)
            else:
                self._add(tag_totals, EMPTY_TAG, up, down)

            if torrent.up_speed or torrent.down_speed:
                active += 1
            if torrent.down_speed:
                downloading += 1
            if torrent.up_speed:
                seeding += 1
            if torrent.last_activity >= activity_edge:
                seen_24h += 1

        attributed_up = sum(value[0] for value in categories.values())
        attributed_down = sum(value[1] for value in categories.values())
        # Удалённый между опросами торрент не попадёт в разбивку, но общий
        # счётчик qBittorrent его уже учёл. Остаток сохраняем отдельно,
        # чтобы сумма категорий не расходилась с итогом периода.
        self._add(categories, UNKNOWN_CATEGORY,
                  up_total - attributed_up, down_total - attributed_down)

        self._previous_alltime = (snapshot.alltime_up, snapshot.alltime_down)
        self._previous_torrents = next_torrents
        self._initialized = True
        return Aggregate(
            up=up_total,
            down=down_total,
            categories=categories,
            tags=tag_totals,
            active=active,
            downloading=downloading,
            seeding=seeding,
            seen_24h=seen_24h,
        )


def _meta_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def store_snapshot(conn: sqlite3.Connection, snapshot: QbitSnapshot,
                   aggregate: Aggregate, now: float) -> None:
    ts = int(now // 60 * 60)
    with conn:
        conn.execute(
            "INSERT INTO samples("
            "ts, status, up_speed, down_speed, up, down, session_up, session_down, "
            "alltime_up, alltime_down, connections, dht_nodes, total, active, "
            "downloading, seeding, seen_24h) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(ts) DO UPDATE SET "
            "status=excluded.status, up_speed=excluded.up_speed, "
            "down_speed=excluded.down_speed, up=samples.up+excluded.up, "
            "down=samples.down+excluded.down, session_up=excluded.session_up, "
            "session_down=excluded.session_down, alltime_up=excluded.alltime_up, "
            "alltime_down=excluded.alltime_down, connections=excluded.connections, "
            "dht_nodes=excluded.dht_nodes, total=excluded.total, "
            "active=excluded.active, downloading=excluded.downloading, "
            "seeding=excluded.seeding, seen_24h=excluded.seen_24h",
            (ts, snapshot.status, snapshot.up_speed, snapshot.down_speed,
             aggregate.up, aggregate.down, snapshot.session_up,
             snapshot.session_down, snapshot.alltime_up, snapshot.alltime_down,
             snapshot.connections, snapshot.dht_nodes, len(snapshot.torrents),
             aggregate.active, aggregate.downloading, aggregate.seeding,
             aggregate.seen_24h),
        )
        for kind, values in (("category", aggregate.categories),
                             ("tag", aggregate.tags)):
            for label, (up, down) in values.items():
                conn.execute(
                    "INSERT INTO breakdown(ts, kind, label, up, down) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(ts, kind, label) DO UPDATE SET "
                    "up=breakdown.up+excluded.up, down=breakdown.down+excluded.down",
                    (ts, kind, label, up, down),
                )
        _meta_set(conn, "last_success", str(int(now)))
        _meta_set(conn, "last_error", "")
        if snapshot.version:
            _meta_set(conn, "qbit_version", snapshot.version)


def cleanup(conn: sqlite3.Connection, now: float, keep_days: int) -> None:
    edge = int(now - max(1, keep_days) * 86400)
    with conn:
        conn.execute("DELETE FROM samples WHERE ts < ?", (edge,))
        conn.execute("DELETE FROM breakdown WHERE ts < ?", (edge,))


class Collector(threading.Thread):
    def __init__(self, settings: Settings, client: QbitClient | None = None):
        super().__init__(name="qbit-collector", daemon=True)
        self.settings = settings
        self.client = client or QbitClient(settings.qbit_url, settings.qbit_timeout)
        self.tracker = DeltaTracker()
        self.stop_event = threading.Event()
        self._last_cleanup = 0.0

    def stop(self) -> None:
        self.stop_event.set()

    def poll_once(self) -> QbitSnapshot:
        snapshot = self.client.snapshot()
        now = time.time()
        aggregate = self.tracker.add(snapshot, now)
        conn = connect(self.settings.db_path)
        try:
            store_snapshot(conn, snapshot, aggregate, now)
            if now - self._last_cleanup > 3600:
                cleanup(conn, now, self.settings.keep_days)
                self._last_cleanup = now
        finally:
            conn.close()
        return snapshot

    def _store_error(self, exc: Exception) -> None:
        try:
            conn = connect(self.settings.db_path)
            try:
                with conn:
                    _meta_set(conn, "last_error",
                              f"{type(exc).__name__}: {str(exc)[:240]}")
            finally:
                conn.close()
        except sqlite3.Error:
            log.exception("не удалось сохранить ошибку qBittorrent")

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.poll_once()
            except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
                log.warning("опрос qBittorrent не удался: %s", exc)
                self._store_error(exc)
            self.stop_event.wait(self.settings.poll_sec)


def _latest(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM samples ORDER BY ts DESC LIMIT 1").fetchone()


def _meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else default


def query_stats(conn: sqlite3.Connection, hours: int, poll_sec: int = 60) -> dict:
    hours = min(max(int(hours), 1), MAX_HOURS)
    now = int(time.time())
    since = now - hours * 3600
    row = conn.execute(
        "SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) "
        "FROM samples WHERE ts >= ?", (since,)
    ).fetchone()
    up, down = int(row[0]), int(row[1])

    step = 60 if hours <= 48 else 3600
    series_rows = conn.execute(
        "SELECT (ts / ?) * ? AS bucket, SUM(up), SUM(down) "
        "FROM samples WHERE ts >= ? GROUP BY bucket ORDER BY bucket",
        (step, step, since),
    ).fetchall()
    series = [{"ts": int(r[0]), "up": int(r[1]), "down": int(r[2])}
              for r in series_rows]

    breakdown: dict[str, list[dict]] = {"category": [], "tag": []}
    for kind in ("category", "tag"):
        rows = conn.execute(
            "SELECT label, SUM(up), SUM(down) FROM breakdown "
            "WHERE kind=? AND ts >= ? GROUP BY label "
            "ORDER BY SUM(up)+SUM(down) DESC LIMIT 30",
            (kind, since),
        ).fetchall()
        breakdown[kind] = [
            {"label": r[0], "up": int(r[1]), "down": int(r[2]),
             "total": int(r[1]) + int(r[2])}
            for r in rows
        ]

    current_row = _latest(conn)
    if current_row:
        current = {
            "status": current_row["status"],
            "up_speed": int(current_row["up_speed"]),
            "down_speed": int(current_row["down_speed"]),
            "connections": int(current_row["connections"]),
            "dht_nodes": int(current_row["dht_nodes"]),
        }
        counts = {
            "total": int(current_row["total"]),
            "active": int(current_row["active"]),
            "downloading": int(current_row["downloading"]),
            "seeding": int(current_row["seeding"]),
            "seen_24h": int(current_row["seen_24h"]),
        }
        alltime = {
            "up": int(current_row["alltime_up"]),
            "down": int(current_row["alltime_down"]),
        }
        last_sample_at = int(current_row["ts"])
    else:
        current = {"status": "unknown", "up_speed": 0, "down_speed": 0,
                   "connections": 0, "dht_nodes": 0}
        counts = {"total": 0, "active": 0, "downloading": 0,
                  "seeding": 0, "seen_24h": 0}
        alltime = {"up": 0, "down": 0}
        last_sample_at = 0

    age = max(0, now - last_sample_at) if last_sample_at else None
    max_age = max(180, poll_sec * 3)
    return {
        "available": bool(last_sample_at and age is not None and age <= max_age),
        "generated_at": now,
        "period_hours": hours,
        "last_sample_at": last_sample_at,
        "sample_age_sec": age,
        "poll_sec": poll_sec,
        "totals": {"up": up, "down": down, "total": up + down},
        "current": current,
        "counts": counts,
        "alltime": alltime,
        "categories": breakdown["category"],
        "tags": breakdown["tag"],
        "series": series,
        "qbit_version": _meta(conn, "qbit_version"),
        "last_error": _meta(conn, "last_error"),
        "agent_version": VERSION,
    }


class StatsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], settings: Settings):
        self.settings = settings
        super().__init__(address, StatsHandler)


class StatsHandler(BaseHTTPRequestHandler):
    server_version = f"qbit-stats/{VERSION}"
    sys_version = ""

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.settings.token}"
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(expected, supplied)

    def do_GET(self) -> None:  # noqa: N802 — имя метода HTTP-сервера
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self._json(200, {"ok": True, "agent_version": VERSION})
            return
        if parsed.path != "/api/v1/stats":
            self._json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        try:
            hours = int(urllib.parse.parse_qs(parsed.query).get("hours", ["24"])[0])
        except ValueError:
            hours = 24
        try:
            path = self.server.settings.db_path
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                payload = query_stats(conn, hours, self.server.settings.poll_sec)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            log.warning("чтение статистики не удалось: %s", exc)
            self._json(503, {"error": "stats unavailable"})
            return
        self._json(200, payload)

    def log_message(self, fmt: str, *args) -> None:
        log.info("http %s %s", self.client_address[0], fmt % args)


def run_server(settings: Settings, collector: Collector | None = None) -> None:
    conn = connect(settings.db_path)
    conn.close()
    worker = collector or Collector(settings)
    worker.start()
    server = StatsHTTPServer((settings.listen, settings.port), settings)

    def stop(_signum=None, _frame=None):
        worker.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        log.info("агент слушает %s:%d, qBittorrent: %s",
                 settings.listen, settings.port, settings.qbit_url)
        server.serve_forever(poll_interval=0.5)
    finally:
        worker.stop()
        server.server_close()
        worker.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Учёт qBittorrent для Splitbox")
    parser.add_argument("--check", action="store_true",
                        help="проверить настройки и локальный API, затем выйти")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    if args.check:
        snapshot = QbitClient(settings.qbit_url, settings.qbit_timeout).snapshot()
        print(json.dumps({
            "qbit_version": snapshot.version,
            "status": snapshot.status,
            "torrents": len(snapshot.torrents),
            "categories": len({t.category for t in snapshot.torrents}),
        }, ensure_ascii=False))
        return 0
    run_server(settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
