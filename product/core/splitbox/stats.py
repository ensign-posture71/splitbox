"""Сбор и хранение статистики трафика.

Источник данных — clash_api sing-box (`/connections`): он отдаёт живые
соединения с накопленными счётчиками, адресом клиента и цепочкой
маршрутизации. Сборщик опрашивает его каждые пару секунд, считает
приросты по каждому соединению и раскладывает их по корзинам.

Ограничение, которое стоит знать: видны только ЖИВЫЕ соединения.
Соединение, успевшее открыться и закрыться между двумя опросами, в
разбивку не попадёт. По объёму потери невелики (весь заметный трафик —
видео, загрузки, мессенджеры — живёт куда дольше пары секунд), но
короткий одиночный запрос в статистике может не появиться вовсе.

Хранилище — SQLite в томе состояния. Ни Prometheus, ни Grafana: коробка
должна работать на мини-ПК у человека, который не хочет знать слов
«time series database». Данные никуда не уходят.

Две глубины хранения, чтобы база не росла бесконечно:
  traffic        — поминутно, последние двое суток (для графика «сегодня»);
  traffic_hourly — по часам, весь срок хранения (для истории);
  hosts          — по часам, «кто куда ходил», отключается настройкой.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import sysstats

log = logging.getLogger("splitbox.stats")

CLASH = "http://127.0.0.1:9090/connections"
POLL_SEC = 2
MINUTE_KEEP_HOURS = 48

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS traffic(
  ts INTEGER NOT NULL, peer TEXT NOT NULL, outbound TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(ts, peer, outbound)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS traffic_hourly(
  ts INTEGER NOT NULL, peer TEXT NOT NULL, outbound TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(ts, peer, outbound)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hosts(
  ts INTEGER NOT NULL, peer TEXT NOT NULL, host TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(ts, peer, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS system(
  ts INTEGER PRIMARY KEY,
  cpu REAL NOT NULL DEFAULT 0,
  mem_used INTEGER NOT NULL DEFAULT 0, mem_total INTEGER NOT NULL DEFAULT 0,
  swap_used INTEGER NOT NULL DEFAULT 0, swap_total INTEGER NOT NULL DEFAULT 0,
  disk_used INTEGER NOT NULL DEFAULT 0, disk_total INTEGER NOT NULL DEFAULT 0,
  net_rx INTEGER NOT NULL DEFAULT 0, net_tx INTEGER NOT NULL DEFAULT 0,
  tcp INTEGER NOT NULL DEFAULT 0, udp INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
"""


def direction(outbound: str) -> str:
    """Куда ушло соединение — по тегу, который мы же и сгенерировали.

    own-*  — свой сервер, bk-* — сервер из подписки, direct — напрямую.
    """
    if outbound in ("direct", "") or outbound.startswith("direct"):
        return "direct"
    if outbound.startswith("own"):
        return "own"
    if outbound.startswith(("bk-", "fast")):
        return "fast"
    return "other"


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10)
    conn.executescript(SCHEMA)
    return conn


@dataclass
class Sample:
    peer: str
    outbound: str
    host: str
    up: int
    down: int


class Collector(threading.Thread):
    """Фоновый опрос clash_api. Живёт столько же, сколько веб-приложение.

    Падение опроса (sing-box перезапускается при каждом применении настроек)
    не должно ронять сборщик: соединения просто исчезают, счётчики
    начинаются заново.
    """

    def __init__(self, db_path: str | Path, resolve_peer, settings,
                 poll_sec: int = POLL_SEC):
        super().__init__(daemon=True)
        self.db_path = str(db_path)
        self.resolve_peer = resolve_peer      # IP -> человеческое имя
        self.settings = settings              # () -> model.Stats
        self.poll_sec = poll_sec
        self.seen: dict[str, tuple[int, int]] = {}
        self._stop = threading.Event()
        self._last_cleanup = 0.0
        self._sys = sysstats.SysCollector()
        self._last_sys = 0.0

    def stop(self) -> None:
        self._stop.set()

    # --- опрос ---------------------------------------------------------------

    def poll_once(self) -> list[Sample]:
        try:
            with urllib.request.urlopen(CLASH, timeout=5) as fh:
                data = json.loads(fh.readline() or b"{}")
        except (OSError, ValueError):
            self.seen.clear()      # sing-box перезапустился — счётчики с нуля
            return []

        out: list[Sample] = []
        alive: set[str] = set()
        for c in data.get("connections") or []:
            cid = str(c.get("id") or "")
            meta = c.get("metadata") or {}
            up, down = int(c.get("upload") or 0), int(c.get("download") or 0)
            prev_up, prev_down = self.seen.get(cid, (0, 0))
            # Отрицательный прирост означал бы переиспользованный id —
            # считаем такое соединение новым.
            d_up = up - prev_up if up >= prev_up else up
            d_down = down - prev_down if down >= prev_down else down
            self.seen[cid] = (up, down)
            alive.add(cid)
            if not d_up and not d_down:
                continue
            chains = c.get("chains") or ["unknown"]
            out.append(Sample(
                peer=self.resolve_peer(meta.get("sourceIP") or ""),
                outbound=chains[0],
                host=(meta.get("host") or meta.get("destinationIP") or "").lower(),
                up=d_up, down=d_down))
        for cid in list(self.seen):
            if cid not in alive:
                del self.seen[cid]
        return out

    # --- запись --------------------------------------------------------------

    def store(self, conn: sqlite3.Connection, samples: list[Sample],
              now: float, track_hosts: bool) -> None:
        minute = int(now // 60 * 60)
        hour = int(now // 3600 * 3600)
        with conn:
            for s in samples:
                for table, ts in (("traffic", minute), ("traffic_hourly", hour)):
                    conn.execute(
                        f"INSERT INTO {table}(ts, peer, outbound, up, down) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(ts, peer, outbound) "
                        "DO UPDATE SET up = up + excluded.up, "
                        "down = down + excluded.down",
                        (ts, s.peer, s.outbound, s.up, s.down))
                if track_hosts and s.host:
                    conn.execute(
                        "INSERT INTO hosts(ts, peer, host, up, down) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(ts, peer, host) "
                        "DO UPDATE SET up = up + excluded.up, "
                        "down = down + excluded.down",
                        (hour, s.peer, s.host, s.up, s.down))

    def cleanup(self, conn: sqlite3.Connection, now: float, keep_days: int) -> None:
        with conn:
            conn.execute("DELETE FROM traffic WHERE ts < ?",
                         (int(now - MINUTE_KEEP_HOURS * 3600),))
            edge = int(now - keep_days * 86400)
            conn.execute("DELETE FROM traffic_hourly WHERE ts < ?", (edge,))
            conn.execute("DELETE FROM hosts WHERE ts < ?", (edge,))
            conn.execute("DELETE FROM system WHERE ts < ?", (edge,))

    def run(self) -> None:
        conn = connect(self.db_path)
        try:
            while not self._stop.is_set():
                st = self.settings()
                if st.enabled:
                    now = time.time()
                    try:
                        self.store(conn, self.poll_once(), now, st.track_hosts)
                        # Системный срез — раз в минуту: чаще незачем,
                        # он и хранится с минутной гранулярностью.
                        if now - self._last_sys >= 60:
                            self._sys.store(conn, self._sys.snapshot(now))
                            self._last_sys = now
                        if now - self._last_cleanup > 3600:
                            self.cleanup(conn, now, st.keep_days)
                            self._last_cleanup = now
                    except sqlite3.Error as exc:
                        log.warning("статистика: запись не удалась: %s", exc)
                self._stop.wait(self.poll_sec)
        finally:
            conn.close()


# --- Запросы для дашборда ----------------------------------------------------

def _table_for(hours: int) -> tuple[str, int]:
    """Поминутные данные точнее, но живут двое суток; дальше — часовые."""
    return ("traffic", 60) if hours <= MINUTE_KEEP_HOURS else ("traffic_hourly", 3600)


def totals(conn: sqlite3.Connection, hours: int = 24) -> dict:
    table, _ = _table_for(hours)
    row = conn.execute(
        f"SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM {table} "
        "WHERE ts >= ?", (int(time.time() - hours * 3600),)).fetchone()
    return {"up": row[0], "down": row[1], "total": row[0] + row[1]}


def by_peer(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    table, _ = _table_for(hours)
    rows = conn.execute(
        f"SELECT peer, SUM(up), SUM(down) FROM {table} WHERE ts >= ? "
        "GROUP BY peer ORDER BY SUM(up)+SUM(down) DESC",
        (int(time.time() - hours * 3600),)).fetchall()
    return [{"peer": r[0], "up": r[1], "down": r[2], "total": r[1] + r[2]}
            for r in rows]


def by_outbound(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    table, _ = _table_for(hours)
    rows = conn.execute(
        f"SELECT outbound, SUM(up), SUM(down) FROM {table} WHERE ts >= ? "
        "GROUP BY outbound ORDER BY SUM(up)+SUM(down) DESC",
        (int(time.time() - hours * 3600),)).fetchall()
    return [{"outbound": r[0], "direction": direction(r[0]),
             "up": r[1], "down": r[2], "total": r[1] + r[2]} for r in rows]


def by_direction(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Сколько ушло своим сервером, сколько группой скорости, сколько мимо."""
    agg: dict[str, int] = {}
    for row in by_outbound(conn, hours):
        agg[row["direction"]] = agg.get(row["direction"], 0) + row["total"]
    order = ["own", "fast", "direct", "other"]
    return [{"direction": d, "total": agg[d]}
            for d in order if agg.get(d)]


def series(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Ряд для графика: (метка времени, отдано, принято)."""
    table, step = _table_for(hours)
    since = int(time.time() - hours * 3600)
    rows = conn.execute(
        f"SELECT ts, SUM(up), SUM(down) FROM {table} WHERE ts >= ? "
        "GROUP BY ts ORDER BY ts", (since,)).fetchall()
    return [{"ts": r[0], "up": r[1], "down": r[2]} for r in rows]


def top_hosts(conn: sqlite3.Connection, hours: int = 24, peer: str = "",
              limit: int = 25) -> list[dict]:
    since = int(time.time() - hours * 3600)
    sql = ("SELECT host, peer, SUM(up), SUM(down) FROM hosts WHERE ts >= ? ")
    args: list = [since]
    if peer:
        sql += "AND peer = ? "
        args.append(peer)
    sql += "GROUP BY host, peer ORDER BY SUM(up)+SUM(down) DESC LIMIT ?"
    args.append(limit)
    return [{"host": r[0], "peer": r[1], "up": r[2], "down": r[3],
             "total": r[2] + r[3]} for r in conn.execute(sql, args).fetchall()]


def known_peers(conn: sqlite3.Connection, hours: int = 24) -> list[str]:
    since = int(time.time() - hours * 3600)
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT peer FROM traffic_hourly WHERE ts >= ? ORDER BY peer",
        (since,)).fetchall()]


def human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"
