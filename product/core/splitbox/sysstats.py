"""Метрики самой машины: процессор, память, диск, сеть, соединения.

Читается напрямую из /proc и statvfs — ни psutil, ни внешних агентов.
В контейнере /proc показывает хозяйскую машину (в LXC — контейнерную,
благодаря lxcfs), то есть ровно то, что человек считает «своей коробкой».

Мгновенные величины (сколько занято сейчас) считаются на лету при
открытии страницы; история для графиков копится в той же базе, что и
трафик, — раз в минуту одной строкой.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

PROC = Path("/proc")

SCHEMA = """
CREATE TABLE IF NOT EXISTS system(
  ts INTEGER PRIMARY KEY,
  cpu REAL NOT NULL DEFAULT 0,
  mem_used INTEGER NOT NULL DEFAULT 0,
  mem_total INTEGER NOT NULL DEFAULT 0,
  swap_used INTEGER NOT NULL DEFAULT 0,
  swap_total INTEGER NOT NULL DEFAULT 0,
  disk_used INTEGER NOT NULL DEFAULT 0,
  disk_total INTEGER NOT NULL DEFAULT 0,
  net_rx INTEGER NOT NULL DEFAULT 0,
  net_tx INTEGER NOT NULL DEFAULT 0,
  tcp INTEGER NOT NULL DEFAULT 0,
  udp INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
"""


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


# --- мгновенные показатели ---------------------------------------------------

def cpu_times() -> tuple[int, int]:
    """(занято, всего) из первой строки /proc/stat."""
    line = _read(PROC / "stat").split("\n", 1)[0]
    parts = [int(x) for x in line.split()[1:] if x.isdigit()]
    if not parts:
        return 0, 0
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    total = sum(parts)
    return total - idle, total


def meminfo() -> dict[str, int]:
    out = {}
    for line in _read(PROC / "meminfo").splitlines():
        key, _, rest = line.partition(":")
        val = rest.strip().split(" ")[0]
        if val.isdigit():
            out[key] = int(val) * 1024        # kB -> байты
    return out


def memory() -> dict[str, int]:
    m = meminfo()
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    swap_total = m.get("SwapTotal", 0)
    swap_free = m.get("SwapFree", 0)
    return {
        "mem_total": total, "mem_used": max(total - avail, 0),
        "swap_total": swap_total, "swap_used": max(swap_total - swap_free, 0),
    }


def disk(path: str = "/") -> dict[str, int]:
    try:
        st = os.statvfs(path)
    except OSError:
        return {"disk_total": 0, "disk_used": 0, "disk_free": 0}
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return {"disk_total": total, "disk_used": total - free, "disk_free": free}


def net_counters() -> tuple[int, int]:
    """Суммарные байты по всем интерфейсам, кроме локальной петли."""
    rx = tx = 0
    for line in _read(PROC / "net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo" or not rest:
            continue
        f = rest.split()
        if len(f) >= 9:
            rx += int(f[0])
            tx += int(f[8])
    return rx, tx


def sockets() -> dict[str, int]:
    """Открытые сокеты. Считаем строки в /proc/net/*, минус заголовок."""
    def count(name: str) -> int:
        lines = _read(PROC / "net" / name).splitlines()
        return max(len(lines) - 1, 0)
    tcp = count("tcp") + count("tcp6")
    udp = count("udp") + count("udp6")
    return {"tcp": tcp, "udp": udp, "total": tcp + udp}


def uptime_seconds() -> float:
    raw = _read(PROC / "uptime").split()
    return float(raw[0]) if raw else 0.0


def cpu_model() -> dict:
    """Ядра и частота — чтобы человек понимал, на чём это крутится."""
    info = {"cores": os.cpu_count() or 1, "mhz": 0.0, "model": ""}
    for line in _read(PROC / "cpuinfo").splitlines():
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "model name" and not info["model"]:
            info["model"] = val
        elif key == "cpu MHz" and not info["mhz"]:
            try:
                info["mhz"] = float(val)
            except ValueError:
                pass
    return info


def self_process() -> dict:
    """Сколько ест сама панель — в железных цифрах, а не на глаз."""
    out = {"rss": 0, "threads": 0}
    for line in _read(PROC / "self/status").splitlines():
        if line.startswith("VmRSS:"):
            out["rss"] = int(line.split()[1]) * 1024
        elif line.startswith("Threads:"):
            out["threads"] = int(line.split()[1])
    return out


def addresses() -> list[str]:
    """Адреса машины (IPv4), кроме петли и докеровских мостов."""
    import socket
    out: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
            ip = info[4][0]
            if ip.startswith(("127.", "172.17.", "172.18.")) or ip in out:
                continue
            out.append(ip)
    except OSError:
        pass
    return out


# --- сбор истории ------------------------------------------------------------

@dataclass
class SysCollector:
    """Раз в минуту складывает срез в базу. Загрузка процессора и скорость
    сети считаются как приросты между вызовами — иначе это были бы
    показания «с момента загрузки», бесполезные для графика."""

    prev_cpu: tuple[int, int] = (0, 0)
    prev_net: tuple[int, int] = (0, 0)
    prev_at: float = 0.0

    def snapshot(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        busy, total = cpu_times()
        rx, tx = net_counters()
        d_busy = busy - self.prev_cpu[0]
        d_total = total - self.prev_cpu[1]
        elapsed = max(now - self.prev_at, 1e-6) if self.prev_at else 0
        cpu = (100.0 * d_busy / d_total) if d_total > 0 else 0.0
        rate_rx = (rx - self.prev_net[0]) / elapsed if elapsed else 0
        rate_tx = (tx - self.prev_net[1]) / elapsed if elapsed else 0
        self.prev_cpu, self.prev_net, self.prev_at = (busy, total), (rx, tx), now

        row = {"ts": int(now // 60 * 60), "cpu": round(max(cpu, 0.0), 2)}
        row.update(memory())
        row.update({k: v for k, v in disk("/var/lib/splitbox").items()
                    if k != "disk_free"})
        row["net_rx"] = int(max(rate_rx, 0))
        row["net_tx"] = int(max(rate_tx, 0))
        s = sockets()
        row["tcp"], row["udp"] = s["tcp"], s["udp"]
        return row

    def store(self, conn, row: dict) -> None:
        conn.execute(SCHEMA)
        with conn:
            conn.execute(
                "INSERT INTO system(ts, cpu, mem_used, mem_total, swap_used, "
                "swap_total, disk_used, disk_total, net_rx, net_tx, tcp, udp) "
                "VALUES(:ts,:cpu,:mem_used,:mem_total,:swap_used,:swap_total,"
                ":disk_used,:disk_total,:net_rx,:net_tx,:tcp,:udp) "
                "ON CONFLICT(ts) DO UPDATE SET cpu=excluded.cpu, "
                "mem_used=excluded.mem_used, swap_used=excluded.swap_used, "
                "disk_used=excluded.disk_used, net_rx=excluded.net_rx, "
                "net_tx=excluded.net_tx, tcp=excluded.tcp, udp=excluded.udp",
                row)


def history(conn, hours: int = 24) -> list[dict]:
    conn.execute(SCHEMA)
    since = int(time.time() - hours * 3600)
    cols = ("ts", "cpu", "mem_used", "mem_total", "swap_used", "swap_total",
            "disk_used", "disk_total", "net_rx", "net_tx", "tcp", "udp")
    rows = conn.execute(
        f"SELECT {', '.join(cols)} FROM system WHERE ts >= ? ORDER BY ts",
        (since,)).fetchall()
    return [dict(zip(cols, r)) for r in rows]


def summary(conn, hours: int = 24) -> dict:
    """Текущее состояние плюс среднее и пик за период — как на панелях
    мониторинга: одно число без контекста ни о чём не говорит."""
    now = memory()
    now.update(disk("/var/lib/splitbox"))
    now.update(sockets())
    now["cpu_info"] = cpu_model()
    now["uptime"] = uptime_seconds()
    now["process"] = self_process()
    now["addresses"] = addresses()

    rows = history(conn, hours)
    def stat(key: str) -> dict:
        vals = [r[key] for r in rows if r.get(key) is not None]
        return {"avg": sum(vals) / len(vals) if vals else 0,
                "peak": max(vals) if vals else 0}
    now["cpu"] = rows[-1]["cpu"] if rows else 0.0
    now["cpu_stat"] = stat("cpu")
    now["mem_stat"] = stat("mem_used")
    now["swap_stat"] = stat("swap_used")
    now["disk_stat"] = stat("disk_used")
    now["net_rx_stat"] = stat("net_rx")
    now["net_tx_stat"] = stat("net_tx")
    now["history"] = rows
    return now


def human_uptime(seconds: float) -> str:
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}д {h}ч"
    if h:
        return f"{h}ч {m}м"
    return f"{m}м"
