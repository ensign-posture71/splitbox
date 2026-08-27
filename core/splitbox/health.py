"""Проверка туннеля БОЕВЫМ путём.

Наследие донора (O32, tunnel-health.sh): проверять надо результат, а не
признак — процесс sing-box может быть жив при мёртвом туннеле. Запрос идёт
через локальный socks-вход local-probe, а правило маршрутизации гонит всё
с него в туннель безусловно; поэтому успешный ответ означает «туннель
реально пропускает трафик наружу».

curl, а не python-сокеты: socks5h (резолв на стороне прокси) из stdlib
недоступен, а тянуть PySocks ради одной пробы не стоит — curl в образе
есть всегда.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
PROXY = "socks5h://127.0.0.1:1080"


@dataclass
class TunnelStatus:
    ok: bool
    exit_ip: str = ""
    country: str = ""
    error: str = ""


def probe_tunnel(timeout: int = 10) -> TunnelStatus:
    try:
        r = subprocess.run(
            ["curl", "-sS", "-4", "--proxy", PROXY,
             "--max-time", str(timeout), PROBE_URL],
            capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return TunnelStatus(ok=False, error=str(exc))
    if r.returncode != 0:
        return TunnelStatus(ok=False, error=r.stderr.strip()[:200])
    ip = country = ""
    for line in r.stdout.splitlines():
        if line.startswith("ip="):
            ip = line[3:]
        elif line.startswith("loc="):
            country = line[4:]
    return TunnelStatus(ok=True, exit_ip=ip, country=country)


def probe_dns(timeout: int = 5) -> bool:
    """AdGuard жив? Ручной DNS-запрос на 127.0.0.1:53 в общем netns —
    dig/resolvectl в минимальном образе может не быть."""
    import socket
    query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, ("127.0.0.1", 53))
        data, _ = s.recvfrom(512)
        return len(data) > 12 and data[:2] == b"\x12\x34"
    except OSError:
        return False
    finally:
        s.close()
