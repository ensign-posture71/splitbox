"""Наблюдение за живым трафиком sing-box и политика BitTorrent.

Первый шаг наблюдаемости: нормализуем живые соединения clash_api,
подсвечиваем подозрительный UDP и показываем фактическую политику пирa.
Полный журнал и телеметрия MikroTik будут позже; пока это UI-подсистема.
"""
from __future__ import annotations

import json
import urllib.request

from .model import Config

CLASH = "http://127.0.0.1:9090/connections"

# Порты не являются детектором, но полезны как подсказка в UI. Реальную
# enforcing-классификацию делает sing-box по протоколу; здесь она только
# помогает пользователю увидеть возможные торренты.
BITTORRENT_PORTS = {6771, 6881, 6882, 6883, 6884, 6885, 6886, 6887,
                    6888, 6889, 6969, 1337, 2710, 43428, 51413}
COMMON_UDP_PORTS = {53, 123, 443, 500, 4500, 51820, 51821}


def collect(timeout: int = 5) -> dict:
    """Вернуть живые соединения sing-box в нормализованном виде."""
    try:
        with urllib.request.urlopen(CLASH, timeout=timeout) as fh:
            data = json.loads(fh.readline() or b"{}")
    except (OSError, ValueError):
        return {"alive": False, "connections": [], "up_total": 0, "down_total": 0}

    rows = [row(c) for c in data.get("connections") or []]
    return {
        "alive": True,
        "connections": rows,
        "up_total": int(data.get("uploadTotal") or 0),
        "down_total": int(data.get("downloadTotal") or 0),
    }


def row(c: dict) -> dict:
    m = c.get("metadata") or {}
    metadata = {
        "source_ip": m.get("sourceIP") or "",
        "source_port": int(m.get("sourcePort") or 0),
        "destination_ip": m.get("destinationIP") or "",
        "destination_port": int(m.get("destinationPort") or 0),
        "protocol": (m.get("network") or "tcp").lower(),
        "host": (m.get("host") or "").lower(),
    }
    return {
        "id": str(c.get("id") or ""),
        **metadata,
        "outbound": (c.get("chains") or ["unknown"])[0],
        "up": int(c.get("upload") or 0),
        "down": int(c.get("download") or 0),
        "rule": " ".join(c.get("rule") or []) or "нет",
        **_classification(c, metadata),
    }


def _classification(c: dict, metadata: dict) -> dict:
    """Простая подсказка UI; не принимается за полный DPI-детектор."""
    if metadata["destination_port"] in BITTORRENT_PORTS:
        return {"category": "torrent", "confidence": "high"}
    if (metadata["protocol"] == "udp"
            and metadata["destination_ip"]
            and metadata["destination_port"] not in COMMON_UDP_PORTS):
        return {"category": "udp", "confidence": "suspicious"}
    return {"category": "unknown", "confidence": "unknown"}


def policy_for(ip: str, cfg: Config) -> str | None:
    """Вернуть политику внешнего WG-клиента, если IP известен как пир."""
    peer = cfg.peer_by_address(ip)
    return peer.torrent_policy.value if peer else None
