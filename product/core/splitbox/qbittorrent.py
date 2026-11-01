"""Клиент локального агента qBittorrent.

Агент работает на том же боксе, что и qBittorrent, и сам считает трафик
счётчиками qBittorrent. Splitbox ходит в этот агент по bearer-токену,
получая только агрегаты. Прямой BitTorrent-трафик в статистику sing-box
не попадает и не должен попадать — по требованию маршрутизации.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any


def configured() -> bool:
    return bool(os.getenv("QBITTORRENT_STATS_URL")
                and os.getenv("QBITTORRENT_STATS_TOKEN"))


def ui_url() -> str:
    return os.getenv("QBITTORRENT_WEB_UI_URL", "")


def fetch(hours: int = 24) -> dict[str, Any]:
    """Собрать агрегаты за период. Ошибки не поднимают исключение:
    страница статистики должна оставаться читаемой."""
    status: dict[str, Any] = {
        "configured": configured(),
        "available": False,
        "categories": [],
        "tags": [],
        "totals": {"up": 0, "down": 0, "total": 0},
        "current": {},
        "counts": {},
    }
    if not configured():
        status["error"] = "агент не настроен"
        return status

    base = os.environ["QBITTORRENT_STATS_URL"].rstrip("/")
    token = os.environ["QBITTORRENT_STATS_TOKEN"]
    timeout = float(os.getenv("QBITTORRENT_STATS_TIMEOUT", "5"))
    query = urllib.parse.urlencode({"hours": hours})
    url = f"{base}/api/v1/stats?{query}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        status["error"] = "агент недоступен"
        return status

    if not isinstance(data, dict):
        status["error"] = "неожиданный ответ агента"
        return status

    return {**status, **data, "configured": True,
            "available": bool(data.get("available"))}
