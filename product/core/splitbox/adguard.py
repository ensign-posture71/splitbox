"""Bootstrap-конфиг AdGuard Home.

Генерируется один раз при первом запуске (splitbox.bootstrap): с готовым
файлом AdGuard стартует сразу рабочим, без мастера первичной настройки
на :3000 — нетехнарь не должен настраивать два продукта.

Дальше AdGuard живёт своим конфигом (сам его переписывает); splitbox его
больше не трогает, кроме тумблера защиты через API. Веб-интерфейс AdGuard
слушает только 127.0.0.1 внутри netns стека — наружу не виден.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import yaml

from .model import Config

API = "http://127.0.0.1:3000"

# schema_version намеренно старый из проверенных: AdGuard мигрирует старую
# схему вверх сам, а слишком новую от чужой версии — отвергает.
SCHEMA_VERSION = 20


def default_config(cfg: Config) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "http": {"address": "127.0.0.1:3000"},
        "users": [],
        "dns": {
            "bind_hosts": ["0.0.0.0"],
            "port": 53,
            "upstream_dns": list(cfg.dns.upstreams),
            "bootstrap_dns": ["1.1.1.1", "8.8.8.8"],
            "cache_size": 4194304,
        },
        "filtering": {
            "protection_enabled": cfg.dns.adblock,
            "filtering_enabled": cfg.dns.adblock,
        },
        "filters": [{
            "enabled": True,
            "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "name": "AdGuard DNS filter",
            "id": 1,
        }],
    }


def set_protection(enabled: bool, timeout: int = 5) -> bool:
    """Тумблер защиты через API AdGuard (без auth: users пуст, слушает
    только localhost внутри netns стека). False = AdGuard не ответил —
    не ошибка страницы: настройка сохранена в config.yaml и применится
    к bootstrap'у при пересоздании."""
    req = urllib.request.Request(
        f"{API}/control/protection",
        data=json.dumps({"enabled": enabled}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except OSError:
        return False


def protection_enabled(timeout: int = 5) -> bool | None:
    """None = AdGuard не отвечает."""
    try:
        with urllib.request.urlopen(f"{API}/control/status",
                                    timeout=timeout) as resp:
            return bool(json.load(resp).get("protection_enabled"))
    except (OSError, ValueError):
        return None


def write_if_missing(cfg: Config, conf_dir: Path) -> bool:
    """True — файл создан; False — уже был (AdGuard им владеет, не трогаем)."""
    path = conf_dir / "AdGuardHome.yaml"
    if path.exists():
        return False
    conf_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    with open(tmp, "w") as fh:
        yaml.safe_dump(default_config(cfg), fh, sort_keys=False)
    tmp.replace(path)
    return True
