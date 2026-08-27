"""Bootstrap-конфиг AdGuard Home.

Генерируется один раз при первом запуске (splitbox.bootstrap): с готовым
файлом AdGuard стартует сразу рабочим, без мастера первичной настройки
на :3000 — нетехнарь не должен настраивать два продукта.

Дальше AdGuard живёт своим конфигом (сам его переписывает); splitbox его
больше не трогает, кроме тумблера защиты через API. Веб-интерфейс AdGuard
слушает только 127.0.0.1 внутри netns стека — наружу не виден.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .model import Config

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
