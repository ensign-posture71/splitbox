"""Каталоги коробки: сервисы для вебки и источники готовых наборов.

Каталоги лежат в образе (product/catalogs/), а не читаются из сети:
страница должна открываться и когда GitHub недоступен.
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

# В образе каталоги кладутся в /opt/splitbox/catalogs; при разработке
# берутся из репозитория относительно этого файла.
_CANDIDATES = (
    Path("/opt/splitbox/catalogs"),
    # при разработке: splitbox/ -> core/ -> product/catalogs
    Path(__file__).resolve().parent.parent.parent / "catalogs",
)


def _dir() -> Path:
    for c in _CANDIDATES:
        if (c / "services.yaml").exists():
            return c
    raise FileNotFoundError("каталоги не найдены ни в одном из известных мест")


@functools.lru_cache(maxsize=1)
def services() -> list[dict]:
    """Группы каталога: [{name, items: [{key, title, desc, default}]}]."""
    with open(_dir() / "services.yaml") as fh:
        return yaml.safe_load(fh)["groups"]


@functools.lru_cache(maxsize=1)
def sources() -> dict:
    """{'sources': {имя: {url, prefix}}, 'update_interval': '1d'}."""
    with open(_dir() / "sources.yaml") as fh:
        return yaml.safe_load(fh)


def default_policies() -> dict[str, str]:
    """Пресет онбординга: key -> политика, off не включается."""
    out = {}
    for group in services():
        for item in group["items"]:
            if item["default"] != "off":
                out[item["key"]] = item["default"]
    return out


def known_keys() -> set[str]:
    return {item["key"] for group in services() for item in group["items"]}
