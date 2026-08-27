"""Чтение и атомарная запись state/config.yaml.

Запись — во временный файл В ТОЙ ЖЕ директории и os.replace: /tmp может быть
другой файловой системой, и replace оттуда падает с «Invalid cross-device
link» (грабля донора vpn-ui.py). Прерванная запись не должна оставлять
обрезанный YAML — иначе следующая загрузка упадёт.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from .model import SCHEMA_VERSION, Config


def load(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        return Config()
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    data = migrate(data)
    return Config.model_validate(data)


def save(cfg: Config, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = cfg.model_dump(mode="json")
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as fh:
        yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)
    os.chmod(tmp, 0o600)             # в файле лежат ключи WG и хэш пароля
    os.replace(tmp, path)


def migrate(data: dict) -> dict:
    """Миграции схемы. Пока версия одна; каркас оставлен, чтобы обновление
    коробки никогда не требовало от пользователя править config.yaml руками."""
    version = data.get("schema_version", SCHEMA_VERSION)
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"config.yaml создан более новой версией коробки "
            f"(schema {version} > {SCHEMA_VERSION}) — обновите образ")
    data["schema_version"] = SCHEMA_VERSION
    return data
