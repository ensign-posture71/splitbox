"""Первичная инициализация тома state — запускается init-сервисом compose
до старта adguard и app (`python -m splitbox.bootstrap`).

Идемпотентен: существующее не трогает. Создаёт каталоги и bootstrap-конфиг
AdGuard, чтобы тот поднялся рабочим без мастера настройки.
"""
from __future__ import annotations

import os

from . import adguard, paths, store
from .model import Mode


def main() -> None:
    paths.RENDERED.mkdir(parents=True, exist_ok=True)
    paths.RUN.mkdir(parents=True, exist_ok=True)
    cfg = store.load(paths.CONFIG)

    # Режим — свойство развёртывания (.env), а не настроек в вебке:
    # именно от него зависит, поднят ли tproxy-inbound в конфиге sing-box.
    # Без синхронизации коробка в lan-режиме рендерила vps-конфиг, порт
    # 7895 не слушался и перехваченный трафик уходил в никуда (учения).
    mode = Mode(os.environ.get("MODE", cfg.mode.value))
    if mode is not cfg.mode:
        print(f"[bootstrap] режим: {cfg.mode.value} -> {mode.value}")
        cfg.mode = mode
        store.save(cfg, paths.CONFIG)

    created = adguard.write_if_missing(cfg, paths.STATE / "adguard" / "conf")
    print(f"[bootstrap] state готов; AdGuardHome.yaml "
          f"{'создан' if created else 'уже был'}")


if __name__ == "__main__":
    main()
