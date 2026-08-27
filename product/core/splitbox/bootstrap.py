"""Первичная инициализация тома state — запускается init-сервисом compose
до старта adguard и app (`python -m splitbox.bootstrap`).

Идемпотентен: существующее не трогает. Создаёт каталоги и bootstrap-конфиг
AdGuard, чтобы тот поднялся рабочим без мастера настройки.
"""
from __future__ import annotations

from . import adguard, paths, store


def main() -> None:
    paths.RENDERED.mkdir(parents=True, exist_ok=True)
    paths.RUN.mkdir(parents=True, exist_ok=True)
    cfg = store.load(paths.CONFIG)
    created = adguard.write_if_missing(cfg, paths.STATE / "adguard" / "conf")
    print(f"[bootstrap] state готов; AdGuardHome.yaml "
          f"{'создан' if created else 'уже был'}")


if __name__ == "__main__":
    main()
