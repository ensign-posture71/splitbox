"""Первичная инициализация тома state — запускается init-сервисом compose
до старта adguard и app (`python -m splitbox.bootstrap`).

Идемпотентен: существующее не трогает. Создаёт каталоги и bootstrap-конфиг
AdGuard, чтобы тот поднялся рабочим без мастера настройки.
"""
from __future__ import annotations

import os

import secrets

from . import adguard, paths, store, tls
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

    # Учётка AdGuard: его интерфейс управляет DNS всей сети, и оставлять
    # его без пароля, раз он слушает не только localhost, нельзя.
    if not cfg.adguard.password_bcrypt:
        plain = secrets.token_urlsafe(12)
        cfg.adguard.password_plain = plain
        cfg.adguard.password_bcrypt = adguard.make_password(plain)
        store.save(cfg, paths.CONFIG)
        print("[bootstrap] создана учётка AdGuard (пароль показан в панели)")

    tls.ensure_cert(paths.STATE / "tls",
                    [cfg.endpoint_host] if cfg.endpoint_host else [])

    conf_dir = paths.STATE / "adguard" / "conf"
    created = adguard.write_if_missing(cfg, conf_dir)
    if not created and adguard.ensure_access(cfg, conf_dir):
        print("[bootstrap] доступ к AdGuard приведён к настройкам "
              "(адрес и пароль)")
    print(f"[bootstrap] state готов; AdGuardHome.yaml "
          f"{'создан' if created else 'уже был'}")


if __name__ == "__main__":
    main()
