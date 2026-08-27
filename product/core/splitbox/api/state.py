"""Доступ веб-приложения к config.yaml: один замок на процесс.

Все изменения идут через update(): load -> мутация -> атомарный save.
Двух процессов, пишущих одновременно, в коробке нет (app — единственный
писатель), замок защищает от параллельных запросов внутри процесса.
"""
from __future__ import annotations

import threading
from collections.abc import Callable

from .. import paths, store
from ..model import Config

_lock = threading.Lock()


def get() -> Config:
    with _lock:
        return store.load(paths.CONFIG)


def update(fn: Callable[[Config], None]) -> Config:
    with _lock:
        cfg = store.load(paths.CONFIG)
        fn(cfg)
        store.save(cfg, paths.CONFIG)
        return cfg
