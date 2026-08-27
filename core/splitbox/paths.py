"""Пути состояния коробки. Всё живёт на одном volume (STATE), поэтому
атомарный os.replace всегда работает — /tmp был бы другой файловой системой
(донорская грабля «Invalid cross-device link»)."""
from __future__ import annotations

import os
from pathlib import Path

STATE = Path(os.environ.get("SPLITBOX_STATE", "/var/lib/splitbox"))

CONFIG = STATE / "config.yaml"
RENDERED = STATE / "rendered"
SINGBOX_LIVE = RENDERED / "singbox.json"
SINGBOX_NEW = RENDERED / "singbox.json.new"
BACKUPS = RENDERED / "backup-outbounds.json"     # кэш refresh'а подписок
RUN = STATE / "run"
SUPERVISOR_SOCK = RUN / "gateway.sock"
