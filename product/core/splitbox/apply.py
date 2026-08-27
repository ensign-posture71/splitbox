"""Применение конфигурации: render -> check -> replace -> reload.

Порядок — прямое наследие донора и он критичен:
  1. новый конфиг собирается во временный файл РЯДОМ с боевым;
  2. проверяется штатным `sing-box check`;
  3. боевой файл заменяется ТОЛЬКО после успешной проверки (os.replace);
  4. контейнеру gateway отправляется команда перезапустить sing-box.

Опечатка в списке не должна ронять туннель: при неудачной проверке всё
остаётся как было, а ошибка возвращается вызывающему для показа в UI.

Сигнал gateway'ю идёт через unix-socket на общем volume, а НЕ через
docker.sock: веб-приложение не должно иметь власть над докером хоста.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess

from . import paths, render
from .model import Config


class ApplyError(Exception):
    pass


def load_backups() -> list[dict]:
    """Кэш последнего refresh'а подписок. Повреждённый файл = пустой резерв,
    а не падение: рендер честно деградирует fast->own."""
    if not paths.BACKUPS.exists():
        return []
    try:
        return json.loads(paths.BACKUPS.read_text())
    except json.JSONDecodeError:
        return []


def save_backups(outbounds: list[dict]) -> None:
    paths.RENDERED.mkdir(parents=True, exist_ok=True)
    tmp = paths.BACKUPS.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(outbounds, indent=2, ensure_ascii=False))
    tmp.replace(paths.BACKUPS)


def singbox_check(path) -> tuple[bool, str]:
    exe = shutil.which("sing-box")
    if not exe:
        raise ApplyError("бинарь sing-box не найден — образ собран неверно")
    r = subprocess.run([exe, "check", "-c", str(path)],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def signal_reload(timeout: float = 10.0) -> str:
    """Попросить супервизор gateway перезапустить sing-box."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(paths.SUPERVISOR_SOCK))
        s.sendall(b"reload\n")
        return s.recv(256).decode().strip()
    finally:
        s.close()


def apply(cfg: Config) -> str:
    """Вернёт человекочитаемый результат; кидает ApplyError с причиной."""
    paths.RENDERED.mkdir(parents=True, exist_ok=True)
    try:
        text = render.render_json(cfg, load_backups())
    except render.RenderError as exc:
        raise ApplyError(f"Сборка конфига не удалась: {exc}") from exc

    paths.SINGBOX_NEW.write_text(text)
    ok, out = singbox_check(paths.SINGBOX_NEW)
    if not ok:
        raise ApplyError("Конфиг не прошёл проверку, ничего не изменено:\n" + out)

    paths.SINGBOX_NEW.replace(paths.SINGBOX_LIVE)
    try:
        answer = signal_reload()
    except OSError as exc:
        raise ApplyError(
            "Конфиг записан, но gateway не ответил на команду перезапуска: "
            f"{exc}") from exc
    if answer != "ok":
        raise ApplyError(f"gateway отказался перезапускать sing-box: {answer}")
    return "Применено, sing-box перезапущен."
