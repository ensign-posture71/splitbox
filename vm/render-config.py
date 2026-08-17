#!/usr/bin/env python3
"""Собирает боевой конфиг sing-box из шаблона и secrets/reality-vps.env.

Шаблон — валидный JSON. Пояснения хранятся в ключах "//..." (JSON их допускает,
sing-box — нет), поэтому перед выдачей они рекурсивно вырезаются.
Плейсхолдеры вида ${NAME} подставляются из env-файла; чисто числовые
значения приводятся к int, потому что sing-box ждёт число в server_port.

Пустые значения в env означают «поля быть не должно» — так реализовано
требование D10 не выставлять flow. Ключ с пустой подстановкой удаляется.

Использование:  ./render-config.py > config.json
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = os.path.join(ROOT, "secrets", "reality-vps.env")
TPL = os.path.join(ROOT, "vm", "sing-box", "config.template.json")

PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


def load_env(path):
    env = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def render(node, env):
    """Возвращает (значение, есть_ли_оно). Второе False — ключ надо выбросить."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k.startswith("//"):
                continue
            rendered, present = render(v, env)
            if present:
                out[k] = rendered
        return out, True
    if isinstance(node, list):
        return [render(v, env)[0] for v in node], True
    if isinstance(node, str):
        m = PLACEHOLDER.fullmatch(node)
        if m:
            name = m.group(1)
            if name not in env:
                sys.exit(f"ОШИБКА: в {ENV} нет переменной {name}")
            val = env[name]
            if val == "":
                return None, False
            return (int(val) if val.isdigit() else val), True
    return node, True


def main():
    env = load_env(ENV)
    with open(TPL) as fh:
        template = json.load(fh)

    cfg, _ = render(template, env)

    leftover = PLACEHOLDER.findall(json.dumps(cfg))
    if leftover:
        sys.exit(f"ОШИБКА: неподставленные плейсхолдеры: {sorted(set(leftover))}")

    json.dump(cfg, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
