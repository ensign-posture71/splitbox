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
SERVICES = os.path.join(ROOT, "sync", "abroad-services.list")
NETWORKS = os.path.join(ROOT, "sync", "abroad-networks.list")

PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


def load_services():
    """Список сервисов -> два массива для правила маршрутизации sing-box.

    Точное совпадение и суффикс задаются раздельно намеренно: голый
    domain_suffix="openai.com" совпал бы и с "myopenai.com". Точка впереди
    делает совпадение по границе метки.
    """
    domains = []
    with open(SERVICES) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                domains.append(line)
    domains = sorted(set(domains))
    return {
        "SERVICES_EXACT": domains,
        "SERVICES_SUFFIX": ["." + d for d in domains],
    }


def load_networks():
    """Подсети для протоколов без имени хоста (Telegram MTProto и подобные).

    Отдельным правилом, а не полем в правиле доменов: в sing-box условия
    внутри одного правила объединяются по И, поэтому domain и ip_cidr вместе
    требовали бы совпадения обоих сразу.
    """
    nets = []
    with open(NETWORKS) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                nets.append(line)
    return {"SERVICES_CIDR": sorted(set(nets))}


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
            if isinstance(val, list):
                # Подстановка массива (списки сервисов) — не строковое значение.
                return val, True
            if val == "":
                return None, False
            return (int(val) if val.isdigit() else val), True
    return node, True


def main():
    env = load_env(ENV)
    services = load_services()
    if not services["SERVICES_EXACT"]:
        sys.exit(f"ОШИБКА: {SERVICES} пуст — конфиг без списка сервисов "
                 "отправил бы весь трафик напрямую")
    env.update(services)
    env.update(load_networks())

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
