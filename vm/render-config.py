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
BACKUP = os.path.join(ROOT, "vm", "sing-box", "backup-outbounds.json")
NETWORKS = os.path.join(ROOT, "sync", "abroad-networks.list")
RULESETS = os.path.join(ROOT, "sync", "rulesets.list")

# Источники готовых наборов. sing-box скачивает их сам по update_interval.
#
# vernette   — заточен под Россию: «недоступно из РФ», реестр РКН и сервисы
#              с учётом местной специфики. Содержит и домены, и подсети,
#              поэтому покрывает протоколы без SNI (Telegram MTProto).
# metacubex  — meta-rules-dat, ~4.7k звёзд. Глобальный посервисный каталог,
#              сотни наборов. Берётся ради гранулярности: отдельно Netflix,
#              отдельно Steam, отдельно apple-music и apple-update.
#
# В rulesets.list запись имеет вид «источник:набор».
SOURCES = {
    "vernette": ("https://raw.githubusercontent.com/vernette/rulesets/master/srs/{}.srs", "vr"),
    "metacubex": ("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/{}.srs", "mc"),
}
RULESET_UPDATE = "1d"

PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


def read_policy_list(path):
    """Файл вида «значение [own|fast]» -> {'own': [...], 'fast': [...]}.

    Политика на каждой строке, а не на файле целиком: у ручных записей она
    так же разная, как у готовых наборов. Умолчание own — свой сервер
    безопаснее чужого, поэтому попадание в общую группу должно быть
    явным решением.
    """
    out = {"own": [], "fast": []}
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            policy = parts[1] if len(parts) > 1 else "own"
            if policy not in out:
                sys.exit(f"ОШИБКА: неизвестная политика '{policy}' в {path}")
            out[policy].append(parts[0].lower())
    return {k: sorted(set(v)) for k, v in out.items()}


def load_services():
    """Свои домены -> массивы для правил маршрутизации sing-box.

    Точное совпадение и суффикс задаются раздельно намеренно: голый
    domain_suffix="openai.com" совпал бы и с "myopenai.com". Точка впереди
    делает совпадение по границе метки.
    """
    by = read_policy_list(SERVICES)
    env = {}
    for policy in ("own", "fast"):
        env[f"SERVICES_EXACT_{policy.upper()}"] = by[policy]
        env[f"SERVICES_SUFFIX_{policy.upper()}"] = ["." + d for d in by[policy]]
    return env


def load_networks():
    """Свои подсети — для протоколов без имени хоста (Telegram MTProto).

    Отдельными правилами, а не полем в правиле доменов: в sing-box условия
    внутри одного правила объединяются по И, поэтому domain и ip_cidr вместе
    требовали бы совпадения обоих сразу.
    """
    by = read_policy_list(NETWORKS)
    return {f"SERVICES_CIDR_{p.upper()}": by[p] for p in ("own", "fast")}


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


def load_rulesets():
    """Включённые готовые списки -> объекты rule_set и список их тегов.

    Файл rulesets.list работает как набор галочек: строка раскомментирована —
    список включён. Ничего, кроме этого файла, править не нужно.
    """
    entries = []
    with open(RULESETS) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            # Формат: «источник:набор [политика]». Политика — own или fast,
            # по умолчанию own: свой сервер безопаснее чужого, поэтому
            # умолчание должно быть консервативным.
            parts = line.split()
            key = parts[0]
            policy = parts[1] if len(parts) > 1 else "own"
            if policy not in ("own", "fast"):
                sys.exit(f"ОШИБКА: неизвестная политика '{policy}' в {RULESETS}")
            source, _, name = key.partition(":")
            if not name:                       # запись без источника — vernette
                source, name = "vernette", source
            if source not in SOURCES:
                sys.exit(f"ОШИБКА: неизвестный источник '{source}' в {RULESETS}")
            entries.append((source, name, policy))

    entries = sorted(set(entries))
    sets, tags = [], {"own": [], "fast": []}
    for source, name, policy in entries:
        url_tpl, prefix = SOURCES[source]
        # Префикс в теге обязателен: у источников есть одноимённые наборы
        # (netflix, telegram), и без него они бы затёрли друг друга.
        tag = f"{prefix}-{name}"
        tags[policy].append(tag)
        sets.append({
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url_tpl.format(name),
            "download_detour": "direct",
            "update_interval": RULESET_UPDATE,
        })
    return sets, tags


def load_backup():
    """Резервные серверы из подписки (готовит vm/parse-subscription.py)."""
    if not os.path.exists(BACKUP):
        return []
    with open(BACKUP) as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            sys.exit(f"ОШИБКА: {BACKUP} повреждён — перезапустите parse-subscription.py")


def main():
    env = load_env(ENV)
    env.update(load_services())
    env.update(load_networks())

    rule_sets, rule_tags = load_rulesets()
    env["RULESET_TAGS_OWN"] = rule_tags["own"]
    env["RULESET_TAGS_FAST"] = rule_tags["fast"]

    with open(TPL) as fh:
        template = json.load(fh)

    cfg, _ = render(template, env)

    # rule_set добавляется после подстановки: это не плейсхолдер, а целый
    # массив объектов, который проще собрать здесь, чем описывать в шаблоне.
    if rule_sets:
        cfg["route"]["rule_set"] = rule_sets
    else:
        cfg["route"].pop("rule_set", None)

    # --- Резервные серверы и группа автовыбора -------------------------------
    backup = load_backup()
    cfg["outbounds"].extend(backup)
    if backup:
        # urltest сам меряет задержку и берёт лучший. Свой сервер включён
        # в группу наравне: если он быстрее, трафик останется на нём.
        cfg["outbounds"].append({
            "type": "urltest",
            "tag": "fast-out",
            "outbounds": ["reality-out"] + [o["tag"] for o in backup],
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
            "tolerance": 60,
            "idle_timeout": "30m",
        })
    else:
        # Без подписки группы нет — правило «fast» должно указывать на свой
        # сервер, иначе конфиг ссылался бы на несуществующий outbound.
        for rule in cfg["route"]["rules"]:
            if rule.get("outbound") == "fast-out":
                rule["outbound"] = "reality-out"

    # Пустые правила по наборам выбрасываются: sing-box не принимает
    # rule_set с пустым массивом.
    cfg["route"]["rules"] = [
        r for r in cfg["route"]["rules"]
        if r.get("rule_set") != [] and r.get("ip_cidr") != [] and r.get("domain") != []
    ]

    leftover = PLACEHOLDER.findall(json.dumps(cfg))
    if leftover:
        sys.exit(f"ОШИБКА: неподставленные плейсхолдеры: {sorted(set(leftover))}")

    json.dump(cfg, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
