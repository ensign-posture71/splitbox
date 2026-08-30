"""Сборка конфига sing-box из модели config.yaml.

Наследник vm/render-config.py. Механика та же: валидный JSON-шаблон,
пояснения в ключах «//», плейсхолдеры ${NAME}, пустое значение = ключ
удаляется. Изменилось одно: источник данных — модель, а не файлы+env.

Динамические части собираются кодом, потому что это не строковые
подстановки, а целые объекты: свои серверы, wireguard-endpoint с пирами,
rule_set, группа автовыбора fast-out.
"""
from __future__ import annotations

import json
import re
from importlib import resources

from . import catalog, subs
from .subs import strip_meta
from .model import Config, Mode, Policy, Strategy

PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


class RenderError(ValueError):
    pass


def _template() -> dict:
    with resources.files("splitbox").joinpath("template.json").open() as fh:
        return json.load(fh)


def _substitute(node, env):
    """Возвращает (значение, есть_ли_оно). Второе False — ключ надо выбросить.

    Перенос render() из донора: ключи «//» вырезаются, ${NAME} подставляется,
    пустая строка означает «поля быть не должно», числа приводятся к int
    (sing-box ждёт число в server_port).
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k.startswith("//"):
                continue
            rendered, present = _substitute(v, env)
            if present:
                out[k] = rendered
        return out, True
    if isinstance(node, list):
        return [_substitute(v, env)[0] for v in node], True
    if isinstance(node, str):
        m = PLACEHOLDER.fullmatch(node)
        if m:
            name = m.group(1)
            if name not in env:
                raise RenderError(f"в подстановках нет переменной {name}")
            val = env[name]
            if isinstance(val, list):
                return val, True
            if val == "":
                return None, False
            return (int(val) if isinstance(val, str) and val.isdigit() else val), True
    return node, True


def _services_env(cfg: Config) -> dict:
    """Свои домены и подсети -> массивы для правил маршрутизации."""
    env: dict = {}
    for policy in (Policy.own, Policy.fast):
        domains = sorted({d.value for d in cfg.policies.domains if d.policy == policy})
        env[f"SERVICES_EXACT_{policy.name.upper()}"] = domains
        # Точка впереди делает совпадение по границе метки.
        env[f"SERVICES_SUFFIX_{policy.name.upper()}"] = ["." + d for d in domains]
        env[f"SERVICES_CIDR_{policy.name.upper()}"] = sorted(
            {n.value for n in cfg.policies.networks if n.policy == policy})
    return env


def _rulesets(cfg: Config) -> tuple[list[dict], dict[str, list[str]]]:
    """Включённые готовые наборы -> объекты rule_set и теги по политикам."""
    src = catalog.sources()
    sets, tags = [], {"own": [], "fast": []}
    for key, policy in sorted(cfg.policies.rulesets.items()):
        if policy == Policy.off:
            continue
        source, _, name = key.partition(":")
        if source not in src["sources"]:
            raise RenderError(f"неизвестный источник наборов: {source!r}")
        url_tpl = src["sources"][source]["url"]
        prefix = src["sources"][source]["prefix"]
        tag = f"{prefix}-{name}"
        tags[policy.value].append(tag)
        sets.append({
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url_tpl.format(name),
            "download_detour": "direct",
            "update_interval": src.get("update_interval", "1d"),
        })
    return sets, tags


def _safe_name(name: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower()
    return out or "server"


def _own_outbounds(cfg: Config) -> list[dict]:
    """Свои серверы -> outbound'ы vless. flow подставляется только если задан
    (D10: сервер, который его не ждёт, рвёт соединение)."""
    out = []
    used: set = set()
    for srv in cfg.enabled_own():
        ob = {
            "type": "vless",
            "tag": subs.safe_tag(srv.name, used, fallback=srv.server.split(".")[0],
                                 prefix="own"),
            "server": srv.server,
            "server_port": srv.server_port,
            "uuid": srv.uuid,
            "packet_encoding": "xudp",
            "domain_resolver": "dns-endpoint",
        }
        if srv.flow:
            ob["flow"] = srv.flow
        if srv.reality_public_key:
            ob["tls"] = {
                "enabled": True,
                "server_name": srv.sni or srv.server,
                "utls": {"enabled": True, "fingerprint": srv.fingerprint},
                "reality": {"enabled": True, "public_key": srv.reality_public_key},
            }
            if srv.reality_short_id:
                ob["tls"]["reality"]["short_id"] = srv.reality_short_id
        elif srv.sni:
            ob["tls"] = {"enabled": True, "server_name": srv.sni,
                         "utls": {"enabled": True, "fingerprint": srv.fingerprint}}
        out.append(ob)
    return out


def _wireguard_endpoint(cfg: Config) -> dict:
    """WG-сервер для устройств друзей — endpoint внутри sing-box (userspace).

    Трафик пиров попадает прямо в route.rules, минуя ядро и tproxy, поэтому
    в режиме vps контейнеру не нужны ни NET_ADMIN, ни модуль ядра wireguard.
    """
    wg = cfg.wireguard
    if not wg.private_key:
        raise RenderError("не сгенерированы ключи WireGuard-сервера "
                          "(wg.ensure_server_keys)")
    prefix = wg.subnet.split("/")[1]
    return {
        "type": "wireguard",
        "tag": "wg-in",
        "system": False,
        "address": [f"{wg.server_address}/{prefix}"],
        "private_key": wg.private_key,
        "listen_port": wg.listen_port,
        "peers": [
            {"public_key": p.public_key, "allowed_ips": [f"{p.address}/32"]}
            for p in wg.peers
        ],
    }


def _rewrite_outbound(rules: list[dict], src: str, dst: str) -> None:
    for rule in rules:
        if rule.get("outbound") == src:
            rule["outbound"] = dst


def _group(tag: str, members: list[dict], bal) -> dict:
    """Группа серверов по выбранной стратегии.

    latency — urltest: sing-box сам меряет задержку и берёт лучший.
    pinned  — selector с фиксированным выбором: всегда один и тот же сервер
              (пока он жив), удобно, когда важна предсказуемость выхода.
    """
    tags = [m["tag"] for m in members]
    if bal.strategy is Strategy.pinned:
        default = bal.pinned_tag if bal.pinned_tag in tags else tags[0]
        return {"type": "selector", "tag": tag, "outbounds": tags,
                "default": default}
    return {
        "type": "urltest",
        "tag": tag,
        "outbounds": tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": bal.interval,
        "tolerance": bal.tolerance,
        "idle_timeout": bal.idle_timeout,
    }


def _backup_groups(ob: dict) -> list[str]:
    """В какие группы просится резервный сервер.

    Отсутствие поля и пустой список — разные вещи: кэш, записанный старой
    версией, поля не имеет (такие серверы считаем «быстрыми»), а пустой
    список означает «владелец исключил эту подписку отовсюду».
    """
    groups = ob.get("_groups")
    return ["fast"] if groups is None else list(groups)


def render_config(cfg: Config, backups: list[dict] | None = None) -> dict:
    """Модель + резервные outbound'ы (кэш refresh'а подписок) -> конфиг.

    Состав каждой группы задаётся флагами участия: у своих серверов —
    in_own/in_fast, у подписок — in_fast/in_own (последний по умолчанию
    выключен: чужой сервер видит весь проходящий трафик).

    Деградации вместо отказов:
      * группа пуста — её правила переписываются на соседнюю;
      * пусты обе — RenderError: маршрутизировать некуда.
    """
    backups = list(backups or [])
    env = _services_env(cfg)
    rule_sets, rule_tags = _rulesets(cfg)
    env["RULESET_TAGS_OWN"] = rule_tags["own"]
    env["RULESET_TAGS_FAST"] = rule_tags["fast"]

    template = _template()
    config, _ = _substitute(template, env)

    if cfg.mode is not Mode.lan_gateway:
        # В режиме vps транзитного LAN нет — tproxy-вход не нужен.
        config["inbounds"] = [i for i in config["inbounds"]
                              if i["tag"] != "tproxy-in"]

    config["endpoints"] = [_wireguard_endpoint(cfg)]

    own = _own_outbounds(cfg)
    servers = cfg.enabled_own()
    if not own and not backups:
        raise RenderError("нет ни одного сервера: добавьте свой сервер "
                          "или подписку")

    config["outbounds"].extend(own)
    config["outbounds"].extend(strip_meta(o) for o in backups)

    # Состав групп по флагам участия.
    members = {
        "own": [o for o, s in zip(own, servers) if s.in_own]
               + [o for o in backups if "own" in _backup_groups(o)],
        "fast": [o for o, s in zip(own, servers) if s.in_fast]
                + [o for o in backups if "fast" in _backup_groups(o)],
    }
    if not members["own"] and not members["fast"]:
        raise RenderError("ни один сервер не включён ни в одну группу — "
                          "отметьте участие серверов в разделе «Серверы»")

    rules = config["route"]["rules"]
    balancers = {"own": cfg.balancing.own, "fast": cfg.balancing.fast}
    resolved: dict[str, str] = {}

    for name in ("own", "fast"):
        group = members[name]
        if not group:
            continue
        if len(group) == 1:
            # Один участник — группа не нужна, правило указывает прямо
            # на сервер: меньше сущностей в конфиге и в логах.
            resolved[name] = group[0]["tag"]
        else:
            resolved[name] = f"{name}-out"
            config["outbounds"].append(
                _group(f"{name}-out", group, balancers[name]))

    # Пустая группа честно деградирует в соседнюю.
    for name, other in (("own", "fast"), ("fast", "own")):
        target = resolved.get(name) or resolved[other]
        _rewrite_outbound(rules, f"{name}-out", target)

    if rule_sets:
        config["route"]["rule_set"] = rule_sets
    else:
        config["route"].pop("rule_set", None)

    # Пустые правила выбрасываются: sing-box не принимает rule_set/domain/
    # ip_cidr с пустым массивом.
    config["route"]["rules"] = [
        r for r in rules
        if r.get("rule_set") != [] and r.get("ip_cidr") != [] and r.get("domain") != []
    ]

    leftover = PLACEHOLDER.findall(json.dumps(config))
    if leftover:
        raise RenderError(f"неподставленные плейсхолдеры: {sorted(set(leftover))}")
    return config


def render_json(cfg: Config, backups: list[dict] | None = None) -> str:
    return json.dumps(render_config(cfg, backups), indent=2, ensure_ascii=False) + "\n"
