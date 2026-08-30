"""Разбор VLESS-подписок в outbound-секции sing-box.

Порт vm/parse-subscription.py в виде чистых функций: без файловых путей,
URL и HWID приходят параметрами. Вся накопленная логика сохранена:

* Панели отдают РАЗНОЕ содержимое в зависимости от User-Agent: одному
  клиенту ссылки, другому готовый sing-box JSON, третьему clash-YAML.
  Незнакомому агенту часто достаётся заглушка. Поэтому перебираем агенты
  и берём ответ, где живых серверов оказалось больше.
* Заголовки HWID (Remnawave): без них панель отдаёт заглушку «Напиши
  в поддержку». Идентификатор постоянный, на подписку — свой: меняющийся
  занимал бы новый слот устройства при каждом запросе.
* Фильтры: мёртвые хосты-заглушки (0.0.0.0:1), профили «LTE обход» и
  «Россия → X» (входные узлы в РФ — по задержке они выигрывали бы у
  зарубежных, и трафик «за рубеж» остался бы в России), голые IP
  (в изученных подписках зарубежные выходы адресуются именами).

Неизвестные схемы пропускаются молча: подписки часто содержат мусор,
и падать из-за них нельзя — одна плохая строка не должна лишать резерва.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("splitbox.subs")

TIMEOUT = 45

AGENTS = [
    "clash-verge/1.5.0",   # обычно самый полный ответ
    "ClashMeta/1.0",
    "SFI/1.0",             # нативный sing-box JSON
    "sing-box/1.13.0",
    "Happ/1.0",
    "v2rayNG/1.8.5",
    "Streisand/1.0",
]

# Профили, которые НЕ берём в резерв: входные узлы в РФ и цепочки со входом
# в РФ. Для задачи «за рубеж» нужен зарубежный выход.
SKIP_PROFILE = re.compile(r"LTE|Росси\w*\s*→|Hysteria", re.I)

# Адреса-заглушки, которые провайдеры кладут вместо серверов у неактивной
# подписки. Без проверки заглушка попадает в группу автовыбора, и sing-box
# бесконечно долбится в несуществующий адрес.
DEAD_HOSTS = {"0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "example.com"}

BARE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class FetchResult:
    outbounds: list[dict] = field(default_factory=list)
    agent: str = ""            # чей ответ выбран
    skipped: int = 0           # отброшено заглушек/мёртвых
    errors: list[str] = field(default_factory=list)
    # Имена отброшенных записей. Панели пишут туда причину человеческим
    # языком («Вы превысили лимит устройств»), и это единственная подсказка,
    # которую пользователь может понять, — показываем её как есть.
    notices: list[str] = field(default_factory=list)


def strip_meta(ob: dict) -> dict:
    """Убрать служебные поля (с подчёркиванием) перед отдачей в конфиг:
    sing-box не примет незнакомые ключи."""
    return {k: v for k, v in ob.items() if not k.startswith("_")}


def hwid_headers(hwid: str) -> dict[str, str]:
    if not hwid:
        return {}
    return {
        "x-hwid": hwid,
        "x-device-os": "Linux",
        "x-ver-os": "Debian 13",
        "x-device-model": "splitbox",
    }


def _fetch(url: str, ua: str, hwid: str, timeout: int) -> str:
    headers = {"User-Agent": ua}
    headers.update(hwid_headers(hwid))
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def maybe_b64(text: str) -> str:
    """Подписки отдают либо голые ссылки, либо base64 от них."""
    stripped = re.sub(r"\s+", "", text)
    if "://" in text:
        return text
    try:
        pad = "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(stripped + pad).decode("utf-8", "replace")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text


def safe_tag(name: str, used: set, fallback: str = "", prefix: str = "bk") -> str:
    """Тег должен быть уникальным и пригодным для ссылки из правил.

    Имена профилей состоят из эмодзи и кириллицы, которые срезаются
    подчистую — без запасного варианта все теги вырождались в bk-node,
    bk-node-2, и по логу было не понять, какой сервер выбран.
    Поэтому запасной вариант — имя хоста.
    """
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower()
    if not base or base.isdigit():
        base = re.sub(r"[^A-Za-z0-9_.-]+", "-", fallback).strip("-").lower() or "node"
    base = f"{prefix}-{base[:40]}"
    tag, n = base, 2
    while tag in used:
        tag, n = f"{base}-{n}", n + 1
    used.add(tag)
    return tag


# --- Разбор ссылок -----------------------------------------------------------

def parse_vless(url: str, used: set) -> dict | None:
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    if not p.hostname or not p.username:
        return None
    name = urllib.parse.unquote(p.fragment or "")
    if SKIP_PROFILE.search(name):
        return None
    ob = {
        "type": "vless",
        "tag": safe_tag(name, used, fallback=p.hostname.split(".")[0]),
        "_name": name,
        "server": p.hostname,
        "server_port": p.port or 443,
        "uuid": p.username,
        "packet_encoding": "xudp",
    }
    if q.get("flow"):
        ob["flow"] = q["flow"]

    security = q.get("security", "")
    if security in ("tls", "reality"):
        tls = {"enabled": True, "server_name": q.get("sni") or p.hostname}
        if q.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if security == "reality":
            if not q.get("pbk"):
                return None          # Reality без ключа нерабочий
            tls["reality"] = {"enabled": True, "public_key": q["pbk"]}
            if q.get("sid"):
                tls["reality"]["short_id"] = q["sid"]
        ob["tls"] = tls

    net = q.get("type", "tcp")
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": q.get("path", "/")}
        if q.get("host"):
            ob["transport"]["headers"] = {"Host": q["host"]}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif net not in ("tcp", "raw", ""):
        return None                  # незнакомый транспорт — лучше пропустить
    return ob


def parse_trojan(url: str, used: set) -> dict | None:
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    if not p.hostname or not p.username:
        return None
    return {
        "type": "trojan",
        "tag": safe_tag(urllib.parse.unquote(p.fragment or p.hostname), used),
        "_name": urllib.parse.unquote(p.fragment or ""),
        "server": p.hostname,
        "server_port": p.port or 443,
        "password": urllib.parse.unquote(p.username),
        "tls": {"enabled": True, "server_name": q.get("sni") or p.hostname},
    }


def parse_ss(url: str, used: set) -> dict | None:
    body = url[5:]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    if "@" not in body:                       # полностью base64-вариант
        try:
            pad = "=" * (-len(body) % 4)
            body = base64.urlsafe_b64decode(body + pad).decode()
        except Exception:
            return None
    userinfo, _, hostport = body.rpartition("@")
    if ":" not in userinfo:
        try:
            pad = "=" * (-len(userinfo) % 4)
            userinfo = base64.urlsafe_b64decode(userinfo + pad).decode()
        except Exception:
            return None
    method, _, password = userinfo.partition(":")
    host, _, port = hostport.partition("?")[0].rpartition(":")
    if not host or not port.isdigit():
        return None
    return {
        "type": "shadowsocks",
        "tag": safe_tag(urllib.parse.unquote(frag or host), used),
        "_name": urllib.parse.unquote(frag or ""),
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


PARSERS = {"vless": parse_vless, "trojan": parse_trojan, "ss": parse_ss}


# --- Разбор форматов подписки ------------------------------------------------

def from_singbox_json(text: str, used: set) -> list | None:
    """Панель отдала готовый конфиг sing-box — берём из него серверы."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None          # список — это формат xray, им занимается другой разбор
    out = []
    for ob in data.get("outbounds", []):
        if ob.get("type") not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2"):
            continue
        name = str(ob.get("tag") or "")
        if SKIP_PROFILE.search(name):
            continue
        ob = dict(ob)
        ob["tag"] = safe_tag(name, used,
                             fallback=str(ob.get("server", "")).split(".")[0])
        ob["_name"] = name
        ob.pop("domain_resolver", None)   # свой резолвер задаётся у нас
        out.append(ob)
    return out


def from_clash_yaml(text: str, used: set) -> list | None:
    """Разбор clash-YAML без внешних библиотек.

    Полноценный YAML-парсер не нужен: секция proxies — это плоский список
    словарей, и панели пишут его однообразно. Берём только то, что умеем
    отобразить в sing-box, остальное молча пропускаем.
    """
    if "proxies:" not in text:
        return None
    block = text.split("proxies:", 1)[1]
    block = re.split(r"\n(?=[a-zA-Z-]+:)", block)[0]

    out = []
    for chunk in re.findall(r"^\s*-\s*(\{.*?\}|(?:.*\n(?:\s{2,}.*\n)*))", block, re.M):
        fields = dict(re.findall(r"([a-zA-Z-]+)\s*:\s*['\"]?([^,'\"\n\}]+)", chunk))
        typ, server = fields.get("type"), fields.get("server")
        port = fields.get("port", "").strip()
        if not typ or not server or not port.isdigit():
            continue
        tag = safe_tag(fields.get("name", server), used)
        raw_name = fields.get("name", "")
        if typ == "vless":
            ob = {"type": "vless", "tag": tag, "_name": raw_name,
                  "server": server.strip(),
                  "server_port": int(port), "uuid": fields.get("uuid", "")}
            if fields.get("flow"):
                ob["flow"] = fields["flow"].strip()
            if fields.get("reality-opts") or fields.get("public-key"):
                ob["tls"] = {"enabled": True,
                             "server_name": fields.get("servername", server).strip(),
                             "reality": {"enabled": True,
                                         "public_key": fields.get("public-key", "").strip()}}
            elif fields.get("tls", "").strip() in ("true", "yes"):
                ob["tls"] = {"enabled": True,
                             "server_name": fields.get("servername", server).strip()}
            out.append(ob)
        elif typ == "trojan":
            out.append({"type": "trojan", "tag": tag, "_name": raw_name,
                        "server": server.strip(),
                        "server_port": int(port), "password": fields.get("password", ""),
                        "tls": {"enabled": True,
                                "server_name": fields.get("sni", server).strip()}})
        elif typ == "ss":
            out.append({"type": "shadowsocks", "tag": tag, "_name": raw_name,
                        "server": server.strip(),
                        "server_port": int(port), "method": fields.get("cipher", ""),
                        "password": fields.get("password", "")})
    return out


def from_xray_json(text: str, used: set) -> list | None:
    """Разбор конфига Xray/V2Ray в outbound'ы sing-box.

    Именно этот формат отдаёт панель Remnawave клиенту с HWID. Адрес сервера
    лежит не в `server`, как у sing-box, а в settings.vnext[0] — из-за чего
    первая версия разборщика видела «0 серверов с адресом».
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    profiles = data if isinstance(data, list) else [data]
    if not profiles or not isinstance(profiles[0], dict):
        return None
    if "outbounds" not in profiles[0]:
        return None
    # Конфиг sing-box — тоже JSON с outbounds, но у xray протокол лежит
    # в ключе «protocol», а у sing-box — в «type». Без этой проверки разбор
    # xray проглатывал sing-box-ответ и возвращал пустой список, не давая
    # шанса правильному разборщику.
    if not any("protocol" in o for p in profiles for o in p.get("outbounds", [])):
        return None

    out, seen = [], set()
    for cfg in profiles:
        remark = str(cfg.get("remarks", ""))
        if SKIP_PROFILE.search(remark):
            continue
        for o in cfg.get("outbounds", []):
            if (o.get("protocol") or o.get("type")) != "vless":
                continue
            vnext = (o.get("settings") or {}).get("vnext") or []
            if not vnext:
                continue
            node, users = vnext[0], (vnext[0].get("users") or [{}])
            key = (node.get("address"), node.get("port"))
            if key in seen or not key[0]:
                continue
            seen.add(key)

            ss = o.get("streamSettings") or {}
            ob = {
                "type": "vless",
                "tag": safe_tag(remark, used, fallback=str(node["address"]).split(".")[0]),
                "_name": remark,
                "server": node["address"],
                "server_port": int(node["port"]),
                "uuid": users[0].get("id", ""),
                "packet_encoding": "xudp",
            }
            if users[0].get("flow"):
                ob["flow"] = users[0]["flow"]

            sec = ss.get("security")
            if sec == "reality":
                rs = ss.get("realitySettings") or {}
                ob["tls"] = {
                    "enabled": True,
                    "server_name": rs.get("serverName", ""),
                    "utls": {"enabled": True,
                             "fingerprint": rs.get("fingerprint", "chrome")},
                    "reality": {"enabled": True,
                                "public_key": rs.get("publicKey", ""),
                                "short_id": rs.get("shortId", "")},
                }
            elif sec == "tls":
                ts = ss.get("tlsSettings") or {}
                ob["tls"] = {"enabled": True,
                             "server_name": ts.get("serverName", node["address"])}

            net = ss.get("network", "tcp")
            if net == "ws":
                wss = ss.get("wsSettings") or {}
                ob["transport"] = {"type": "ws", "path": wss.get("path", "/")}
            elif net == "grpc":
                gs = ss.get("grpcSettings") or {}
                ob["transport"] = {"type": "grpc",
                                   "service_name": gs.get("serviceName", "")}
            elif net not in ("tcp", "raw", ""):
                continue
            out.append(ob)
    return out


def usable(ob: dict | None) -> bool:
    if not ob:
        return False
    host = str(ob.get("server", "")).strip().lower()
    port = ob.get("server_port", 0)
    if host in DEAD_HOSTS or not host:
        return False
    if not isinstance(port, int) or port < 20 or port > 65535:
        return False
    # Отсев входных узлов внутри РФ: в изученных подписках зарубежные выходы
    # адресуются именами, а узлы «LTE обход» — голыми IP из российских
    # диапазонов. Признак провайдер-специфичный, но цена ошибки высока:
    # такой узел ближе всех по задержке, и группа автовыбора предпочла бы его.
    if BARE_IP.match(host):
        return False
    return True


def parse_payload(raw: str, used: set | None = None) -> list[dict]:
    """Разбор одного ответа подписки: пробуем форматы по очереди.

    Порядок важен: xray-конфиг тоже JSON, но со своей структурой,
    и sing-box-разборщик нашёл бы в нём ноль серверов.
    """
    used = set() if used is None else used
    got = from_xray_json(raw, used)
    if got is None:
        got = from_singbox_json(raw, used)
    if got is None:
        got = from_clash_yaml(raw, used)
    if got is None:
        got = []
        for line in maybe_b64(raw).splitlines():
            line = line.strip()
            if "://" not in line:
                continue
            parser = PARSERS.get(line.split("://", 1)[0].lower())
            if not parser:
                continue
            try:
                ob = parser(line, used)
            except Exception:
                ob = None
            if ob:
                got.append(ob)
    return got


def fetch_subscription(url: str, hwid: str = "",
                       timeout: int = TIMEOUT) -> FetchResult:
    """Скачать подписку всеми агентами и вернуть лучший разбор."""
    result = FetchResult()
    for ua in AGENTS:
        used: set = set()
        try:
            raw = _fetch(url, ua, hwid, timeout)
        except Exception as exc:
            result.errors.append(f"{ua}: {str(exc)[:60]}")
            continue
        got = parse_payload(raw, used)
        alive = [o for o in got if usable(o)]
        dead = len(got) - len(alive)
        log.info("%s: получено %d, пригодно %d%s", ua, len(got), len(alive),
                 f", заглушек {dead}" if dead else "")
        if dead > result.skipped:
            result.skipped = dead
            result.notices = [n for n in
                              (str(o.get("_name") or "").strip()
                               for o in got if not usable(o)) if n]
        if len(alive) > len(result.outbounds):
            result.outbounds = [strip_meta(o) for o in alive]
            result.agent = ua
    return result


def parse_manual_link(link: str) -> dict:
    """Одна ручная ссылка (vless:// / trojan:// / ss://) -> outbound.

    В отличие от подписки здесь ошибка НЕ проглатывается: пользователь ввёл
    ссылку руками и должен увидеть, что с ней не так.
    """
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    parser = PARSERS.get(scheme)
    if not parser:
        raise ValueError(f"неизвестная схема ссылки: {scheme or link[:30]!r}")
    ob = parser(link.strip(), set())
    if not ob:
        raise ValueError("ссылка не разобралась — проверьте, что она скопирована целиком")
    if not usable(ob):
        raise ValueError(f"сервер {ob.get('server')!r} выглядит нерабочим "
                         "(заглушка или голый IP)")
    return strip_meta(ob)
