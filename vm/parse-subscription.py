#!/usr/bin/env python3
"""Разбор подписки в outbound-секции sing-box.

Читает URL из secrets/backup-subscription.txt, скачивает подписку, разбирает
ссылки и пишет vm/sing-box/backup-outbounds.json — массив готовых outbound'ов.
Их подхватывает render-config.py и собирает в группу автовыбора.

Поддерживаются vless:// (в том числе Reality), trojan:// и ss://.
Неизвестные схемы пропускаются молча: подписки часто содержат мусор и
служебные записи, и падать из-за них нельзя — иначе одна плохая строка
лишает дом всего резерва.

Результат пишется атомарно: сначала во временный файл, потом replace.
Иначе прерванная загрузка оставила бы обрезанный JSON, и следующая
сборка конфига упала бы.

  --dry-run   показать, что получилось, ничего не записывая
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUB_FILE = os.path.join(ROOT, "secrets", "backup-subscription.txt")
OUT_FILE = os.path.join(ROOT, "vm", "sing-box", "backup-outbounds.json")

TIMEOUT = 45

# Панели отдают РАЗНОЕ содержимое в зависимости от User-Agent: одному клиенту
# ссылки, другому готовый sing-box JSON, третьему clash-YAML. Незнакомому
# агенту часто достаётся заглушка. Проверено на shadowq.cc: v2rayNG и Happ
# получали 320 байт, SFI — JSON, clash-verge — 67 КБ YAML.
# Поэтому перебираем агенты и берём ответ, где серверов оказалось больше.
AGENTS = [
    "clash-verge/1.5.0",   # обычно самый полный ответ
    "ClashMeta/1.0",
    "SFI/1.0",             # нативный sing-box JSON
    "sing-box/1.13.0",
    "Happ/1.0",
    "v2rayNG/1.8.5",
    "Streisand/1.0",
]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def hwid_headers():
    """Заголовки привязки к устройству (Remnawave).

    Без них панель отдаёт заглушку «Напиши в поддержку» вместо серверов —
    в ответе это видно по X-Hwid-Not-Supported: true. Happ такие заголовки
    шлёт, обычный HTTP-клиент нет.

    Идентификатор постоянный и лежит в secrets/hwid.env: меняющийся занимал бы
    новый слот устройства при каждом запросе и быстро исчерпал бы лимит.
    """
    path = os.path.join(ROOT, "secrets", "hwid.env")
    if not os.path.exists(path):
        return {}
    hwid = ""
    for line in open(path):
        if line.startswith("HWID="):
            hwid = line.split("=", 1)[1].strip()
    if not hwid:
        return {}
    return {
        "x-hwid": hwid,
        "x-device-os": "Linux",
        "x-ver-os": "Debian 13",
        "x-device-model": "singbox-gw",
    }


def fetch(url, ua):
    headers = {"User-Agent": ua}
    headers.update(hwid_headers())
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


def maybe_b64(text):
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


def safe_tag(name, used, fallback=""):
    """Тег должен быть уникальным и пригодным для ссылки из правил.

    Имена профилей в подписках состоят из эмодзи и кириллицы, которые здесь
    срезаются подчистую — без запасного варианта все теги вырождались
    в bk-node, bk-node-2 и так далее, и по логу было не понять, какой
    сервер выбран. Поэтому запасной вариант — имя хоста.
    """
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower()
    if not base or base.isdigit():
        base = re.sub(r"[^A-Za-z0-9_.-]+", "-", fallback).strip("-").lower() or "node"
    base = f"bk-{base[:40]}"
    tag, n = base, 2
    while tag in used:
        tag, n = f"{base}-{n}", n + 1
    used.add(tag)
    return tag


def parse_vless(url, used):
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    if not p.hostname or not p.username:
        return None
    name = urllib.parse.unquote(p.fragment or "")
    # Тот же отбор, что и для остальных форматов: узлы «LTE обход» стоят
    # на российских адресах и по задержке выигрывают у зарубежных, поэтому
    # группа автовыбора предпочла бы их — и трафик «за рубеж» остался бы в РФ.
    if SKIP_PROFILE.search(name):
        return None
    ob = {
        "type": "vless",
        "tag": safe_tag(name, used, fallback=p.hostname.split(".")[0]),
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


def parse_trojan(url, used):
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    if not p.hostname or not p.username:
        return None
    return {
        "type": "trojan",
        "tag": safe_tag(urllib.parse.unquote(p.fragment or p.hostname), used),
        "server": p.hostname,
        "server_port": p.port or 443,
        "password": urllib.parse.unquote(p.username),
        "tls": {"enabled": True, "server_name": q.get("sni") or p.hostname},
    }


def parse_ss(url, used):
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
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


PARSERS = {"vless": parse_vless, "trojan": parse_trojan, "ss": parse_ss}

# Адреса, которые никуда не ведут. Провайдеры кладут такие записи вместо
# серверов, когда подписка неактивна: у shadowq.cc это был
# vless://...@0.0.0.0:1 с тегом «Напиши в поддержку».
# Без этой проверки заглушка попадает в группу автовыбора, и sing-box
# бесконечно долбится в несуществующий адрес, замедляя выбор живого.
DEAD_HOSTS = {"0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "example.com"}


def from_singbox_json(text, used):
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
        # Тот же фильтр, что и для xray-формата: «LTE обход» — это входные
        # узлы на российских адресах, а «Россия → X» — цепочки со входом в РФ.
        # Для задачи «за рубеж» они не годятся, а по задержке выигрывали бы
        # у зарубежных и перетягивали трафик на себя.
        if SKIP_PROFILE.search(name):
            continue
        ob = dict(ob)
        # Запасное имя — хост: теги в подписке состоят из эмодзи и кириллицы
        # и после очистки вырождаются в «node», по которому в логе ничего
        # не понять.
        ob["tag"] = safe_tag(name, used,
                             fallback=str(ob.get("server", "")).split(".")[0])
        ob.pop("domain_resolver", None)   # свой резолвер задаётся у нас
        out.append(ob)
    return out


def from_clash_yaml(text, used):
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
        if typ == "vless":
            ob = {"type": "vless", "tag": tag, "server": server.strip(),
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
            out.append({"type": "trojan", "tag": tag, "server": server.strip(),
                        "server_port": int(port), "password": fields.get("password", ""),
                        "tls": {"enabled": True,
                                "server_name": fields.get("sni", server).strip()}})
        elif typ == "ss":
            out.append({"type": "shadowsocks", "tag": tag, "server": server.strip(),
                        "server_port": int(port), "method": fields.get("cipher", ""),
                        "password": fields.get("password", "")})
    return out


# Профили, которые НЕ берём в резерв. Подписка отдаёт не только зарубежные
# выходы: «LTE обход» — это входные узлы на российских адресах для обхода
# замедления у мобильных операторов, а «Россия → X» — цепочки со входом в РФ.
# Для задачи «за рубеж» нужен зарубежный выход, поэтому такие профили
# пропускаются: иначе группа автовыбора могла бы предпочесть их по задержке
# (они ближе!) и трафик остался бы в России.
SKIP_PROFILE = re.compile(r"LTE|Росси\w*\s*→|Hysteria", re.I)


def from_xray_json(text, used):
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


BARE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def usable(ob):
    if not ob:
        return False
    host = str(ob.get("server", "")).strip().lower()
    port = ob.get("server_port", 0)
    if host in DEAD_HOSTS or not host:
        return False
    if not isinstance(port, int) or port < 20 or port > 65535:
        return False
    # Отсев входных узлов внутри РФ. В этой подписке зарубежные выходы
    # адресуются именами (nl.shadowq.cc, usa.shadowq.cc), а узлы «LTE обход»
    # — голыми IP из российских диапазонов, причём в формате ссылок они
    # названы BEST-2-* и по имени не отличаются.
    # Признак провайдер-специфичный, но здесь разделяет группы однозначно,
    # а цена ошибки высока: такой узел ближе всех по задержке, группа
    # автовыбора предпочла бы именно его, и трафик «за рубеж» остался бы в РФ.
    if BARE_IP.match(host):
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(SUB_FILE):
        log(f"{SUB_FILE} не найден — резервных серверов нет, это не ошибка")
        if not args.dry_run:
            write([])
        return

    url = ""
    for line in open(SUB_FILE):
        line = line.split("#", 1)[0].strip()
        if line:
            url = line
            break
    if not url:
        log("ссылка на подписку пуста — резервных серверов нет")
        if not args.dry_run:
            write([])
        return

    best, best_ua, skipped = [], None, 0
    for ua in AGENTS:
        used = set()
        try:
            raw = fetch(url, ua)
        except Exception as exc:
            log(f"  {ua}: не ответил ({str(exc)[:40]})")
            continue

        # Порядок важен: xray-конфиг тоже JSON, но со своей структурой,
        # и sing-box-разборщик нашёл бы в нём ноль серверов.
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

        alive = [o for o in got if usable(o)]
        dead = len(got) - len(alive)
        log(f"  {ua:20} получено {len(got):>3}, пригодно {len(alive):>3}"
            + (f", заглушек {dead}" if dead else ""))
        skipped = max(skipped, dead)   # чтобы счётчик не терялся при нулевом улове
        if len(alive) > len(best):
            best, best_ua = alive, ua

    outbounds = best
    if best_ua:
        log(f"выбран ответ для {best_ua}")
    log(f"серверов пригодных: {len(outbounds)}, отброшено заглушек: {skipped}")
    if not outbounds and skipped:
        log("ВНИМАНИЕ: в подписке нет ни одного рабочего сервера. "
            "Обычно это значит, что она неактивна — проверьте у провайдера.")
    by_type = {}
    for ob in outbounds:
        by_type[ob["type"]] = by_type.get(ob["type"], 0) + 1
    for t, n in sorted(by_type.items()):
        log(f"  {t}: {n}")

    if args.dry_run:
        log("dry-run: файл не записан")
        return
    write(outbounds)
    log(f"записано в {OUT_FILE}")


def write(outbounds):
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(outbounds, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, OUT_FILE)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"ОШИБКА: {exc}")
        sys.exit(1)
