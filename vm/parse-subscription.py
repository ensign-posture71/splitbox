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


def fetch(url, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
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


def safe_tag(name, used):
    """Тег должен быть уникальным и пригодным для ссылки из правил."""
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower() or "node"
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
    ob = {
        "type": "vless",
        "tag": safe_tag(urllib.parse.unquote(p.fragment or p.hostname), used),
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
    out = []
    for ob in data.get("outbounds", []):
        if ob.get("type") in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2"):
            ob = dict(ob)
            ob["tag"] = safe_tag(str(ob.get("tag") or ob.get("server", "node")), used)
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


def usable(ob):
    if not ob:
        return False
    host = str(ob.get("server", "")).strip().lower()
    port = ob.get("server_port", 0)
    if host in DEAD_HOSTS or not host:
        return False
    if not isinstance(port, int) or port < 20 or port > 65535:
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
