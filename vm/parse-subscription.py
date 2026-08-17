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
UA = "v2rayNG/1.8.5"   # некоторые панели отдают подписку только «известным» клиентам


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
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

    text = maybe_b64(fetch(url))
    used, outbounds, skipped = set(), [], 0
    for line in text.splitlines():
        line = line.strip()
        if "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()
        parser = PARSERS.get(scheme)
        if not parser:
            skipped += 1
            continue
        try:
            ob = parser(line, used)
        except Exception:
            ob = None
        if ob:
            outbounds.append(ob)
        else:
            skipped += 1

    log(f"серверов разобрано: {len(outbounds)}, пропущено: {skipped}")
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
