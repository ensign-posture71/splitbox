#!/usr/bin/env python3
"""Наполнение address-list `abroad` на MikroTik (Вариант A: D1, D11).

Два независимых потока, каждый запускается своей подкомандой:

  ip-base    Статическая IP-база ReFilter (ips_refilter + ips_antifilter).
             Записи без timeout — живут до следующего прохода. Обновлять редко.

  dns-feed   Динамический поток: query-лог AdGuard → домены из abroad-набора →
             их резолвленные A-записи. Записи с timeout: то, что перестали
             спрашивать, само уходит из списка, и он не пухнет.

Почему SSH, а не файл с /import: на роутере 16 МБ flash и меньше мегабайта
свободно (O18) — файл списка туда физически не влезает. Команды отправляются
в консоль пачками и нигде не сохраняются.

Почему пачками, а не по одной: одно SSH-соединение на запись означало бы
десятки тысяч рукопожатий. Пачка в BATCH записей идёт одной командой.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROUTER = "192.168.88.1"
ROUTER_USER = "sync"
SSH_KEY = "/root/.ssh/id_sync"
LIST = "abroad"

# Столько записей уходит одной SSH-командой. Подобрано так, чтобы командная
# строка не упёрлась в лимит длины и при этом рукопожатий было немного.
BATCH = 250

# Метки в comment: по ним скрипт отличает свои записи от чужих и от записей
# другого потока. Ручные записи владельца (и FQDN-записи, O19) не трогаются.
TAG_IP = "refilter"
TAG_DNS = "adguard"

SOURCES_IP = [
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/main/rules/ips_refilter.list",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/main/rules/ips_antifilter.list",
]
SOURCES_DOMAIN = [
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/main/rules/domains_refilter.list",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/main/rules/domains_community.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Gemini/Gemini.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Copilot/Copilot.list",
]

# Подсети, которые не должны попадать в abroad ни при каких условиях.
# Приватные — потому что завернуть внутрисетевой трафик в туннель означает
# потерять доступ к роутеру. 45.61.137.0/24 — сам VPS: заворачивать путь
# к точке выхода внутрь этой же точки выхода нельзя.
NEVER = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "abroad-sync/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", "replace")


def ip_in_never(addr):
    """Грубая, но достаточная проверка: адрес из приватного/служебного диапазона."""
    import ipaddress
    try:
        net = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return True
    if net.version != 4:
        return True
    for blocked in NEVER:
        if net.subnet_of(ipaddress.ip_network(blocked)):
            return True
    return False


def parse_ip_list(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2 and parts[0].upper() in ("IP-CIDR", "IP-CIDR6"):
            addr = parts[1]
            if ":" in addr:
                continue
            if not ip_in_never(addr):
                out.add(addr)
    return out


def parse_domain_list(text):
    """Возвращает (суффиксы, точные_домены, ключевые_слова)."""
    suffixes, exact, keywords = set(), set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        kind, value = parts[0].upper(), parts[1].lower()
        if kind == "DOMAIN-SUFFIX":
            suffixes.add(value)
        elif kind == "DOMAIN":
            exact.add(value)
        elif kind == "DOMAIN-KEYWORD":
            keywords.add(value)
    return suffixes, exact, keywords


def domain_matches(name, suffixes, exact, keywords):
    name = name.lower().rstrip(".")
    if name in exact:
        return True
    if any(k in name for k in keywords):
        return True
    parts = name.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in suffixes:
            return True
    return False


def router(commands):
    """Выполняет список команд RouterOS одним SSH-вызовом."""
    if not commands:
        return ""
    payload = "; ".join(commands)
    result = subprocess.run(
        ["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
         f"{ROUTER_USER}@{ROUTER}", payload],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ошибка SSH к роутеру: {result.stderr.strip()[:300]}")
    return result.stdout


def existing(tag):
    """Адреса из списка, добавленные этим скриптом под данной меткой."""
    out = router([
        f':foreach e in=[/ip firewall address-list find where list={LIST}] do={{'
        f':local c [/ip firewall address-list get $e comment];'
        f':if ($c~"^{tag}") do={{:put [/ip firewall address-list get $e address]}}}}'
    ])
    return {line.strip() for line in out.splitlines() if line.strip()}


def push(addresses, tag, timeout=None):
    """Добавляет адреса пачками. Возвращает количество добавленных."""
    addrs = sorted(addresses)
    suffix = f" timeout={timeout}" if timeout else ""
    added = 0
    for i in range(0, len(addrs), BATCH):
        chunk = addrs[i:i + BATCH]
        cmds = [
            f'/ip firewall address-list add list={LIST} address={a} '
            f'comment={tag}{suffix}'
            for a in chunk
        ]
        router(cmds)
        added += len(chunk)
        log(f"  добавлено {added}/{len(addrs)}")
    return added


def remove(addresses, tag):
    removed = 0
    addrs = sorted(addresses)
    for i in range(0, len(addrs), BATCH):
        chunk = addrs[i:i + BATCH]
        cmds = [
            f'/ip firewall address-list remove '
            f'[find where list={LIST} && address="{a}" && comment~"^{tag}"]'
            for a in chunk
        ]
        router(cmds)
        removed += len(chunk)
    return removed


def cmd_ip_base(args):
    wanted = set()
    for url in SOURCES_IP:
        text = fetch(url)
        got = parse_ip_list(text)
        log(f"{url.rsplit('/', 1)[-1]}: {len(got)} записей")
        wanted |= got
    log(f"итого в источниках: {len(wanted)}")

    have = existing(TAG_IP)
    log(f"уже на роутере под меткой {TAG_IP}: {len(have)}")

    to_add = wanted - have
    to_del = have - wanted
    log(f"к добавлению: {len(to_add)}, к удалению: {len(to_del)}")

    if args.dry_run:
        log("dry-run: роутер не менялся")
        return
    if to_del:
        remove(to_del, TAG_IP)
    if to_add:
        push(to_add, TAG_IP)
    log("готово")


def adguard_get(path, params=None):
    env = {}
    with open(os.path.join(ROOT, "secrets", "adguard.env")) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    url = env["ADGUARD_URL"].rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    auth = f"{env['ADGUARD_USER']}:{env['ADGUARD_PASS']}"
    import base64
    req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def cmd_dns_feed(args):
    suffixes, exact, keywords = set(), set(), set()
    for url in SOURCES_DOMAIN:
        s, e, k = parse_domain_list(fetch(url))
        suffixes |= s
        exact |= e
        keywords |= k
    log(f"доменный набор: суффиксов {len(suffixes)}, точных {len(exact)}, "
        f"ключевых слов {len(keywords)}")

    data = adguard_get("/control/querylog", {"limit": args.limit})
    entries = data.get("data") or []
    log(f"записей из query-лога: {len(entries)}")

    wanted, hit_domains = set(), set()
    for entry in entries:
        name = ((entry.get("question") or {}).get("name") or "")
        if not name or not domain_matches(name, suffixes, exact, keywords):
            continue
        for ans in entry.get("answer") or []:
            if ans.get("type") == "A":
                addr = str(ans.get("value") or "")
                if addr and not ip_in_never(addr + "/32"):
                    wanted.add(addr + "/32")
                    hit_domains.add(name.lower())

    log(f"совпало доменов: {len(hit_domains)}, из них IP: {len(wanted)}")
    if args.verbose:
        for d in sorted(hit_domains)[:30]:
            log(f"    {d}")

    have = existing(TAG_DNS)
    to_add = wanted - have
    log(f"уже под меткой {TAG_DNS}: {len(have)}, к добавлению: {len(to_add)}")

    if args.dry_run:
        log("dry-run: роутер не менялся")
        return
    if to_add:
        push(to_add, TAG_DNS, timeout=args.timeout)
    log("готово")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("ip-base", help="статическая IP-база ReFilter")
    p1.add_argument("--dry-run", action="store_true")
    p1.set_defaults(func=cmd_ip_base)

    p2 = sub.add_parser("dns-feed", help="поток из query-лога AdGuard")
    p2.add_argument("--limit", type=int, default=5000,
                    help="сколько последних записей лога разбирать")
    p2.add_argument("--timeout", default="1d",
                    help="время жизни записи на роутере (RouterOS-формат)")
    p2.add_argument("--dry-run", action="store_true")
    p2.add_argument("--verbose", action="store_true")
    p2.set_defaults(func=cmd_dns_feed)

    args = ap.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        log(f"ОШИБКА: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
