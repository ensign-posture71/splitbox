#!/usr/bin/env python3
"""Синхронизация curated-списка сервисов с address-list `abroad` на MikroTik.

Схема D16, ступень 1. Домены из sync/abroad-services.list кладутся на роутер
FQDN-записями: RouterOS резолвит их сам и поддерживает дочерние динамические
записи с актуальными адресами (проверено, O19).

Почему именно так, а не резолвинг на нашей стороне с заливкой IP:
клиентские устройства массово ходят по DoH/DoT мимо локального DNS (O27),
поэтому наблюдать за их резолвингом бесполезно. А FQDN-запись резолвит сам
роутер, и от поведения клиентов это не зависит вовсе.

Скрипт идемпотентен и трогает только свои записи — те, что помечены
комментарием TAG. Ручные записи владельца остаются нетронутыми.

  --dry-run   показать план, ничего не менять
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICES = os.path.join(ROOT, "sync", "abroad-services.list")

ROUTER = "192.168.88.1"
ROUTER_USER = "sync"
SSH_KEY = os.path.expanduser("~/.ssh/id_sync")
LIST = "abroad"
TAG = "svc"

# Записей на одну SSH-команду. Список короткий (десятки), но пачками
# всё равно быстрее и меньше рукопожатий.
BATCH = 40


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def read_services():
    domains = []
    with open(SERVICES) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                domains.append(line.lower())
    # Порядок не важен, но дубликаты создали бы лишние записи на роутере.
    return sorted(set(domains))


def router(commands):
    if not commands:
        return ""
    result = subprocess.run(
        ["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
         f"{ROUTER_USER}@{ROUTER}", "; ".join(commands)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SSH к роутеру: {result.stderr.strip()[:300]}")
    return result.stdout


def existing():
    """Статические записи, добавленные этим скриптом.

    dynamic=no отсеивает дочерние записи с резолвленными адресами —
    ими управляет сам RouterOS, трогать их нельзя.
    """
    out = router([
        f':foreach e in=[/ip firewall address-list find where list={LIST} && dynamic=no] do={{'
        f':local c [/ip firewall address-list get $e comment];'
        f':if ($c="{TAG}") do={{:put [/ip firewall address-list get $e address]}}}}'
    ])
    return {l.strip().lower() for l in out.splitlines() if l.strip()}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    wanted = set(read_services())
    log(f"в списке сервисов: {len(wanted)} доменов")

    have = existing()
    log(f"на роутере под меткой {TAG}: {len(have)}")

    to_add = sorted(wanted - have)
    to_del = sorted(have - wanted)
    log(f"добавить: {len(to_add)}, удалить: {len(to_del)}")
    for d in to_add:
        log(f"  + {d}")
    for d in to_del:
        log(f"  - {d}")

    if args.dry_run:
        log("dry-run: роутер не менялся")
        return

    for i in range(0, len(to_del), BATCH):
        router([
            f'/ip firewall address-list remove '
            f'[find where list={LIST} && address="{d}" && comment="{TAG}"]'
            for d in to_del[i:i + BATCH]
        ])
    for i in range(0, len(to_add), BATCH):
        router([
            f'/ip firewall address-list add list={LIST} address={d} comment={TAG}'
            for d in to_add[i:i + BATCH]
        ])

    total = router([
        f':put [:len [/ip firewall address-list find where list={LIST}]]'
    ]).strip()
    log(f"готово. записей в списке {LIST} всего (с дочерними динамическими): {total}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"ОШИБКА: {exc}")
        sys.exit(1)
