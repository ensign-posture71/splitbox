#!/usr/bin/env python3
"""Синхронизация списка сервисов с DNS-статикой MikroTik (схема D19).

Для каждого домена из sync/abroad-services.list создаётся запись:

    /ip dns static add name=<домен> type=FWD match-subdomain=yes \\
        address-list=abroad forward-to=192.168.88.45

Механика: роутер и так DNS для всей сети (DHCP отдаёт 192.168.88.1).
Резолвя такой домен, он кладёт в address-list `abroad` **ровно те адреса,
которые в этот же момент отдал клиенту**. Расхождение между «что знает
роутер» и «куда пошёл клиент» становится невозможным.

Чем это лучше двух предыдущих подходов:
  * FQDN-записи в address-list — роутер резолвил домен сам, отдельно от
    клиента, и у сервисов с ротацией адресов (Meta, Google) списки
    расходились: клиент шёл на адрес, которого в списке нет (O31);
  * широкие диапазоны провайдеров — покрывают проценты всего IPv4,
    а помеченный трафик не проходит fasttrack, и роутер на 448 МГц
    обрабатывал бы медленным путём большую часть домашнего трафика.

Ограничение (важное): работает только для клиентов, которые резолвят
через роутер. Устройства с DoH/DoT ходят мимо (O27) — для них стеринг
не сработает. Отсюда практический смысл блокировки DoH/DoT (§7.8).

Скрипт идемпотентен и трогает только свои записи (comment=svc).

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
UPSTREAM = "192.168.88.45"   # AdGuard: цепочка резолвинга сети не меняется (D6)
BATCH = 25


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def read_services():
    domains = []
    with open(SERVICES) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                domains.append(line)
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
    out = router([
        f':foreach e in=[/ip dns static find where comment="{TAG}"] do='
        f'{{:put [/ip dns static get $e name]}}'
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
        router([f'/ip dns static remove [find where comment="{TAG}" && name="{d}"]'
                for d in to_del[i:i + BATCH]])

    for i in range(0, len(to_add), BATCH):
        router([
            f'/ip dns static add name={d} type=FWD match-subdomain=yes '
            f'address-list={LIST} forward-to={UPSTREAM} comment={TAG}'
            for d in to_add[i:i + BATCH]
        ])

    if to_add or to_del:
        # Кэш держит старые ответы, а вместе с ними — старые адреса.
        # Без сброса новые записи начнут наполнять список только по истечении TTL.
        router(["/ip dns cache flush"])
        log("кэш DNS сброшен")

    stats = router([
        f':put [:len [/ip dns static find where comment="{TAG}"]]',
        f':put [:len [/ip firewall address-list find where list={LIST}]]',
    ]).split()
    log(f"готово. DNS-записей: {stats[0]}, адресов в {LIST}: {stats[1]}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"ОШИБКА: {exc}")
        sys.exit(1)
