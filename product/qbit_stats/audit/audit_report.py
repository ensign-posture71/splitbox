#!/usr/bin/env python3
"""Маленький отчёт по логу аудит-прокси qBittorrent."""
from __future__ import annotations
import argparse
import collections
import json
import pathlib


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Показать, кто открывал qBittorrent через аудит-прокси")
    parser.add_argument("--log", default="/opt/qbittorrent-audit/logs/access.log")
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args()

    counts: collections.Counter[str] = collections.Counter()
    statuses: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    path = pathlib.Path(args.log)
    if not path.exists():
        print(f"лог не найден: {path}")
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        request = record.get("request") or {}
        ip = request.get("remote_ip") or request.get("client_ip") or "unknown"
        uri = (request.get("uri") or "")
        if uri.startswith("/api/"):
            continue
        counts[ip] += 1
        try:
            statuses[ip][int(record.get("status") or 0)] += 1
        except ValueError:
            pass
    if not counts:
        print("обращений к UI пока нет")
        return
    for ip, count in counts.most_common(args.top):
        print(f"{ip:<18}{count:>6}  {sum(statuses[ip].values())} всего")


if __name__ == "__main__":
    main()
