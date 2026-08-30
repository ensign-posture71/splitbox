"""Определение имён устройств в локальной сети.

Роутеры знают имена (из DHCP-запросов), но почти никогда не отдают их
наружу: обратный DNS у большинства домашних роутеров пуст. Поэтому имя
спрашивается у самого устройства — так это работает у всех, независимо
от модели роутера и без доступа к нему.

Три способа, от дешёвого к дорогому:
  * обратный DNS — сработает там, где роутер всё же ведёт зону;
  * NBNS (порт 137) — отвечают Windows и всё, что говорит по SMB;
  * mDNS (порт 5353) — отвечают устройства Apple, Android и Linux с avahi.

Опрос идёт в фоне и с кэшем: на странице статистики он не должен
задерживать ответ ни на секунду.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("splitbox.discovery")

TIMEOUT = 1.0
CACHE_TTL = 3600          # имена меняются редко
NEGATIVE_TTL = 300        # не тревожить молчунов слишком часто


def _reverse_dns(ip: str, timeout: float) -> str:
    """Свой PTR-запрос к локальному резолверу.

    Не gethostbyaddr: системный резолвер перебирает серверы по своему
    расписанию и на молчащий адрес тратит десятки секунд, игнорируя любой
    таймаут. Здесь один пакет и жёсткий срок ответа.
    """
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    labels = b"".join(bytes([len(p)]) + p.encode() for p in rev.split(".")) + b"\x00"
    query = (struct.pack(">H", 0x1234) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + labels + b"\x00\x0c\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, ("127.0.0.1", 53))
        data, _ = s.recvfrom(512)
    except OSError:
        return ""
    finally:
        s.close()
    if len(data) < 12 or struct.unpack(">H", data[6:8])[0] == 0:
        return ""
    # Ответ начинается после запроса; имя может быть сжатым, поэтому
    # берём первую нормальную метку.
    pos = 12 + len(labels) + 4 + 12
    parts = []
    while pos < len(data):
        ln = data[pos]
        if ln == 0 or ln > 63 or pos + 1 + ln > len(data):
            break
        parts.append(data[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
        pos += 1 + ln
    return parts[0] if parts else ""


def _nbns(ip: str, timeout: float) -> str:
    """Запрос NBSTAT: имя NetBIOS. Формат древний, но живой в каждой Windows."""
    query = (struct.pack(">H", 0x4242) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
    except OSError:
        return ""
    finally:
        s.close()
    if len(data) < 57:
        return ""
    count = data[56]
    pos = 57
    for _ in range(count):
        if pos + 18 > len(data):
            break
        raw = data[pos:pos + 15].decode("latin-1").strip()
        flags = data[pos + 16]
        # Групповые имена (рабочая группа) пропускаем — нужно имя машины.
        if raw and not flags & 0x80:
            return raw
        pos += 18
    return ""


MDNS_GROUP = "224.0.0.251"


def _decode_name(data: bytes, pos: int) -> str:
    """Первая метка имени с учётом сжатия ссылок (DNS-компрессия)."""
    for _ in range(8):                      # защита от кольцевых ссылок
        if pos >= len(data):
            return ""
        ln = data[pos]
        if ln & 0xC0 == 0xC0:               # ссылка на другое место пакета
            if pos + 1 >= len(data):
                return ""
            pos = ((ln & 0x3F) << 8) | data[pos + 1]
            continue
        if ln == 0 or ln > 63 or pos + 1 + ln > len(data):
            return ""
        return data[pos + 1:pos + 1 + ln].decode("utf-8", "replace")
    return ""


def _mdns(ip: str, timeout: float) -> str:
    """Обратный mDNS-запрос: так представляются Apple, Android и Linux.

    Запрос уходит на групповой адрес, а не на само устройство: спрашивать
    напрямую разрешено не всеми реализациями, а групповой слышат все.
    Ответ приходит от нужного адреса, остальные пакеты в сети игнорируем.
    """
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    labels = b"".join(bytes([len(p)]) + p.encode() for p in rev.split(".")) + b"\x00"
    query = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + labels + b"\x00\x0c\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    # Ответы mDNS приходят на порт 5353 группы, а не на порт запроса,
    # поэтому слушать надо именно его и состоять в группе. Если порт
    # занят (на машине уже есть свой mDNS-демон) — способ пропускаем.
    try:
        s.bind(("", 5353))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0"))
    except OSError:
        s.close()
        return ""
    s.settimeout(timeout)
    try:
        s.sendto(query, (MDNS_GROUP, 5353))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s.settimeout(max(deadline - time.monotonic(), 0.05))
            try:
                data, addr = s.recvfrom(2048)
            except OSError:
                break
            if addr[0] != ip or len(data) < 12:
                continue                    # чужой ответ в общей сети
            if struct.unpack(">H", data[6:8])[0] == 0:
                continue                    # ответов нет
            pos = 12 + len(labels) + 4      # пропускаем секцию вопроса
            pos += 2 + 2 + 2 + 4 + 2        # имя-ссылка, тип, класс, TTL, длина
            name = _decode_name(data, pos)
            if name:
                return name
    finally:
        s.close()
    return ""


def lookup(ip: str, timeout: float = TIMEOUT) -> str:
    """Имя устройства или пустая строка. Блокирует до timeout на способ."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if not addr.is_private or addr.is_loopback:
        return ""
    # mDNS отвечает не везде и ждать его дольше остальных смысла нет:
    # он идёт последним и с укороченным сроком.
    for probe, budget in ((_reverse_dns, timeout), (_nbns, timeout),
                          (_mdns, min(timeout, 0.7))):
        try:
            name = probe(ip, budget)
        except Exception:            # noqa: BLE001 — опрос не должен ронять сбор
            name = ""
        if name and name.lower() not in ("localhost", "unknown"):
            return name.strip(". ")
    return ""


class NameCache:
    """Имена с фоновым обновлением: страница берёт из кэша и не ждёт сеть."""

    def __init__(self) -> None:
        self._names: dict[str, tuple[str, float]] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def get(self, ip: str) -> str:
        now = time.monotonic()
        with self._lock:
            hit = self._names.get(ip)
            if hit:
                name, at = hit
                ttl = CACHE_TTL if name else NEGATIVE_TTL
                if now - at < ttl:
                    return name
            if ip in self._pending:
                return hit[0] if hit else ""
            self._pending.add(ip)
        threading.Thread(target=self._refresh, args=(ip,), daemon=True).start()
        return hit[0] if hit else ""

    def _refresh(self, ip: str) -> None:
        name = lookup(ip)
        with self._lock:
            self._names[ip] = (name, time.monotonic())
            self._pending.discard(ip)
        if name:
            log.info("устройство %s определилось как %r", ip, name)


cache = NameCache()
