#!/usr/bin/env python3
"""Супервизор контейнера gateway: обвязка сети + sing-box + fail-open.

Один процесс владеет всем жизненным циклом — это осознанный перенос
донорской грабли «PartOf= не пробрасывает запуск»: когда обвязка tproxy
и sing-box были разными systemd-юнитами, их рассинхронизация однажды
стоила петли маршрутизации. Здесь порядок «сначала сеть, потом sing-box,
при остановке — снять nft» зашит в код, расщепить его нельзя.

Обязанности:
  * режим lan-gateway: sysctl, ip rule/route для tproxy, две nft-таблицы —
    базовая (forward+masquerade, стоит всегда) и tproxy-слой (перехват);
  * запуск sing-box и его перезапуск с backoff при падении;
  * unix-socket $STATE/run/gateway.sock: команда reload от веб-приложения
    (после успешного sing-box check) перезапускает sing-box;
  * watchdog: проба туннеля БОЕВЫМ путём раз в 30 с; два провала подряд
    в режиме lan — снять tproxy-слой (LAN продолжает жить напрямую),
    восстановление — вернуть слой. Наследник tunnel-health.sh.

Чего тут нет: kill-switch. Философия проекта — fail-open: сломанный
туннель не должен оставлять людей без интернета.
"""
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

MODE = os.environ.get("MODE", "vps")
STATE = Path(os.environ.get("SPLITBOX_STATE", "/var/lib/splitbox"))
CONFIG = STATE / "rendered" / "singbox.json"
SOCK = STATE / "run" / "gateway.sock"

PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
PROBE_PROXY = "socks5h://127.0.0.1:1080"
PROBE_PERIOD = 30
FAILS_TO_OPEN = 2      # одиночный сбой не должен дёргать маршрутизацию

TPROXY_PORT = 7895
FWMARK = 1
RTABLE = 100

# --- nftables ----------------------------------------------------------------
# Базовый слой: обычный форвардинг LAN с masquerade. У коробки, в отличие
# от донора, нет Mikrotik, делающего NAT, поэтому masquerade — её работа.
# Слой стоит всегда: именно он держит LAN в интернете при снятом tproxy.
NFT_BASE = """
table ip splitbox-base
delete table ip splitbox-base
table ip splitbox-base {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname != "lo" masquerade
    }
}
"""

# tproxy-слой: перехват транзита в sing-box. ПОРЯДОК ПРАВИЛ КРИТИЧЕН —
# правило с приватными сетями стоит первым намеренно: без него в туннель
# уедет и трафик к самой коробке, включая SSH и вебку, по которым ею
# управляют (перенос vm/container/nftables-singbox.nft дословно).
NFT_TPROXY = f"""
table ip splitbox-tproxy
delete table ip splitbox-tproxy
table ip splitbox-tproxy {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        ip daddr {{
            0.0.0.0/8,
            10.0.0.0/8,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.168.0.0/16,
            224.0.0.0/4,
            240.0.0.0/4
        }} return

        # Трафик собственных docker-сетей коробки не перехватываем: это её
        # внутренняя кухня (сборка образов при обновлении, загрузка
        # контейнеров). Иначе обновление в режиме шлюза не проходит вовсе —
        # сборка не может достучаться до репозиториев пакетов.
        iifname "docker*" return
        iifname "br-*" return

        meta l4proto {{ tcp, udp }} meta mark set {FWMARK} \
            tproxy to 127.0.0.1:{TPROXY_PORT} accept
    }}
}}
"""


def log(msg: str) -> None:
    print(f"[gateway] {msg}", flush=True)


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r


def nft_load(script: str) -> None:
    r = subprocess.run(["nft", "-f", "-"], input=script,
                       capture_output=True, text=True)
    # «delete table» на несуществующей таблице — не ошибка (идемпотентность
    # донора); nft ругается, но вторая половина скрипта применяется. Если
    # таблица в итоге не появилась — вот это ошибка.
    name = script.split("table ip ", 1)[1].split()[0]
    if subprocess.run(["nft", "list", "table", "ip", name],
                      capture_output=True).returncode != 0:
        raise RuntimeError(f"nft: таблица {name} не установилась: {r.stderr.strip()}")


def nft_delete(name: str) -> None:
    subprocess.run(["nft", "delete", "table", "ip", name],
                   capture_output=True)


def own_addresses() -> set[str]:
    """Собственные адреса машины — по ним распознаётся петля."""
    out: set[str] = set()
    r = run(["ip", "-4", "-o", "addr", "show"], check=False)
    for line in r.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            addr = parts[parts.index("inet") + 1].split("/")[0]
            if not addr.startswith("127."):
                out.add(addr)
    return out


def loop_detected() -> str:
    """Признак петли маршрутизации: перехват ловит трафик, отправленный
    самой коробкой.

    Так бывает, когда на роутере трафик заворачивается по интерфейсу
    целиком, без исключения для адреса коробки: она отправляет пакет
    наружу, роутер видит его как трафик из локальной сети и возвращает
    обратно. Сеть в этом случае встаёт полностью, и понять причину
    снаружи почти невозможно — поэтому коробка распознаёт её сама.

    Возвращает пояснение или пустую строку.
    """
    mine = own_addresses()
    if not mine:
        return ""
    r = run(["nft", "-j", "list", "counters"], check=False)
    # Считаем не по счётчикам (их может не быть), а по факту: есть ли
    # среди перехваченных соединений те, что пришли с нашего адреса.
    conns = run(["ss", "-tn", "state", "established"], check=False).stdout
    for line in conns.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local, peer = parts[-2], parts[-1]
        l_ip = local.rsplit(":", 1)[0].strip("[]")
        p_ip = peer.rsplit(":", 1)[0].strip("[]")
        if l_ip in mine and p_ip in mine and l_ip != p_ip:
            return f"соединение {local} -> {peer} внутри самой коробки"
    return ""


def tproxy_harness_ok() -> bool:
    if subprocess.run(["nft", "list", "table", "ip", "splitbox-tproxy"],
                      capture_output=True).returncode != 0:
        return False
    rules = run(["ip", "rule", "show"], check=False).stdout
    return f"fwmark 0x{FWMARK:x} lookup {RTABLE}" in rules


def setup_lan_network(with_tproxy: bool = True) -> None:
    """Базовый слой ставится всегда, слой перехвата — отдельно.

    Перехват включается ТОЛЬКО когда sing-box действительно работает.
    Иначе свежая, ещё не настроенная коробка, назначенная шлюзом, уводила
    бы весь трафик сети в порт, которого никто не слушает: интернет
    пропадал бы до окончания настройки, а обновить её (тоже через сеть)
    было бы уже нельзя.
    """
    log("режим lan-gateway: ставлю сетевую обвязку")
    # На docker-хосте ip_forward обычно уже включён (docker его требует),
    # а /proc/sys в host-network контейнере может быть read-only — тогда
    # не пишем, а проверяем.
    forward = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        forward.write_text("1")
    except OSError:
        if forward.read_text().strip() != "1":
            raise RuntimeError(
                "net.ipv4.ip_forward=0 и /proc/sys недоступен на запись — "
                "включите форвардинг на хосте: sysctl -w net.ipv4.ip_forward=1")
    # ip rule/route идемпотентны через предварительное удаление
    subprocess.run(["ip", "rule", "del", "fwmark", str(FWMARK),
                    "lookup", str(RTABLE)], capture_output=True)
    run(["ip", "rule", "add", "fwmark", str(FWMARK), "lookup", str(RTABLE)])
    run(["ip", "route", "replace", "local", "0.0.0.0/0",
         "dev", "lo", "table", str(RTABLE)])
    nft_load(NFT_BASE)
    if with_tproxy:
        nft_load(NFT_TPROXY)


def teardown_lan_network() -> None:
    nft_delete("splitbox-tproxy")
    nft_delete("splitbox-base")
    subprocess.run(["ip", "rule", "del", "fwmark", str(FWMARK),
                    "lookup", str(RTABLE)], capture_output=True)


class Supervisor:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.stopping = False
        self.fails = 0
        self.failed_open = False

    # --- sing-box ------------------------------------------------------------

    def start_singbox(self) -> None:
        with self.lock:
            self.proc = subprocess.Popen(
                ["sing-box", "run", "-c", str(CONFIG)])
        log(f"sing-box запущен (pid {self.proc.pid})")
        # Перехват включаем только теперь: до этого момента заворачивать
        # трафик было некуда.
        if MODE == "lan-gateway" and not self.failed_open:
            try:
                nft_load(NFT_TPROXY)
                log("перехват LAN включён")
            except RuntimeError as exc:
                log(f"перехват включить не удалось: {exc}")

    def stop_singbox(self) -> None:
        # Сначала снимаем перехват, потом гасим процесс: иначе между
        # остановкой и следующим стартом трафик сети уходил бы в никуда.
        if MODE == "lan-gateway":
            nft_delete("splitbox-tproxy")
        with self.lock:
            proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def reload(self) -> str:
        """Команда от веб-приложения: конфиг уже проверен sing-box check."""
        log("reload: перезапускаю sing-box")
        self.stop_singbox()
        self.start_singbox()
        return "ok"

    # --- unix-socket для команд ---------------------------------------------

    def serve_commands(self) -> None:
        SOCK.parent.mkdir(parents=True, exist_ok=True)
        SOCK.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(SOCK))
        os.chmod(SOCK, 0o660)
        server.listen(2)
        while not self.stopping:
            try:
                conn, _ = server.accept()
            except OSError:
                break
            with conn:
                try:
                    cmd = conn.recv(64).decode().strip()
                    if cmd == "reload":
                        conn.sendall(self.reload().encode())
                    elif cmd == "status":
                        alive = self.proc is not None and self.proc.poll() is None
                        conn.sendall(
                            f"singbox={'up' if alive else 'down'} "
                            f"failopen={'yes' if self.failed_open else 'no'}"
                            .encode())
                    else:
                        conn.sendall(b"unknown")
                except OSError:
                    pass

    # --- watchdog ------------------------------------------------------------

    def probe(self) -> bool:
        r = subprocess.run(
            ["curl", "-sS", "-4", "--proxy", PROBE_PROXY,
             "--max-time", "10", "-o", "/dev/null", PROBE_URL],
            capture_output=True)
        return r.returncode == 0

    def watchdog(self) -> None:
        """Наследник tunnel-health.sh: проверять результат, а не признак.

        В lan-режиме два провала подряд снимают tproxy-слой — LAN живёт
        напрямую (fail-open), восстановление возвращает слой. Отсутствие
        обвязки при живом туннеле — чинится, а не гасится (донор)."""
        while not self.stopping:
            time.sleep(PROBE_PERIOD)
            if self.stopping or not CONFIG.exists():
                continue
            singbox_alive = self.proc is not None and self.proc.poll() is None
            if (MODE == "lan-gateway" and not self.failed_open
                    and singbox_alive and not tproxy_harness_ok()):
                log("ОБВЯЗКА TPROXY ОТСУТСТВУЕТ — восстанавливаю")
                try:
                    setup_lan_network()
                except RuntimeError as exc:
                    log(f"восстановить обвязку не удалось: {exc}")
            # Петлю ищем только при включённом перехвате: без него её
            # быть не может.
            if MODE == "lan-gateway" and not self.failed_open:
                why = loop_detected()
                if why:
                    log("ВНИМАНИЕ: похоже на петлю маршрутизации — " + why)
                    log("  на роутере нужно правило-исключение для адреса "
                        "этой коробки ВЫШЕ правила заворачивания трафика")

            if self.probe():
                self.fails = 0
                if self.failed_open:
                    log("туннель восстановлен: возвращаю tproxy-слой")
                    try:
                        nft_load(NFT_TPROXY)
                        self.failed_open = False
                    except RuntimeError as exc:
                        log(f"вернуть tproxy-слой не удалось: {exc}")
                continue
            self.fails += 1
            log(f"проверка туннеля не прошла ({self.fails} подряд)")
            if (MODE == "lan-gateway" and self.fails >= FAILS_TO_OPEN
                    and not self.failed_open):
                log("ТУННЕЛЬ СЛОМАН: снимаю tproxy-слой, LAN идёт напрямую")
                nft_delete("splitbox-tproxy")
                self.failed_open = True

    # --- главный цикл --------------------------------------------------------

    def main(self) -> None:
        if MODE == "lan-gateway":
            try:
                setup_lan_network(with_tproxy=False)
            except (RuntimeError, PermissionError, OSError) as exc:
                log(f"ОШИБКА: обвязка lan-режима не установилась: {exc}")
                log("на этом устройстве доступен только режим vps (WireGuard) —"
                    " проверьте NET_ADMIN и поддержку tproxy ядром")
                sys.exit(1)

        threading.Thread(target=self.serve_commands, daemon=True).start()
        threading.Thread(target=self.watchdog, daemon=True).start()

        def stop(*_):
            self.stopping = True
            self.stop_singbox()
            if MODE == "lan-gateway":
                teardown_lan_network()
            sys.exit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        while not CONFIG.exists():
            log(f"жду конфиг {CONFIG} — откройте вебку и пройдите настройку "
                "(перехват LAN пока выключен, сеть работает напрямую)")
            time.sleep(5)

        backoff = 1
        while not self.stopping:
            if self.proc is None or self.proc.poll() is not None:
                if self.proc is not None:
                    log(f"sing-box умер (код {self.proc.returncode}), "
                        f"перезапуск через {backoff} с")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                else:
                    backoff = 1
                self.start_singbox()
                # успешная минута работы сбрасывает backoff
                started = time.monotonic()
                while (self.proc.poll() is None and not self.stopping
                       and time.monotonic() - started < 60):
                    time.sleep(1)
                if self.proc and self.proc.poll() is None:
                    backoff = 1
            time.sleep(1)


if __name__ == "__main__":
    Supervisor().main()
