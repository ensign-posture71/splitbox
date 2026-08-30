"""Bootstrap-конфиг AdGuard Home.

Генерируется один раз при первом запуске (splitbox.bootstrap): с готовым
файлом AdGuard стартует сразу рабочим, без мастера первичной настройки
на :3000 — нетехнарь не должен настраивать два продукта.

Дальше AdGuard живёт своим конфигом (сам его переписывает); splitbox его
больше не трогает, кроме тумблера защиты через API. Веб-интерфейс AdGuard
слушает только 127.0.0.1 внутри netns стека — наружу не виден.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import yaml

from .model import Config

def _api(cfg: Config | None) -> str:
    """Адрес API. С включённым force_https http-порт только перенаправляет,
    поэтому ходим сразу на https — и не проверяем сертификат: он наш
    собственный, самоподписанный, а соединение не покидает localhost."""
    port = cfg.adguard.port_https if cfg else 3443
    return f"https://127.0.0.1:{port}"


def _ssl_ctx():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# schema_version намеренно старый из проверенных: AdGuard мигрирует старую
# схему вверх сам, а слишком новую от чужой версии — отвергает.
SCHEMA_VERSION = 20


def make_password(plain: str) -> str:
    """AdGuard принимает только bcrypt — другого формата он не понимает."""
    import bcrypt
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def tls_section(cfg: Config, cert: str, key: str) -> dict:
    """HTTPS для интерфейса AdGuard тем же сертификатом, что у панели.

    force_https означает, что http-порт только перенаправляет: ссылку
    в панели можно давать сразу на https, и человек не окажется на
    открытом соединении, даже если перейдёт по старому адресу.
    """
    return {
        "enabled": True,
        "server_name": "",
        "force_https": True,
        "port_https": cfg.adguard.port_https,
        "port_dns_over_tls": 0,
        "port_dns_over_quic": 0,
        "certificate_path": cert,
        "private_key_path": key,
    }


def default_config(cfg: Config, cert: str = "", key: str = "") -> dict:
    users = ([{"name": cfg.adguard.username,
               "password": cfg.adguard.password_bcrypt}]
             if cfg.adguard.password_bcrypt else [])
    return {
        "schema_version": SCHEMA_VERSION,
        # Слушает все адреса внутри сетевого пространства стека. В домашнем
        # режиме это адрес машины в локальной сети, в режиме VPS порт наружу
        # не публикуется — туда попадают только через WireGuard.
        "http": {"address": f"0.0.0.0:{cfg.adguard.port}"},
        "users": users,
        "dns": {
            "bind_hosts": ["0.0.0.0"],
            "port": 53,
            "upstream_dns": list(cfg.dns.upstreams),
            "bootstrap_dns": ["1.1.1.1", "8.8.8.8"],
            "cache_size": 4194304,
        },
        "filtering": {
            "protection_enabled": cfg.dns.adblock,
            "filtering_enabled": cfg.dns.adblock,
        },
        "filters": [{
            "enabled": True,
            "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "name": "AdGuard DNS filter",
            "id": 1,
        }],
        **({"tls": tls_section(cfg, cert, key)} if cert and key else {}),
    }


def _auth_header(cfg: Config | None) -> dict[str, str]:
    """AdGuard теперь за паролем — API тоже требует Basic-авторизацию."""
    if not cfg or not cfg.adguard.password_plain:
        return {}
    import base64
    raw = f"{cfg.adguard.username}:{cfg.adguard.password_plain}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def set_protection(enabled: bool, cfg: Config | None = None,
                   timeout: int = 5) -> bool:
    """Тумблер защиты через API AdGuard (без auth: users пуст, слушает
    только localhost внутри netns стека). False = AdGuard не ответил —
    не ошибка страницы: настройка сохранена в config.yaml и применится
    к bootstrap'у при пересоздании."""
    headers = {"Content-Type": "application/json"}
    headers.update(_auth_header(cfg))
    req = urllib.request.Request(
        f"{_api(cfg)}/control/protection",
        data=json.dumps({"enabled": enabled}).encode(),
        headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            return resp.status == 200
    except OSError:
        return False


def status(cfg: Config | None = None, timeout: int = 5) -> dict | None:
    """Состояние AdGuard или None, если он не отвечает."""
    req = urllib.request.Request(f"{_api(cfg)}/control/status",
                                 headers=_auth_header(cfg))
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            return json.load(resp)
    except (OSError, ValueError):
        return None


def counters(cfg: Config | None = None, timeout: int = 5) -> dict | None:
    """Счётчики фильтрации: сколько запросов и сколько из них заблокировано."""
    req = urllib.request.Request(f"{_api(cfg)}/control/stats",
                                 headers=_auth_header(cfg))
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            return json.load(resp)
    except (OSError, ValueError):
        return None


def ensure_access(cfg: Config, conf_dir: Path, cert: str = "",
                  key: str = "") -> bool:
    """Привести доступ к интерфейсу в соответствие с настройками коробки.

    Нужна для уже работающих установок: их AdGuardHome.yaml создан прошлой
    версией — слушает только localhost и пускает без пароля. Просто
    пересоздать файл нельзя (AdGuard хранит там свои списки и настройки),
    поэтому правим ровно два поля.
    """
    path = conf_dir / "AdGuardHome.yaml"
    if not path.exists() or not cfg.adguard.password_bcrypt:
        return False
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError:
        return False

    want_addr = f"0.0.0.0:{cfg.adguard.port}"
    changed = False
    http = data.setdefault("http", {})
    if http.get("address") != want_addr:
        http["address"] = want_addr
        changed = True
    if not data.get("users"):
        data["users"] = [{"name": cfg.adguard.username,
                          "password": cfg.adguard.password_bcrypt}]
        changed = True
    if cert and key and not (data.get("tls") or {}).get("enabled"):
        data["tls"] = tls_section(cfg, cert, key)
        changed = True
    if changed:
        tmp = path.with_suffix(".yaml.tmp")
        with open(tmp, "w") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)
        tmp.replace(path)
    return changed


def write_if_missing(cfg: Config, conf_dir: Path, cert: str = "",
                     key: str = "") -> bool:
    """True — файл создан; False — уже был (AdGuard им владеет, не трогаем)."""
    path = conf_dir / "AdGuardHome.yaml"
    if path.exists():
        return False
    conf_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    with open(tmp, "w") as fh:
        yaml.safe_dump(default_config(cfg, cert, key), fh, sort_keys=False)
    tmp.replace(path)
    return True


def clients(cfg: Config | None = None, timeout: int = 5) -> dict[str, str]:
    """Адрес устройства -> его имя, как их знает AdGuard.

    Два источника: заданные владельцем (persistent) и определённые
    автоматически по обратному DNS и DHCP-арендам роутера (auto_clients).
    Первые важнее: имя, которое человек написал сам, точнее того, что
    выдумал роутер.
    """
    req = urllib.request.Request(f"{_api(cfg)}/control/clients",
                                 headers=_auth_header(cfg))
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            data = json.load(resp)
    except (OSError, ValueError):
        return {}

    out: dict[str, str] = {}
    for c in data.get("auto_clients") or []:
        ip, name = c.get("ip"), (c.get("name") or "").strip()
        if ip and name:
            out[ip] = name.rstrip(".")
    for c in data.get("clients") or []:          # заданные вручную — важнее
        name = (c.get("name") or "").strip()
        for ip in c.get("ids") or []:
            if name and ip:
                out[ip] = name
    return out
