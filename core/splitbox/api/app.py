"""Веб-приложение коробки: онбординг, дашборд, каталог, устройства, подписки.

Сервер-рендеринг (Jinja2) + ванильный JS, как в доноре vpn-ui.py: ноль
внешних фронтенд-зависимостей — нечего вендорить и нечему ломаться без
сети. FastAPI — ради нормальной формы/валидации/тестируемости.

Все эндпоинты синхронные (def, не async): FastAPI гоняет их в тредпуле,
а внутри — файловый ввод-вывод и subprocess (sing-box check, curl-проба),
которым в event-loop не место.
"""
from __future__ import annotations

import datetime
import html
import io
import logging
import threading
import urllib.parse

import segno
import yaml
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from .. import adguard as adguard_mod
from .. import apply as apply_mod
from .. import catalog, health, subs, wg
from ..model import (Config, DomainRule, Mode, NetworkRule, OwnServer, Policy,
                     Subscription)
from . import auth, state

log = logging.getLogger("splitbox.api")

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
limiter = auth.LoginLimiter()

app = FastAPI(title="splitbox", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


# --- Вспомогательное ---------------------------------------------------------

def _logged_in(request: Request, cfg: Config) -> bool:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return bool(token) and auth.check_session(cfg.admin.session_secret, token)


def _guard(request: Request, cfg: Config) -> RedirectResponse | None:
    """Куда отправить неавторизованного: на онбординг или на вход."""
    if not cfg.admin.password_hash:
        return RedirectResponse("/setup", status_code=303)
    if not _logged_in(request, cfg):
        return RedirectResponse("/login", status_code=303)
    return None


def _page(request: Request, name: str, cfg: Config, **ctx) -> HTMLResponse:
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ctx["mode"] = cfg.mode.value
    ctx.setdefault("cfg", cfg)
    return templates.TemplateResponse(request, name, ctx)


def _redirect(url: str, msg: str = "", err: str = "") -> RedirectResponse:
    if msg:
        url += ("&" if "?" in url else "?") + "msg=" + urllib.parse.quote(msg)
    if err:
        url += ("&" if "?" in url else "?") + "err=" + urllib.parse.quote(err)
    return RedirectResponse(url, status_code=303)


def _try_apply(cfg: Config) -> tuple[str, str]:
    """(msg, err) для флеша. Ошибка применения не роняет страницу:
    конфиг-файл уже сохранён, боевой sing-box остался на старом."""
    try:
        return apply_mod.apply(cfg), ""
    except apply_mod.ApplyError as exc:
        return "", str(exc)


def _collect_backups() -> list[dict]:
    """Общий пул резерва: все включённые подписки + ручные ссылки.

    Сетевые запросы идут ВНЕ замка конфига (они медленные), метаданные
    подписок (когда обновлялась, сколько живых) сохраняются отдельным
    update. Если совсем всё пусто — старый кэш не затирается (атомарность
    донора: одна плохая загрузка не должна лишать резерва)."""
    cfg = state.get()
    results = {s.id: subs.fetch_subscription(s.url, hwid=s.hwid)
               for s in cfg.enabled_subscriptions()}
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")

    def put(c: Config):
        for sub in c.subscriptions:
            if sub.id in results:
                sub.last_refresh = now
                sub.last_count = len(results[sub.id].outbounds)
    cfg = state.update(put)

    pool: list[dict] = []
    used: set = set()
    for result in results.values():
        for ob in result.outbounds:
            ob = dict(ob)
            ob["tag"] = subs.safe_tag(ob["tag"].removeprefix("bk-"), used)
            pool.append(ob)
    for link in cfg.manual_nodes:
        try:
            ob = subs.parse_manual_link(link)
            ob["tag"] = subs.safe_tag(ob["tag"].removeprefix("bk-"), used)
            pool.append(ob)
        except ValueError:
            continue
    if pool:
        apply_mod.save_backups(pool)
    return pool or apply_mod.load_backups()


# --- Онбординг ---------------------------------------------------------------

def _setup_gate(request: Request) -> HTMLResponse | None:
    """До установки пароля вебка на VPS торчит в интернет — окно, в которое
    пароль мог бы поставить кто угодно. Инсталлер генерирует одноразовый
    токен и печатает ссылку с ним; без токена мастер не открывается.
    Дома (без переменной) токен не требуется."""
    import os
    expected = os.environ.get("SPLITBOX_SETUP_TOKEN", "")
    if not expected:
        return None
    got = request.query_params.get("token", "") or \
        request.cookies.get("splitbox_setup", "")
    if got == expected:
        return None
    return HTMLResponse(
        "<h1>Нужна ссылка из установщика</h1>"
        "<p>Откройте адрес вида /setup?token=… — он напечатан "
        "в конце установки (splitbox install).</p>", status_code=403)


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    cfg = state.get()
    if cfg.admin.password_hash and not _logged_in(request, cfg):
        return RedirectResponse("/login", status_code=303)
    if not cfg.admin.password_hash and (gate := _setup_gate(request)):
        return gate
    step = int(request.query_params.get("step", "1"))
    if cfg.admin.password_hash and step == 1:
        step = 2
    ctx: dict = {"step": step}
    if step == 4:
        peer = cfg.wireguard.peers[-1] if cfg.wireguard.peers else None
        ctx["peer"] = peer
    if step == 5:
        ctx["tunnel"] = health.probe_tunnel()
    resp = _page(request, "setup.html", cfg, **ctx)
    token = request.query_params.get("token", "")
    if token:
        # токен переезжает в cookie, чтобы POST-формы мастера не таскали его
        resp.set_cookie("splitbox_setup", token, httponly=True,
                        samesite="strict", max_age=3600)
    return resp


@app.post("/setup/password")
def setup_password(request: Request, password: str = Form(...),
                   password2: str = Form(...)):
    cfg = state.get()
    if cfg.admin.password_hash:
        return _redirect("/setup?step=2")
    if gate := _setup_gate(request):
        return gate
    if len(password) < 8:
        return _redirect("/setup?step=1", err="Пароль короче 8 символов")
    if password != password2:
        return _redirect("/setup?step=1", err="Пароли не совпадают")
    cfg = state.update(lambda c: setattr(
        c.admin, "password_hash", auth.hash_password(password)))
    resp = _redirect("/setup?step=2")
    resp.set_cookie(auth.SESSION_COOKIE,
                    auth.make_session(cfg.admin.session_secret),
                    httponly=True, samesite="strict",
                    max_age=auth.SESSION_TTL)
    return resp


@app.post("/setup/source")
def setup_source(request: Request, link: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    link = link.strip()
    if not link:
        return _redirect("/setup?step=2", err="Вставьте ссылку")

    def put(c: Config):
        # Пресет политик — при первом источнике, чтобы «просто заработало».
        if not c.policies.rulesets:
            c.policies.rulesets = {k: Policy(v)
                                   for k, v in catalog.default_policies().items()}
        if link.startswith(("http://", "https://")):
            c.subscriptions.append(Subscription(name="Подписка", url=link))
        else:
            ob = subs.parse_manual_link(link)   # ValueError -> покажем ниже
            if ob["type"] == "vless":
                tls = ob.get("tls", {})
                c.own_servers.append(OwnServer(
                    name=ob["tag"].removeprefix("bk-"),
                    server=ob["server"], server_port=ob["server_port"],
                    uuid=ob["uuid"], flow=ob.get("flow", ""),
                    sni=tls.get("server_name", ""),
                    fingerprint=tls.get("utls", {}).get("fingerprint", "chrome"),
                    reality_public_key=tls.get("reality", {}).get("public_key", ""),
                    reality_short_id=tls.get("reality", {}).get("short_id", ""),
                ))
            else:
                c.manual_nodes.append(link)
        wg.ensure_server_keys(c)
        if not c.endpoint_host:
            c.endpoint_host = (request.headers.get("host", "").split(":")[0]
                               or "")
    try:
        cfg = state.update(put)
    except ValueError as exc:
        return _redirect("/setup?step=2", err=str(exc))

    n = 0
    if cfg.subscriptions:
        n = len(_collect_backups())
        cfg = state.get()          # _collect_backups обновил last_count
        if n == 0:
            return _redirect("/setup?step=2",
                             err="Подписка не отдала ни одного рабочего сервера")
    msg, err = _try_apply(cfg)
    if err:
        return _redirect("/setup?step=2", err=err)
    return _redirect("/setup?step=3",
                     msg=f"Найдено серверов: {n}" if n else "Сервер добавлен")


@app.post("/setup/device")
def setup_device(request: Request, name: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    name = name.strip() or "Устройство"

    def put(c: Config):
        wg.ensure_server_keys(c)
        wg.new_peer(c, name)
    cfg = state.update(put)
    msg, err = _try_apply(cfg)
    return _redirect("/setup?step=4", err=err)


# --- Вход --------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    cfg = state.get()
    if not cfg.admin.password_hash:
        return RedirectResponse("/setup", status_code=303)
    return _page(request, "login.html", cfg)


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    cfg = state.get()
    if not limiter.allowed():
        return _redirect("/login", err="Слишком много попыток — подождите минуту")
    ok = auth.verify_password(password, cfg.admin.password_hash)
    limiter.record(ok)
    if not ok:
        return _redirect("/login", err="Неверный пароль")
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(auth.SESSION_COOKIE,
                    auth.make_session(cfg.admin.session_secret),
                    httponly=True, samesite="strict",
                    max_age=auth.SESSION_TTL)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


# --- Дашборд -----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    tunnel = health.probe_tunnel()
    dns_ok = health.probe_dns()
    return _page(request, "dashboard.html", cfg,
                 tunnel=tunnel, dns_ok=dns_ok,
                 n_subs=len(cfg.enabled_subscriptions()),
                 n_backups=len(apply_mod.load_backups()))


@app.get("/api/status")
def api_status():
    tunnel = health.probe_tunnel()
    return {"tunnel": tunnel.ok, "exit_ip": tunnel.exit_ip,
            "country": tunnel.country, "dns": health.probe_dns()}


# --- Каталог сервисов --------------------------------------------------------

@app.get("/services", response_class=HTMLResponse)
def services_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    groups = catalog.services()
    policies = {k: p.value for k, p in cfg.policies.rulesets.items()}
    return _page(request, "services.html", cfg, groups=groups, policies=policies)


@app.post("/services")
async def services_save(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    form = await request.form()

    def put(c: Config):
        # Параллельных списков нет: имя поля несёт ключ сервиса целиком —
        # рассинхронизация значений и политик невозможна по построению
        # (урок parse_qs/keep_blank_values из донора).
        out = {}
        for key in catalog.known_keys():
            mode = form.get(f"p:{key}", "off")
            if mode in ("own", "fast"):
                out[key] = Policy(mode)
        c.policies.rulesets = out
    cfg = state.update(put)
    msg, err = _try_apply(cfg)
    return _redirect("/services", msg=msg, err=err)


# --- Свои домены и подсети ---------------------------------------------------

@app.get("/lists", response_class=HTMLResponse)
def lists_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    return _page(request, "lists.html", cfg,
                 domains=cfg.policies.domains, networks=cfg.policies.networks)


@app.post("/lists")
async def lists_save(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    form = await request.form()
    # Значение и политика склеены в одном поле «policy|value» на строку —
    # параллельные списки запрещены (донорская грабля рассинхронизации).
    rows = form.getlist("row")
    try:
        def put(c: Config):
            domains, networks = [], []
            for row in rows:
                kind, policy, value = row.split("|", 2)
                value = value.strip()
                if not value or policy == "drop":
                    continue
                if kind == "d":
                    domains.append(DomainRule(value=value, policy=Policy(policy)))
                else:
                    networks.append(NetworkRule(value=value, policy=Policy(policy)))
            c.policies.domains = domains
            c.policies.networks = networks
        cfg = state.update(put)
    except Exception as exc:  # noqa: BLE001 — покажем пользователю
        return _redirect("/lists", err=f"Строка не принята: {exc}")
    msg, err = _try_apply(cfg)
    return _redirect("/lists", msg=msg, err=err)


# --- Устройства (WireGuard) --------------------------------------------------

@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    return _page(request, "devices.html", cfg, peers=cfg.wireguard.peers,
                 endpoint_host=cfg.endpoint_host)


@app.post("/devices/add")
def device_add(request: Request, name: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard

    def put(c: Config):
        wg.ensure_server_keys(c)
        wg.new_peer(c, name.strip() or "Устройство")
    cfg = state.update(put)
    peer = cfg.wireguard.peers[-1]
    msg, err = _try_apply(cfg)
    return _redirect(f"/devices?show={peer.id}", msg=msg, err=err)


@app.post("/devices/{peer_id}/delete")
def device_delete(request: Request, peer_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    cfg = state.update(lambda c: c.wireguard.peers.__setitem__(
        slice(None), [p for p in c.wireguard.peers if p.id != peer_id]))
    msg, err = _try_apply(cfg)
    return _redirect("/devices", msg=msg or "Устройство удалено", err=err)


@app.get("/devices/{peer_id}/conf")
def device_conf(request: Request, peer_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    peer = next((p for p in cfg.wireguard.peers if p.id == peer_id), None)
    if not peer:
        return PlainTextResponse("нет такого устройства", status_code=404)
    text = wg.client_conf(cfg, peer)
    # Заголовки HTTP — latin-1: кириллическое имя устройства кладём
    # в filename* (RFC 5987), а в filename — ASCII-запасной вариант.
    ascii_name = "".join(ch for ch in peer.name if ord(ch) < 128).strip() or "device"
    quoted = urllib.parse.quote(peer.name)
    return PlainTextResponse(text, headers={
        "Content-Disposition":
            f'attachment; filename="{ascii_name}.conf"; '
            f"filename*=UTF-8''{quoted}.conf"})


@app.get("/devices/{peer_id}/qr.svg")
def device_qr(request: Request, peer_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    peer = next((p for p in cfg.wireguard.peers if p.id == peer_id), None)
    if not peer:
        return PlainTextResponse("нет такого устройства", status_code=404)
    buf = io.BytesIO()
    segno.make(wg.client_conf(cfg, peer)).save(buf, kind="svg", scale=4,
                                               dark="#e8eaed", light=None)
    return Response(buf.getvalue(), media_type="image/svg+xml")


# --- Подписки и серверы ------------------------------------------------------

@app.get("/subscriptions", response_class=HTMLResponse)
def subscriptions_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    return _page(request, "subscriptions.html", cfg,
                 subscriptions=cfg.subscriptions, own_servers=cfg.own_servers,
                 manual_nodes=cfg.manual_nodes,
                 n_backups=len(apply_mod.load_backups()))


@app.post("/subscriptions/add")
def subscription_add(request: Request, name: str = Form(""), url: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    url = url.strip()
    if url.startswith(("vless://", "trojan://", "ss://")):
        try:
            subs.parse_manual_link(url)
        except ValueError as exc:
            return _redirect("/subscriptions", err=str(exc))
        cfg = state.update(lambda c: c.manual_nodes.append(url))
    elif url.startswith(("http://", "https://")):
        cfg = state.update(lambda c: c.subscriptions.append(
            Subscription(name=name.strip() or "Подписка", url=url)))
    else:
        return _redirect("/subscriptions",
                         err="Нужна ссылка на подписку (https://…) или vless://")
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/subscriptions", msg=msg, err=err)


@app.post("/subscriptions/{sub_id}/toggle")
def subscription_toggle(request: Request, sub_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard

    def put(c: Config):
        for s in c.subscriptions:
            if s.id == sub_id:
                s.enabled = not s.enabled
    cfg = state.update(put)
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/subscriptions", msg=msg, err=err)


@app.post("/subscriptions/{sub_id}/delete")
def subscription_delete(request: Request, sub_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    cfg = state.update(lambda c: c.subscriptions.__setitem__(
        slice(None), [s for s in c.subscriptions if s.id != sub_id]))
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/subscriptions", msg=msg or "Подписка удалена", err=err)


@app.post("/subscriptions/own/{idx}/delete")
def own_server_delete(request: Request, idx: int):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    if not (0 <= idx < len(cfg.own_servers)):
        return _redirect("/subscriptions", err="Нет такого сервера")
    cfg = state.update(lambda c: c.own_servers.pop(idx))
    msg, err = _try_apply(cfg)
    return _redirect("/subscriptions", msg=msg or "Сервер удалён", err=err)


@app.post("/subscriptions/manual/{idx}/delete")
def manual_node_delete(request: Request, idx: int):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    if not (0 <= idx < len(cfg.manual_nodes)):
        return _redirect("/subscriptions", err="Нет такой ссылки")
    state.update(lambda c: c.manual_nodes.pop(idx))
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/subscriptions", msg=msg or "Ссылка удалена", err=err)


@app.post("/subscriptions/refresh")
def subscriptions_refresh(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    n = len(_collect_backups())
    msg, err = _try_apply(state.get())
    return _redirect("/subscriptions",
                     msg=msg and f"Обновлено, серверов в резерве: {n}", err=err)


# --- Настройки ---------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    return _page(request, "settings.html", cfg)


@app.post("/settings")
def settings_save(request: Request, endpoint_host: str = Form(""),
                  adblock: str = Form(""), password: str = Form(""),
                  password2: str = Form("")):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    if password:
        if len(password) < 8:
            return _redirect("/settings", err="Пароль короче 8 символов")
        if password != password2:
            return _redirect("/settings", err="Пароли не совпадают")

    def put(c: Config):
        c.endpoint_host = endpoint_host.strip()
        c.dns.adblock = bool(adblock)
        if password:
            c.admin.password_hash = auth.hash_password(password)
    cfg = state.update(put)
    # Живой тумблер AdGuard — через его API; провал не роняет сохранение
    # (config.yaml уже записан, bootstrap применит при пересоздании).
    adguard_mod.set_protection(cfg.dns.adblock)
    msg, err = _try_apply(cfg)
    return _redirect("/settings", msg=msg or "Сохранено", err=err)


@app.get("/settings/backup")
def settings_backup(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    from .. import paths
    if not paths.CONFIG.exists():
        return PlainTextResponse("конфига ещё нет", status_code=404)
    return PlainTextResponse(paths.CONFIG.read_text(), headers={
        "Content-Disposition": 'attachment; filename="splitbox-config.yaml"'})


@app.post("/settings/restore")
def settings_restore(request: Request, backup: UploadFile = File(...)):
    """Восстановление из бэкапа: файл валидируется моделью ЦЕЛИКОМ до
    записи — битый или чужой YAML не должен затереть рабочее состояние."""
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    try:
        raw = backup.file.read(1 << 20)
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError("это не config.yaml")
        from .. import store as store_mod
        restored = Config.model_validate(store_mod.migrate(data))
    except Exception as exc:      # noqa: BLE001 — покажем пользователю
        return _redirect("/settings", err=f"Бэкап не принят: {exc}")
    if not restored.admin.password_hash:
        return _redirect("/settings", err="Бэкап не принят: в нём нет пароля")
    state.replace(restored)
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/settings",
                     msg=msg and "Восстановлено из бэкапа. " + msg, err=err)


# --- Планировщик суточного refresh -------------------------------------------

def _scheduler():
    import random
    import time as _time
    _time.sleep(random.randint(60, 300))
    while True:
        try:
            cfg = state.get()
            if cfg.enabled_subscriptions():
                _collect_backups()
                apply_mod.apply(state.get())
                log.info("суточный refresh подписок выполнен")
        except Exception as exc:      # noqa: BLE001 — фон не должен умирать
            log.warning("суточный refresh не удался: %s", exc)
        _time.sleep(24 * 3600)


@app.on_event("startup")
def start_scheduler():
    threading.Thread(target=_scheduler, daemon=True).start()
