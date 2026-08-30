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
from .. import catalog, charts, health, paths, stats, subs, sysstats, wg
from .. import render as render_mod
from ..model import (Balancer, Config, DomainRule, Mode, NetworkRule,
                     OwnServer, Policy, Strategy, Subscription, WorkMode)
from . import auth, state

log = logging.getLogger("splitbox.api")

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
# Форматирование величин и подписи направлений — в шаблонах они нужны
# повсеместно, поэтому проще отдать их глобально, чем таскать в контексте.
templates.env.globals["human_bytes"] = stats.human_bytes
templates.env.globals["direction_label"] = charts.DIRECTION_LABEL
templates.env.globals["direction_color"] = charts.DIRECTION_COLOR
templates.env.globals["human_uptime"] = sysstats.human_uptime
templates.env.globals["sparkline"] = charts.sparkline
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


def _adguard_url(request: Request, cfg: Config) -> str:
    """Адрес интерфейса AdGuard — тот же хост, что и у панели, свой порт.

    По https: AdGuard получает тот же самоподписанный сертификат, что и
    панель, а его http-порт настроен только перенаправлять. Отправлять
    человека из защищённой панели на открытое соединение нельзя.
    """
    host = request.url.hostname or "127.0.0.1"
    return f"https://{host}:{cfg.adguard.port_https}"


def _page(request: Request, name: str, cfg: Config, **ctx) -> HTMLResponse:
    ctx.setdefault("adguard_url", _adguard_url(request, cfg))
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


# Последние сообщения провайдеров подписок («Вы превысили лимит устройств»
# и т.п.) — их показываем пользователю, когда рабочих серверов не нашлось.
_last_notices: list[str] = []


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
                r = results[sub.id]
                sub.last_refresh = now
                sub.last_count = len(r.outbounds)
                sub.last_notice = "; ".join(dict.fromkeys(r.notices))[:200]
    cfg = state.update(put)

    global _last_notices
    _last_notices = [n for r in results.values() for n in r.notices]

    pool: list[dict] = []
    used: set = set()
    for sub in cfg.subscriptions:
        result = results.get(sub.id)
        if not result:
            continue
        # Куда пускать серверы этой подписки — решает владелец: чужой
        # сервер видит весь проходящий через него трафик.
        groups = (["fast"] if sub.in_fast else []) + (["own"] if sub.in_own else [])
        for ob in result.outbounds:
            ob = dict(ob)
            ob["tag"] = subs.safe_tag(ob["tag"].removeprefix("bk-"), used)
            ob["_groups"] = groups
            pool.append(ob)
    for link in cfg.manual_nodes:
        try:
            ob = subs.parse_manual_link(link)
            ob["tag"] = subs.safe_tag(ob["tag"].removeprefix("bk-"), used)
            ob["_groups"] = ["fast"]
            pool.append(ob)
        except ValueError:
            continue
    if pool:
        apply_mod.save_backups(pool)
    return pool or apply_mod.load_backups()


def _no_servers_error() -> str:
    """Понятное объяснение, почему подписка не дала серверов.

    Панель почти всегда пишет причину человеческим языком прямо в имени
    записи-заглушки — это единственная подсказка, которую пользователь
    может понять и по которой может действовать.
    """
    base = "Подписка ответила, но рабочих серверов в ней нет."
    if _last_notices:
        quoted = "; ".join(dict.fromkeys(_last_notices))[:300]
        return (f"{base}\nПровайдер пишет: «{quoted}»\n"
                "Решите вопрос на стороне провайдера и повторите.")
    return (base + "\nОбычно это значит, что подписка неактивна или "
            "исчерпан лимит устройств — проверьте у провайдера.")


# --- Онбординг ---------------------------------------------------------------

SETUP_STEPS = 8


def _guess_external(request: Request) -> str:
    """Подсказка для поля внешнего адреса: то, через что человек сейчас
    открыл панель. Часто это и есть нужный адрес, но не всегда — поэтому
    подставляем как подсказку, а не молча."""
    host = request.url.hostname or ""
    return "" if host in ("localhost", "127.0.0.1") else host


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
    ctx: dict = {"step": step, "steps_total": SETUP_STEPS,
                 "guessed_host": _guess_external(request)}
    if step == 6:
        ctx["peer"] = cfg.wireguard.peers[-1] if cfg.wireguard.peers else None
    if step == 7:
        ctx["tunnel"] = health.probe_tunnel()
    if step == 8:
        # Финальный шаг — самый важный и самый пугающий: трогать роутер.
        # Без него коробка просто стоит и ничего не делает.
        ctx["box_ip"] = request.url.hostname or ""
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


@app.post("/setup/mode")
def setup_mode(request: Request, work_mode: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    try:
        mode = WorkMode(work_mode)
    except ValueError:
        return _redirect("/setup?step=2", err="Выберите режим работы")
    state.update(lambda c: setattr(c, "work_mode", mode))
    # В режиме «только локальная сеть» внешний адрес не нужен — шаг пропускаем.
    return _redirect("/setup?step=3" if mode is WorkMode.full
                     else "/setup?step=4")


@app.post("/setup/external")
def setup_external(request: Request, endpoint_host: str = Form("")):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    host = endpoint_host.strip()
    if host:
        state.update(lambda c: setattr(c, "endpoint_host", host))
    return _redirect("/setup?step=4")


@app.post("/setup/source")
def setup_source(request: Request, link: str = Form(...)):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    link = link.strip()
    if not link:
        return _redirect("/setup?step=4", err="Вставьте ссылку")

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
        return _redirect("/setup?step=4", err=str(exc))

    n = 0
    if cfg.subscriptions:
        n = len(_collect_backups())
        cfg = state.get()          # _collect_backups обновил last_count
        if n == 0:
            return _redirect("/setup?step=4", err=_no_servers_error())
    msg, err = _try_apply(cfg)
    if err:
        return _redirect("/setup?step=4", err=err)
    return _redirect("/setup?step=5",
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
    return _redirect("/setup?step=6", err=err)


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


# --- Серверы, подписки, балансировка -----------------------------------------

@app.get("/servers", response_class=HTMLResponse)
def servers_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    backups = apply_mod.load_backups()
    return _page(request, "servers.html", cfg,
                 backups=backups,
                 backup_tags=[b["tag"] for b in backups],
                 own_tags=[o["tag"] for o in render_mod._own_outbounds(cfg)])


@app.post("/servers")
async def servers_save(request: Request):
    """Массовое сохранение: имена, участие в группах, включённость,
    идентификаторы устройств и настройки обеих групп.

    Ключ строки входит в имя поля (own.3.name, sub.a1b2.hwid) — параллельных
    списков нет, поэтому рассинхронизация значений и флагов невозможна.
    """
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    form = await request.form()

    def put(c: Config):
        for i, srv in enumerate(c.own_servers):
            srv.name = (form.get(f"own.{i}.name") or srv.name).strip()
            srv.enabled = form.get(f"own.{i}.enabled") == "1"
            srv.in_own = form.get(f"own.{i}.in_own") == "1"
            srv.in_fast = form.get(f"own.{i}.in_fast") == "1"
        for sub in c.subscriptions:
            sub.name = (form.get(f"sub.{sub.id}.name") or sub.name).strip()
            sub.enabled = form.get(f"sub.{sub.id}.enabled") == "1"
            sub.in_fast = form.get(f"sub.{sub.id}.in_fast") == "1"
            sub.in_own = form.get(f"sub.{sub.id}.in_own") == "1"
            hwid = (form.get(f"sub.{sub.id}.hwid") or "").strip()
            if hwid:
                sub.hwid = hwid
        for group in ("own", "fast"):
            bal: Balancer = getattr(c.balancing, group)
            bal.strategy = Strategy(form.get(f"bal.{group}.strategy", "latency"))
            bal.interval = (form.get(f"bal.{group}.interval") or "5m").strip()
            bal.tolerance = int(form.get(f"bal.{group}.tolerance") or 60)
            bal.pinned_tag = (form.get(f"bal.{group}.pinned_tag") or "").strip()

    try:
        cfg = state.update(put)
    except Exception as exc:      # noqa: BLE001 — показываем пользователю
        return _redirect("/servers", err=f"Настройки не приняты: {exc}")
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/servers", msg=msg, err=err)


@app.post("/servers/add")
def server_add(request: Request, name: str = Form(""), url: str = Form(...)):
    """Одна форма на всё: по виду ссылки понятно, что добавляют."""
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    url = url.strip()
    try:
        if url.startswith(("http://", "https://")):
            state.update(lambda c: c.subscriptions.append(
                Subscription(name=name.strip() or "Подписка", url=url)))
        elif url.startswith("vless://"):
            ob = subs.parse_manual_link(url)
            tls = ob.get("tls", {})
            state.update(lambda c: c.own_servers.append(OwnServer(
                name=name.strip() or ob["tag"].removeprefix("bk-"),
                server=ob["server"], server_port=ob["server_port"],
                uuid=ob["uuid"], flow=ob.get("flow", ""),
                sni=tls.get("server_name", ""),
                fingerprint=tls.get("utls", {}).get("fingerprint", "chrome"),
                reality_public_key=tls.get("reality", {}).get("public_key", ""),
                reality_short_id=tls.get("reality", {}).get("short_id", ""))))
        elif url.startswith(("trojan://", "ss://")):
            subs.parse_manual_link(url)     # проверяем до сохранения
            state.update(lambda c: c.manual_nodes.append(url))
        else:
            return _redirect("/servers", err="Нужна ссылка на подписку "
                                             "(https://…) или сервер (vless://…)")
    except ValueError as exc:
        return _redirect("/servers", err=str(exc))
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/servers", msg=msg, err=err)


@app.post("/servers/own/{idx}/delete")
def own_server_delete(request: Request, idx: int):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    if not (0 <= idx < len(cfg.own_servers)):
        return _redirect("/servers", err="Нет такого сервера")
    cfg = state.update(lambda c: c.own_servers.pop(idx))
    msg, err = _try_apply(cfg)
    return _redirect("/servers", msg=msg or "Сервер удалён", err=err)


@app.post("/servers/sub/{sub_id}/delete")
def subscription_delete(request: Request, sub_id: str):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    state.update(lambda c: c.subscriptions.__setitem__(
        slice(None), [s for s in c.subscriptions if s.id != sub_id]))
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/servers", msg=msg or "Подписка удалена", err=err)


@app.post("/servers/manual/{idx}/delete")
def manual_node_delete(request: Request, idx: int):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    if not (0 <= idx < len(cfg.manual_nodes)):
        return _redirect("/servers", err="Нет такой ссылки")
    state.update(lambda c: c.manual_nodes.pop(idx))
    _collect_backups()
    msg, err = _try_apply(state.get())
    return _redirect("/servers", msg=msg or "Ссылка удалена", err=err)


@app.post("/servers/refresh")
def servers_refresh(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    n = len(_collect_backups())
    if n == 0:
        return _redirect("/servers", err=_no_servers_error())
    msg, err = _try_apply(state.get())
    return _redirect("/servers",
                     msg=msg and f"Обновлено, серверов в резерве: {n}", err=err)


# --- Настройки ---------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    return _page(request, "settings.html", cfg)


@app.post("/settings")
async def settings_save(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    form = await request.form()
    password = (form.get("password") or "").strip()
    if password:
        if len(password) < 8:
            return _redirect("/settings", err="Пароль короче 8 символов")
        if password != (form.get("password2") or ""):
            return _redirect("/settings", err="Пароли не совпадают")

    def put(c: Config):
        c.work_mode = WorkMode(form.get("work_mode") or c.work_mode.value)
        c.endpoint_host = (form.get("endpoint_host") or "").strip()
        c.timezone = (form.get("timezone") or "UTC").strip()
        c.dns.adblock = form.get("adblock") == "1"
        upstreams = [u.strip() for u in
                     (form.get("upstreams") or "").splitlines() if u.strip()]
        if upstreams:
            c.dns.upstreams = upstreams
        c.wireguard.listen_port = int(form.get("wg_port") or 51820)
        subnet = (form.get("wg_subnet") or "").strip()
        if subnet and subnet != c.wireguard.subnet:
            # Смена подсети не трогает уже выданные адреса: у людей на руках
            # рабочие конфиги, и молча их сломать нельзя.
            import ipaddress
            net = ipaddress.ip_network(subnet)
            if any(ipaddress.ip_address(p.address) not in net
                   for p in c.wireguard.peers):
                raise ValueError(
                    "в новой подсети не помещаются уже выданные адреса — "
                    "сначала удалите устройства")
            c.wireguard.subnet = subnet
        c.stats.enabled = form.get("stats_enabled") == "1"
        c.stats.track_hosts = form.get("track_hosts") == "1"
        c.stats.keep_days = int(form.get("keep_days") or 14)
        if password:
            c.admin.password_hash = auth.hash_password(password)

    try:
        cfg = state.update(put)
    except Exception as exc:      # noqa: BLE001 — показываем пользователю
        return _redirect("/settings", err=f"Настройки не приняты: {exc}")
    adguard_mod.set_protection(cfg.dns.adblock)
    msg, err = _try_apply(cfg)
    if not err and cfg.wireguard.listen_port != 51820:
        msg = (msg + " Порт WireGuard изменён — проверьте, что он проброшен "
               "снаружи (WG_PORT в .env и перезапуск стека).")
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


# --- Подключение сети --------------------------------------------------------

@app.get("/connect", response_class=HTMLResponse)
def connect_page(request: Request):
    """Инструкция «что делать дальше»: коробка поднята, но трафик в неё
    пока не идёт. Это самый страшный для человека шаг — он трогает роутер,
    от которого зависит интернет всей семьи, — поэтому здесь и точные
    адреса, и порядок «сначала одно устройство», и способ всё вернуть.
    """
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    box_ip = request.url.hostname or ""
    conn = _stats_conn()
    try:
        peers = stats.by_peer(conn, 1)
    finally:
        conn.close()
    # Свои же пробы и WG-клиенты не считаются: нас интересует, пришёл ли
    # кто-то из локальной сети.
    wg_names = {p.name for p in cfg.wireguard.peers}
    lan_clients = [p for p in peers
                   if p["peer"] not in wg_names
                   and not p["peer"].startswith("коробка")]
    return _page(request, "connect.html", cfg,
                 box_ip=box_ip,
                 lan_clients=lan_clients,
                 wg_peers=cfg.wireguard.peers)


# --- Статистика --------------------------------------------------------------

_peer_cache: dict[str, str] = {}
_peer_cache_at = 0.0


def _resolve_peer(ip: str) -> str:
    """Адрес клиента -> человеческое имя устройства.

    Кэш на полминуты: сборщик зовёт это на каждое соединение, а читать
    config.yaml с диска по десять раз в секунду незачем.
    """
    import time as _t
    global _peer_cache, _peer_cache_at
    if not ip:
        return "неизвестно"
    if ip.startswith("127."):
        # Это собственная проверка связи коробки, а не чьё-то устройство.
        return "коробка (проверка связи)"
    if _t.monotonic() - _peer_cache_at > 30:
        cfg = state.get()
        _peer_cache = {p.address: p.name for p in cfg.wireguard.peers}
        _peer_cache_at = _t.monotonic()
    return _peer_cache.get(ip, ip)


def _stats_conn():
    return stats.connect(paths.STATS_DB)


@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    cfg = state.get()
    if guard := _guard(request, cfg):
        return guard
    hours = min(max(int(request.query_params.get("hours", "24")), 1), 24 * 90)
    peer = request.query_params.get("peer", "")
    conn = _stats_conn()
    try:
        ctx = {
            "hours": hours,
            "peer": peer,
            "totals": stats.totals(conn, hours),
            "peers": stats.by_peer(conn, hours),
            "outbounds": stats.by_outbound(conn, hours)[:12],
            "directions": stats.by_direction(conn, hours),
            "hosts": stats.top_hosts(conn, hours, peer=peer)
                     if cfg.stats.track_hosts else [],
            "chart": charts.area_chart(stats.series(conn, hours), hours,
                                       cfg.timezone),
            "donut": charts.donut(stats.by_direction(conn, hours)),
            "known_peers": stats.known_peers(conn, hours),
            "sys": sysstats.summary(conn, hours),
            "adguard": adguard_mod.status(cfg),
            "adguard_counters": adguard_mod.counters(cfg),
        }
        h = ctx["sys"]["history"]
        ctx["spark"] = {
            "cpu": charts.sparkline([r["cpu"] for r in h], "#38bdf8"),
            "mem": charts.sparkline([r["mem_used"] for r in h], "#818cf8"),
            "swap": charts.sparkline([r["swap_used"] for r in h], "#a78bfa"),
            "disk": charts.sparkline([r["disk_used"] for r in h], "#4ade80"),
            "net": charts.dual_sparkline([r["net_rx"] for r in h],
                                         [r["net_tx"] for r in h]),
            "sockets": charts.sparkline([r["tcp"] + r["udp"] for r in h],
                                        "#7dd3fc"),
        }
    finally:
        conn.close()
    return _page(request, "stats.html", cfg, **ctx)


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
def start_background():
    threading.Thread(target=_scheduler, daemon=True).start()
    stats.Collector(paths.STATS_DB, _resolve_peer,
                    lambda: state.get().stats).start()
