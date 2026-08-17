#!/usr/bin/env python3
"""Веб-интерфейс к спискам маршрутизации sing-box.

Задача одна: дать менять «что идёт в туннель» без ноутбука и SSH.

Что делает:
  * галочки по готовым наборам блокировок (sync/rulesets.list);
  * правка своего списка доменов и подсетей;
  * применение: пересборка конфига -> sing-box check -> перезапуск.

Порядок применения важен. Новый конфиг сначала собирается во временный файл
и проверяется штатным `sing-box check`. Боевой файл заменяется только после
успешной проверки. Опечатка в списке не должна ронять интернет всему дому —
поэтому при неудачной проверке всё остаётся как было, а ошибка показывается
на странице.

Зависимостей нет: только стандартная библиотека.
"""

import base64
import html
import http.server
import os
import subprocess
import time
import urllib.parse

ROOT = "/opt/vpn-config"
RULESETS = os.path.join(ROOT, "sync", "rulesets.list")
SERVICES = os.path.join(ROOT, "sync", "abroad-services.list")
NETWORKS = os.path.join(ROOT, "sync", "abroad-networks.list")
RENDER = os.path.join(ROOT, "vm", "render-config.py")
LIVE = "/etc/sing-box/config.json"
# Рядом с целевым файлом, а НЕ в /tmp: там отдельная файловая система,
# и os.replace падает с «Invalid cross-device link».
TMP = "/etc/sing-box/config.json.new"
AUTH_FILE = os.path.join(ROOT, "secrets", "webui.env")

LISTEN = ("192.168.88.6", 8088)

# Каталог держится здесь, а не читается из сети: страница должна открываться
# и когда GitHub недоступен. Формат записи — («источник:набор», подпись).
CATALOG = [
    ("Базовое для РФ", [
        ("vernette:unavailable-in-russia",
         "Всё, что недоступно из России — сервисы, которые сами блокируют "
         "российские адреса. Закрывает «а почему этот сайт не открылся» "
         "и нужен для облаков IoT (Bosch, Ubiquiti). ~730 доменов."),
        ("vernette:rkn",
         "Реестр заблокированного в РФ. Огромный и с мусором — мошеннические "
         "сайты, спам. Для дома скорее вреден."),
    ]),
    ("Мессенджеры", [
        ("vernette:telegram", "Telegram — домены и подсети дата-центров"),
        ("vernette:whatsapp", "WhatsApp"),
        ("vernette:discord-full", "Discord целиком"),
        ("vernette:telegram-voice-chats", "Голос Telegram — если пропадает звук"),
        ("vernette:discord-voice-chats", "Голос Discord — если пропадает звук"),
    ]),
    ("Соцсети", [
        ("vernette:instagram", "Instagram"),
        ("vernette:x", "X (Twitter)"),
        ("vernette:linkedin", "LinkedIn"),
        ("vernette:tiktok", "TikTok"),
        ("metacubex:facebook", "Facebook"),
        ("metacubex:reddit", "Reddit"),
    ]),
    ("Нейросети", [
        ("vernette:openai", "ChatGPT, OpenAI API"),
        ("vernette:claude", "Claude"),
        ("metacubex:anthropic", "Anthropic — API и сайт"),
        ("vernette:gemini", "Google Gemini, AI Studio"),
        ("vernette:grok", "Grok, x.ai"),
        ("vernette:copilot", "GitHub Copilot, Microsoft Copilot"),
    ]),
    ("Видео и музыка", [
        ("vernette:youtube", "YouTube и googlevideo"),
        ("vernette:netflix", "Netflix"),
        ("vernette:spotify", "Spotify"),
        ("metacubex:twitch", "Twitch"),
        ("metacubex:soundcloud", "SoundCloud"),
        ("metacubex:disney", "Disney+"),
        ("metacubex:hbo", "HBO Max"),
        ("metacubex:primevideo", "Prime Video"),
        ("metacubex:bbc", "BBC"),
        ("metacubex:imdb", "IMDb"),
    ]),
    ("Работа и разработка", [
        ("metacubex:notion", "Notion"),
        ("metacubex:figma", "Figma"),
        ("metacubex:canva", "Canva"),
        ("metacubex:github", "GitHub"),
        ("metacubex:jetbrains", "JetBrains — IDE и лицензии"),
        ("metacubex:docker", "Docker Hub"),
        ("metacubex:atlassian", "Jira, Confluence"),
        ("metacubex:slack", "Slack"),
        ("metacubex:zoom", "Zoom"),
        ("metacubex:dropbox", "Dropbox"),
        ("metacubex:vercel", "Vercel"),
        ("metacubex:netlify", "Netlify"),
        ("metacubex:heroku", "Heroku"),
        ("metacubex:digitalocean", "DigitalOcean"),
    ]),
    ("Платежи и покупки", [
        ("metacubex:paypal", "PayPal"),
        ("metacubex:ebay", "eBay"),
        ("metacubex:booking", "Booking.com"),
        ("metacubex:airbnb", "Airbnb"),
        ("metacubex:amazon", "Amazon"),
    ]),
    ("Игры", [
        ("metacubex:steam", "Steam"),
        ("metacubex:epicgames", "Epic Games"),
        ("metacubex:playstation", "PlayStation Network"),
        ("metacubex:xbox", "Xbox Live"),
        ("metacubex:nintendo", "Nintendo"),
    ]),
    ("Обучение", [
        ("metacubex:coursera", "Coursera"),
        ("metacubex:udemy", "Udemy"),
        ("metacubex:duolingo", "Duolingo"),
    ]),
    ("Прочее", [
        ("metacubex:medium", "Medium"),
        ("metacubex:patreon", "Patreon"),
        ("metacubex:pornhub", "Pornhub"),
        ("metacubex:adobe", "Adobe — облако и активация"),
        ("metacubex:apple-music", "Apple Music"),
        ("metacubex:apple-tvplus", "Apple TV+"),
        ("metacubex:apple-update", "Обновления Apple"),
        ("metacubex:microsoft", "Microsoft"),
        ("metacubex:cloudflare", "Cloudflare — сервисы, не CDN"),
    ]),
]

PAGE = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Маршрутизация</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{font:15px/1.5 -apple-system,system-ui,sans-serif;background:#101215;color:#e8eaed;
     margin:0;padding:22px clamp(16px,3vw,44px)}}
.wrap{{max-width:1760px;margin-inline:auto}}
header{{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap;margin-bottom:14px}}
h1{{font-size:21px;margin:0}}
.sub{{color:#8b98a5;font-size:13px}}
.bar{{position:sticky;top:0;z-index:5;background:#101215;padding:10px 0 14px;
     border-bottom:1px solid #23282f;margin-bottom:18px}}
.row{{display:flex;gap:14px;align-items:center;flex-wrap:wrap}}
.status{{display:flex;gap:22px;flex-wrap:wrap;background:#171a1f;border:1px solid #23282f;
        border-radius:10px;padding:11px 15px;flex:1 1 380px}}
.status b{{color:#fff}}
.ok{{color:#4ade80}} .bad{{color:#f87171}}
input[type=search]{{flex:1 1 260px;background:#171a1f;border:1px solid #2b313a;border-radius:9px;
     padding:11px 14px;color:#e8eaed;font-size:14px}}
input[type=search]:focus{{outline:none;border-color:#f97316}}
button{{background:#f97316;color:#0d0d0d;border:0;border-radius:9px;padding:11px 24px;
       font-size:15px;font-weight:650;cursor:pointer}}
button:hover{{background:#fb923c}}
.count{{color:#8b98a5;font-size:13px;white-space:nowrap}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:#8b98a5;
    margin:26px 0 10px;font-weight:650;display:flex;align-items:center;gap:12px}}
h2 .pick{{font-size:11px;text-transform:none;letter-spacing:0;color:#6b7681;cursor:pointer;
        border:1px solid #2b313a;border-radius:6px;padding:2px 9px;font-weight:500}}
h2 .pick:hover{{color:#e8eaed;border-color:#3a424d}}
.grid{{display:grid;gap:9px;grid-template-columns:repeat(auto-fill,minmax(330px,1fr))}}
label{{display:flex;gap:11px;align-items:flex-start;padding:11px 13px;border-radius:10px;
      cursor:pointer;background:#171a1f;border:1px solid #23282f}}
label:hover{{border-color:#39414c}}
label.on{{border-color:#7c4318;background:#1d1a17}}
input[type=checkbox]{{margin-top:2px;width:17px;height:17px;accent-color:#f97316;flex:none}}
.nm{{font-weight:650;display:flex;gap:7px;align-items:center;flex-wrap:wrap}}
.src{{font-size:10px;font-weight:600;padding:1px 6px;border-radius:5px;
     background:#23282f;color:#8b98a5;text-transform:uppercase;letter-spacing:.04em}}
.src.vr{{background:#1c2c3a;color:#7dd3fc}}
.desc{{color:#8b98a5;font-size:12.5px;margin-top:2px}}
.cols{{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}}
textarea{{width:100%;background:#171a1f;color:#e8eaed;border:1px solid #23282f;border-radius:10px;
         padding:12px;font:12.5px/1.55 ui-monospace,Menlo,monospace;min-height:230px}}
.msg{{padding:13px 16px;border-radius:10px;margin-bottom:16px;white-space:pre-wrap;
     font:12.5px/1.5 ui-monospace,Menlo,monospace}}
.msg.ok{{background:#0f2a1a;border:1px solid #1f5133}}
.msg.bad{{background:#2a1215;border:1px solid #5a2126}}
.hint{{color:#8b98a5;font-size:12.5px;margin:5px 0 0}}
.hide{{display:none}}
</style>
<div class="wrap">
<header>
  <h1>Что идёт в туннель</h1>
  <span class="sub">роутер отдаёт весь трафик сюда — решение по каждому
  соединению принимает sing-box по имени хоста</span>
</header>
{message}
<form method="post">
<div class="bar"><div class="row">
  <div class="status">
    <span>sing-box: <b class="{sb_class}">{sb}</b></span>
    <span>туннель: <b class="{tun_class}">{tun}</b></span>
    <span>выход: <b>{exit_ip}</b></span>
  </div>
  <input type="search" id="q" placeholder="Поиск по сервисам…" autocomplete="off">
  <span class="count"><b id="cnt">{count}</b> включено</span>
  <button type="submit">Применить</button>
</div></div>
{groups}
<h2>Свои списки</h2>
<div class="cols">
  <div>
    <div class="hint">Домены, которых нет в готовых наборах.
    Один на строку, поддомены покрываются автоматически.</div>
    <textarea name="services">{services}</textarea>
  </div>
  <div>
    <div class="hint">Подсети — только для протоколов без имени хоста.
    Общие облачные диапазоны сюда класть нельзя: отсеивать попутчиков
    после этого правила уже некому.</div>
    <textarea name="networks">{networks}</textarea>
  </div>
</div>
<button type="submit">Применить</button>
</form>
</div>
<script>
const boxes=[...document.querySelectorAll('input[type=checkbox]')];
const cnt=document.getElementById('cnt');
function paint(b){{b.closest('label').classList.toggle('on',b.checked)}}
function recount(){{cnt.textContent=boxes.filter(b=>b.checked).length}}
boxes.forEach(b=>{{paint(b);b.addEventListener('change',()=>{{paint(b);recount()}})}});
document.getElementById('q').addEventListener('input',e=>{{
  const q=e.target.value.trim().toLowerCase();
  document.querySelectorAll('.grid > label').forEach(l=>{{
    l.classList.toggle('hide', q && !l.dataset.k.includes(q));
  }});
  document.querySelectorAll('h2[data-g]').forEach(h=>{{
    const g=document.querySelector('.grid[data-g="'+h.dataset.g+'"]');
    const any=[...g.children].some(l=>!l.classList.contains('hide'));
    h.classList.toggle('hide',!any); g.classList.toggle('hide',!any);
  }});
}});
document.querySelectorAll('.pick').forEach(p=>p.addEventListener('click',()=>{{
  const g=document.querySelector('.grid[data-g="'+p.dataset.g+'"]');
  const vis=[...g.children].filter(l=>!l.classList.contains('hide'));
  const on=vis.every(l=>l.querySelector('input').checked);
  vis.forEach(l=>{{const b=l.querySelector('input');b.checked=!on;paint(b)}});
  recount();
}}));
</script>
"""


def read_enabled():
    enabled = set()
    with open(RULESETS) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                enabled.add(line if ":" in line else "vernette:" + line)
    return enabled


def write_rulesets(enabled):
    out = [
        "# Сгенерировано веб-интерфейсом http://192.168.88.6:8088",
        "# Формат: «источник:набор». Строка без # — набор включён.",
        "",
    ]
    for group, items in CATALOG:
        out.append(f"# --- {group} ---")
        for key, _ in items:
            out.append(key if key in enabled else f"# {key}")
        out.append("")
    with open(RULESETS, "w") as fh:
        fh.write("\n".join(out) + "\n")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180, **kw)


def apply_config():
    """Пересобрать, проверить, и только потом заменить боевой конфиг."""
    r = run(["python3", RENDER])
    if r.returncode != 0:
        return False, "Сборка конфига не удалась:\n" + r.stderr.strip()
    with open(TMP, "w") as fh:
        fh.write(r.stdout)

    r = run(["sing-box", "check", "-c", TMP])
    if r.returncode != 0:
        return False, ("Конфиг не прошёл проверку, ничего не изменено:\n"
                       + (r.stderr or r.stdout).strip())

    os.replace(TMP, LIVE)
    r = run(["systemctl", "restart", "sing-box"])
    if r.returncode != 0:
        return False, "sing-box не перезапустился:\n" + r.stderr.strip()
    return True, "Применено, sing-box перезапущен."


def status():
    sb = run(["systemctl", "is-active", "sing-box"]).stdout.strip()
    exit_ip, tun = "—", "НЕ РАБОТАЕТ"
    r = run(["curl", "-sS", "-4", "--proxy", "socks5h://127.0.0.1:1080",
             "--max-time", "10", "https://www.cloudflare.com/cdn-cgi/trace"])
    if r.returncode == 0:
        tun = "работает"
        for line in r.stdout.splitlines():
            if line.startswith("ip="):
                exit_ip = line[3:]
    return sb, tun, exit_ip


def render(message=""):
    enabled = read_enabled()
    out = []
    for gi, (group, items) in enumerate(CATALOG):
        out.append(f'<h2 data-g="{gi}">{html.escape(group)}'
                   f'<span class="pick" data-g="{gi}">все / никого</span></h2>')
        out.append(f'<div class="grid" data-g="{gi}">')
        for key, desc in items:
            source, name = key.split(":", 1)
            chk = " checked" if key in enabled else ""
            cls = " vr" if source == "vernette" else ""
            search_key = html.escape(f"{name} {desc} {group}".lower(), quote=True)
            out.append(
                f'<label data-k="{search_key}">'
                f'<input type="checkbox" name="rs" value="{html.escape(key)}"{chk}>'
                f'<span><span class="nm">{html.escape(name)}'
                f'<span class="src{cls}">{source[:2]}</span></span>'
                f'<span class="desc">{html.escape(desc)}</span></span></label>'
            )
        out.append("</div>")

    sb, tun, exit_ip = status()
    return PAGE.format(
        message=message,
        groups="\n".join(out),
        count=len(enabled),
        services=html.escape(open(SERVICES).read()),
        networks=html.escape(open(NETWORKS).read()),
        sb=sb, sb_class="ok" if sb == "active" else "bad",
        tun=tun, tun_class="ok" if tun == "работает" else "bad",
        exit_ip=html.escape(exit_ip),
    )


def load_auth():
    with open(AUTH_FILE) as fh:
        for line in fh:
            if line.startswith("WEBUI_AUTH="):
                return line.split("=", 1)[1].strip()
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "vpn-ui"

    def _authorized(self):
        expect = load_auth()
        if not expect:
            return True
        got = self.headers.get("Authorization", "")
        if got.startswith("Basic "):
            try:
                if base64.b64decode(got[6:]).decode() == expect:
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="vpn"')
        self.end_headers()
        return False

    def _send(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self._authorized():
            self._send(render())

    def do_POST(self):
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        known = {k for _, items in CATALOG for k, _ in items}
        write_rulesets(set(form.get("rs", [])) & known)
        for path, field in ((SERVICES, "services"), (NETWORKS, "networks")):
            if field in form:
                with open(path, "w") as fh:
                    fh.write(form[field][0].replace("\r\n", "\n"))

        ok, text = apply_config()
        if ok:
            # Дать sing-box подняться и подтянуть наборы, иначе статус сразу
            # после перезапуска показывает «туннель не работает» без причины.
            time.sleep(10)
        self._send(render(f'<div class="msg {"ok" if ok else "bad"}">'
                          f'{html.escape(text)}</div>'))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(LISTEN, Handler).serve_forever()
