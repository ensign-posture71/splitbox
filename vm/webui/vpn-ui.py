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
.grid{{display:grid;gap:9px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}}
.card{{padding:11px 13px;border-radius:10px;background:#171a1f;border:1px solid #23282f;
      display:flex;flex-direction:column;gap:7px}}
.card.m-own{{border-color:#2f5f7a;background:#151b20}}
.card.m-fast{{border-color:#7c4318;background:#1d1a17}}
.seg{{display:flex;gap:0;border:1px solid #2b313a;border-radius:8px;
     overflow:hidden;align-self:flex-start;flex:none}}
.card .seg{{margin-top:auto}}
.sw{{cursor:pointer}}
.sw input{{position:absolute;opacity:0;pointer-events:none}}
.sw span{{display:block;padding:5px 13px;font-size:12.5px;color:#8b98a5;
         border-right:1px solid #2b313a;user-select:none}}
.sw:last-child span{{border-right:0}}
.sw:hover span{{background:#1f242b;color:#cbd5e1}}
.sw input:checked + .s-own{{background:#1d4d68;color:#e0f2fe}}
.sw input:checked + .s-fast{{background:#9a4a12;color:#fff5eb}}
.sw input:checked + .s-off{{background:#2b313a;color:#e8eaed}}
.nm{{font-weight:650;display:flex;gap:7px;align-items:center;flex-wrap:wrap}}
.src{{font-size:10px;font-weight:600;padding:1px 6px;border-radius:5px;
     background:#23282f;color:#8b98a5;text-transform:uppercase;letter-spacing:.04em}}
.src.vr{{background:#1c2c3a;color:#7dd3fc}}
.desc{{color:#8b98a5;font-size:12.5px;margin-top:2px}}
/* Переключатель в строке таблицы. Разметка тут на span-ах, а не на label
   с радиокнопками как в карточках, поэтому нужны отдельные правила —
   без них сегменты слипались в сплошной текст «мимосвойбыстрый»
   и выбранный ничем не отличался от остальных. */
.seg-btn{{display:block;padding:5px 11px;font-size:12px;color:#8b98a5;
         border-right:1px solid #2b313a;cursor:pointer;user-select:none;
         white-space:nowrap}}
.seg-btn:last-child{{border-right:0}}
.seg-btn:hover{{background:#1f242b;color:#cbd5e1}}
.trow.m-own  .seg-btn.s-own {{background:#1d4d68;color:#e0f2fe}}
.trow.m-fast .seg-btn.s-fast{{background:#9a4a12;color:#fff5eb}}
.trow.m-off  .seg-btn.s-off {{background:#2b313a;color:#e8eaed}}

/* 520px, а не 430: длинные домены вроде generativelanguage.googleapis.com
   не должны обрезаться — иначе непонятно, что именно в строке. */
.tbl{{display:grid;gap:6px;grid-template-columns:repeat(auto-fill,minmax(520px,1fr));
     margin-top:10px}}
.trow{{display:flex;gap:8px;align-items:center;background:#171a1f;border:1px solid #23282f;
      border-radius:9px;padding:6px 8px}}
.trow.m-own{{border-color:#2f5f7a}}
.trow.m-fast{{border-color:#7c4318}}
.trow.m-off{{opacity:.5}}
.trow input[type=text]{{flex:1;min-width:0;background:transparent;border:0;color:#e8eaed;
     font:13px/1.4 ui-monospace,Menlo,monospace;padding:5px 4px}}
.trow input[type=text]:focus{{outline:none;background:#1f242b;border-radius:6px}}
.del{{color:#6b7681;cursor:pointer;padding:2px 7px;border-radius:6px;font-size:15px;flex:none}}
.del:hover{{color:#f87171;background:#2a1215}}
code{{background:#1f242b;padding:1px 5px;border-radius:4px;font-size:12px}}
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
<h2>Свои домены<span class="pick" data-add="svc">+ строка</span></h2>
<div class="hint">Чего нет в готовых наборах. Поддомены покрываются автоматически:
<code>rezka.ag</code> покрывает и <code>hd.rezka.ag</code>.</div>
<div class="tbl" id="t-svc">{services}</div>

<h2>Свои подсети<span class="pick" data-add="net">+ строка</span></h2>
<div class="hint">Только для протоколов <b>без имени хоста</b> — например Telegram
MTProto. Общие облачные диапазоны сюда класть нельзя: отсеивать попутчиков
после этого правила уже некому.</div>
<div class="tbl" id="t-net">{networks}</div>
<button type="submit">Применить</button>
</form>
</div>
<script>
const cards=[...document.querySelectorAll('.card')];
const cnt=document.getElementById('cnt');
function mode(c){{return c.querySelector('input:checked').value}}
function paint(c){{c.className='card m-'+mode(c)+(c.classList.contains('hide')?' hide':'')}}
function recount(){{
  const n=m=>cards.filter(c=>mode(c)===m).length;
  cnt.textContent=n('own')+' свой · '+n('fast')+' быстрый';
}}
cards.forEach(c=>c.addEventListener('change',()=>{{paint(c);recount()}}));
document.getElementById('q').addEventListener('input',e=>{{
  const q=e.target.value.trim().toLowerCase();
  cards.forEach(c=>c.classList.toggle('hide', q && !c.dataset.k.includes(q)));
  document.querySelectorAll('h2[data-g]').forEach(h=>{{
    const g=document.querySelector('.grid[data-g="'+h.dataset.g+'"]');
    const any=[...g.children].some(c=>!c.classList.contains('hide'));
    h.classList.toggle('hide',!any); g.classList.toggle('hide',!any);
  }});
}});
document.querySelectorAll('.pick[data-g]').forEach(p=>p.addEventListener('click',()=>{{
  const g=document.querySelector('.grid[data-g="'+p.dataset.g+'"]');
  [...g.children].filter(c=>!c.classList.contains('hide')).forEach(c=>{{
    c.querySelector('input[value="'+p.dataset.m+'"]').checked=true; paint(c);
  }});
  recount();
}}));

// --- таблицы своих списков -------------------------------------------------
// Значение и политика — два поля в строке: скрытое поле хранит выбор,
// сегменты его переключают. Так оба списка приходят на сервер в одном
// порядке и не разъезжаются.
function rowMode(row,m){{
  row.querySelector('input[type=hidden]').value=m;
  row.className='trow m-'+m;
}}
function bindRow(row){{
  row.querySelectorAll('.seg-btn').forEach(b=>
    b.addEventListener('click',()=>rowMode(row,b.dataset.m)));
  row.querySelector('.del').addEventListener('click',()=>{{
    const t=row.parentElement; row.remove();
    if(!t.children.length) addRow(t.id==='t-svc'?'svc':'net');
  }});
  // Печатаешь в последней строке — сразу появляется следующая пустая,
  // чтобы не жать «плюс» на каждый домен.
  const inp=row.querySelector('input[type=text]');
  inp.addEventListener('input',()=>{{
    const t=row.parentElement;
    if(row===t.lastElementChild && inp.value.trim())
      addRow(t.id==='t-svc'?'svc':'net');
  }});
}}
function addRow(prefix,focus){{
  const t=document.getElementById('t-'+prefix);
  const src=t.lastElementChild||t.firstElementChild;
  const row=src.cloneNode(true);
  row.querySelector('input[type=text]').value='';
  rowMode(row,'own');
  t.appendChild(row); bindRow(row);
  if(focus) row.querySelector('input[type=text]').focus();
  return row;
}}
document.querySelectorAll('.trow').forEach(bindRow);
document.querySelectorAll('.pick[data-add]').forEach(p=>
  p.addEventListener('click',()=>addRow(p.dataset.add,true)));
</script>
"""


def read_rows(path):
    """Файл своих списков -> [(значение, политика)] в исходном порядке.

    Закомментированная строка вида «# rezka.ag fast» означает «мимо туннеля»,
    но запись сохраняется: удалять её при выключении значило бы терять
    то, что владелец однажды уже вписал.
    """
    rows = []
    for line in open(path):
        raw = line.strip()
        if not raw:
            continue
        off = raw.startswith("#")
        body = raw.lstrip("#").strip()
        parts = body.split()
        # Комментарии-пояснения от выключенных записей отличаем по форме:
        # запись — это одно-два слова, где второе является политикой.
        if not parts or len(parts) > 2:
            continue
        if len(parts) == 2 and parts[1] not in ("own", "fast"):
            continue
        if "." not in parts[0] and "/" not in parts[0]:
            continue
        rows.append((parts[0], "off" if off else (parts[1] if len(parts) > 1 else "own")))
    return rows


def write_rows(path, rows, header):
    out = [header, ""]
    for value, policy in rows:
        if not value:
            continue
        # «Мимо» пишется комментарием, а не удалением: запись сохраняется
        # и её видно в интерфейсе, чтобы можно было вернуть одним щелчком.
        out.append(f"# {value} own" if policy == "off" else f"{value} {policy}")
    open(path, "w").write("\n".join(out) + "\n")


def read_policies():
    """key -> 'own' | 'fast'. Отсутствие ключа означает «напрямую»."""
    policies = {}
    with open(RULESETS) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            key = parts[0] if ":" in parts[0] else "vernette:" + parts[0]
            policies[key] = parts[1] if len(parts) > 1 else "own"
    return policies


def write_rulesets(policies):
    out = [
        "# Сгенерировано веб-интерфейсом http://192.168.88.6:8088",
        "# Формат: «источник:набор политика». own — только свой VPS,",
        "# fast — группа автовыбора (свой + резервные из подписки).",
        "# Закомментированная строка = сервис идёт напрямую, мимо туннеля.",
        "",
    ]
    for group, items in CATALOG:
        out.append(f"# --- {group} ---")
        for key, _ in items:
            p = policies.get(key)
            out.append(f"{key} {p}" if p else f"# {key} own")
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


MODES = [("off", "мимо"), ("own", "свой"), ("fast", "быстрый")]


def render(message=""):
    policies = read_policies()
    out = []
    for gi, (group, items) in enumerate(CATALOG):
        out.append(f'<h2 data-g="{gi}">{html.escape(group)}'
                   f'<span class="pick" data-g="{gi}" data-m="own">все → свой</span>'
                   f'<span class="pick" data-g="{gi}" data-m="fast">все → быстрый</span>'
                   f'<span class="pick" data-g="{gi}" data-m="off">все → мимо</span></h2>')
        out.append(f'<div class="grid" data-g="{gi}">')
        for key, desc in items:
            source, name = key.split(":", 1)
            cur = policies.get(key, "off")
            cls = " vr" if source == "vernette" else ""
            search_key = html.escape(f"{name} {desc} {group}".lower(), quote=True)
            seg = "".join(
                f'<label class="sw"><input type="radio" name="p:{html.escape(key)}"'
                f' value="{m}"{" checked" if cur == m else ""}>'
                f'<span class="s-{m}">{lbl}</span></label>'
                for m, lbl in MODES
            )
            out.append(
                f'<div class="card m-{cur}" data-k="{search_key}">'
                f'<div class="nm">{html.escape(name)}'
                f'<span class="src{cls}">{source[:2]}</span></div>'
                f'<div class="desc">{html.escape(desc)}</div>'
                f'<div class="seg">{seg}</div></div>'
            )
        out.append("</div>")

    def table(path, prefix):
        rows = read_rows(path)
        rows.append(("", "own"))          # одна пустая строка, чтобы можно было сразу дописать
        cells = []
        for value, policy in rows:
            seg = "".join(
                f'<span class="s-{m} seg-btn" data-m="{m}">{lbl}</span>'
                for m, lbl in MODES
            )
            cells.append(
                f'<div class="trow m-{policy}">'
                f'<input type="text" name="{prefix}-val" value="{html.escape(value)}"'
                f' placeholder="{"домен" if prefix == "svc" else "подсеть, например 91.108.4.0/22"}">'
                f'<input type="hidden" name="{prefix}-pol" value="{policy}">'
                f'<span class="seg">{seg}</span>'
                f'<span class="del" title="удалить строку">×</span></div>'
            )
        return "\n".join(cells)

    sb, tun, exit_ip = status()
    n_own = sum(1 for v in policies.values() if v == "own")
    n_fast = sum(1 for v in policies.values() if v == "fast")
    return PAGE.format(
        message=message,
        groups="\n".join(out),
        count=f"{n_own} свой · {n_fast} быстрый",
        services=table(SERVICES, "svc"),
        networks=table(NETWORKS, "net"),
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
        # keep_blank_values обязателен: без него parse_qs выбрасывает пустые
        # значения, и пустая строка таблицы теряет своё «значение», сохраняя
        # «политику» — списки разъезжаются, и все записи после неё получают
        # чужой режим. Поймано на том, что новый домен сохранился как own
        # вместо fast.
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(),
                                     keep_blank_values=True)

        policies = {}
        for key in (k for _, items in CATALOG for k, _ in items):
            mode = form.get(f"p:{key}", ["off"])[0]
            if mode in ("own", "fast"):
                policies[key] = mode
        write_rulesets(policies)

        # Значения и политики приходят двумя параллельными списками: браузер
        # отправляет поля в порядке DOM, поэтому i-е значение соответствует
        # i-й политике. Пары длиннее короткого списка отбрасываются — так
        # рассинхронизация не может испортить файл.
        for path, prefix, header in (
            (SERVICES, "svc", "# Свои домены. Формат: «домен политика» (own|fast).\n"
                              "# Закомментированная строка = мимо туннеля."),
            (NETWORKS, "net", "# Свои подсети — для протоколов без имени хоста.\n"
                              "# Формат: «подсеть политика» (own|fast)."),
        ):
            vals = form.get(f"{prefix}-val")
            pols = form.get(f"{prefix}-pol")
            if vals is None or pols is None:
                continue
            rows = [(v.strip(), p if p in ("own", "fast", "off") else "own")
                    for v, p in zip(vals, pols) if v.strip()]
            write_rows(path, rows, header)

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
