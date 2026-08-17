#!/usr/bin/env python3
"""Веб-интерфейс к спискам маршрутизации sing-box.

Задача одна: дать менять «что идёт в туннель» без ноутбука и SSH.

Что делает:
  * галочки по готовым спискам блокировок (sync/rulesets.list);
  * правка ручного списка доменов и подсетей;
  * применение: пересборка конфига -> sing-box check -> перезапуск.

Порядок применения важен. Новый конфиг сначала собирается во временный файл
и проверяется штатным `sing-box check`. Боевой файл заменяется только после
успешной проверки. Опечатка в списке не должна ронять интернет всему дому —
поэтому при неудачной проверке всё остаётся как было, а ошибка показывается
на странице.

Зависимостей нет: только стандартная библиотека. На слабой машине это
неважно, но на одну движущуюся часть меньше.
"""

import base64
import html
import http.server
import json
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
# и os.replace падает с «Invalid cross-device link». Атомарная замена
# работает только в пределах одной ФС.
TMP = "/etc/sing-box/config.json.new"
AUTH_FILE = "/opt/vpn-config/secrets/webui.env"

LISTEN = ("192.168.88.6", 8088)

# Каталог доступных наборов. Держится здесь, а не читается из сети, чтобы
# страница открывалась и когда GitHub недоступен.
CATALOG = [
    ("Нейросети", [
        ("openai", "ChatGPT, OpenAI API"),
        ("claude", "Claude, Anthropic"),
        ("gemini", "Google Gemini, AI Studio"),
        ("grok", "Grok, x.ai"),
        ("copilot", "GitHub Copilot, Microsoft Copilot"),
    ]),
    ("Соцсети и мессенджеры", [
        ("instagram", "Instagram"),
        ("x", "X (Twitter)"),
        ("linkedin", "LinkedIn"),
        ("whatsapp", "WhatsApp"),
        ("telegram", "Telegram — домены и подсети дата-центров"),
        ("discord-full", "Discord целиком"),
        ("tiktok", "TikTok"),
    ]),
    ("Медиа", [
        ("youtube", "YouTube и googlevideo"),
        ("netflix", "Netflix"),
        ("spotify", "Spotify"),
    ]),
    ("Игры", [
        ("roblox", "Roblox"),
        ("nintendo", "Nintendo"),
    ]),
    ("Голосовые чаты", [
        ("discord-voice-chats", "Голос Discord — включать, если пропадает звук"),
        ("telegram-voice-chats", "Голос Telegram — то же самое"),
    ]),
    ("Крупные наборы — включать осознанно", [
        ("unavailable-in-russia",
         "Всё, что недоступно из России. Самый широкий набор: закрывает «а почему "
         "этот сайт не открылся». Цена — заметно больше трафика через один VPS."),
        ("rkn",
         "Реестр заблокированного в РФ. Огромный и с мусором (мошеннические сайты, "
         "спам). Для дома скорее вреден: нагрузка ради ненужного."),
    ]),
]

PAGE = """<!doctype html><meta charset="utf-8">
<title>Маршрутизация</title>
<style>
:root{{color-scheme:dark}}
body{{font:15px/1.5 -apple-system,system-ui,sans-serif;background:#15171a;color:#e6e6e6;
     margin:0;padding:24px;max-width:940px;margin-inline:auto}}
h1{{font-size:20px;margin:0 0 4px}}
h2{{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#8b98a5;
    margin:28px 0 10px;font-weight:600}}
.status{{background:#1c1f24;border:1px solid #2a2f36;border-radius:10px;padding:14px 16px;
        margin-bottom:8px;display:flex;gap:26px;flex-wrap:wrap}}
.status b{{color:#fff}}
.ok{{color:#4ade80}} .bad{{color:#f87171}}
label{{display:flex;gap:11px;align-items:flex-start;padding:9px 12px;border-radius:8px;
      cursor:pointer}}
label:hover{{background:#1c1f24}}
input[type=checkbox]{{margin-top:3px;width:17px;height:17px;accent-color:#f97316;flex:none}}
.name{{font-weight:600}}
.desc{{color:#8b98a5;font-size:13px}}
textarea{{width:100%;background:#1c1f24;color:#e6e6e6;border:1px solid #2a2f36;
         border-radius:8px;padding:12px;font:13px/1.5 ui-monospace,Menlo,monospace;
         min-height:150px;box-sizing:border-box}}
button{{background:#f97316;color:#111;border:0;border-radius:8px;padding:12px 26px;
       font-size:15px;font-weight:600;cursor:pointer;margin-top:20px}}
button:hover{{background:#fb923c}}
.msg{{padding:13px 16px;border-radius:8px;margin-bottom:18px;white-space:pre-wrap;
     font:13px/1.5 ui-monospace,Menlo,monospace}}
.msg.ok{{background:#0f2a1a;border:1px solid #1f5133}}
.msg.bad{{background:#2a1215;border:1px solid #5a2126}}
.hint{{color:#8b98a5;font-size:13px;margin:6px 0 0}}
</style>
<h1>Что идёт в туннель</h1>
<p class="hint">Роутер отдаёт весь трафик сюда, а решение по каждому соединению
принимает sing-box — по имени хоста. Снятая галочка возвращает сервис напрямую.</p>
{message}
<div class="status">
  <span>sing-box: <b class="{sb_class}">{sb}</b></span>
  <span>туннель: <b class="{tun_class}">{tun}</b></span>
  <span>точка выхода: <b>{exit_ip}</b></span>
</div>
<form method="post">
{groups}
<h2>Свои домены</h2>
<p class="hint">То, чего нет в готовых наборах. Один домен на строку,
поддомены покрываются автоматически.</p>
<textarea name="services">{services}</textarea>
<h2>Свои подсети</h2>
<p class="hint">Только для протоколов без имени хоста — например Telegram MTProto.
Общие облачные диапазоны сюда класть нельзя: отсеивать попутчиков после
этого правила уже некому.</p>
<textarea name="networks">{networks}</textarea>
<button type="submit">Применить</button>
</form>
"""


def read_enabled():
    enabled = set()
    with open(RULESETS) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                enabled.add(line)
    return enabled


def write_rulesets(enabled):
    lines = [
        "# Сгенерировано веб-интерфейсом. Формат прежний: строка без # включена.",
        "# Каталог и пояснения — в веб-интерфейсе на http://192.168.88.6:8088",
        "",
    ]
    for group, items in CATALOG:
        lines.append(f"# --- {group} ---")
        for tag, _ in items:
            lines.append(tag if tag in enabled else f"# {tag}")
        lines.append("")
    with open(RULESETS, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


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
    exit_ip, tun = "—", "не проверялся"
    r = run(["curl", "-sS", "-4", "--proxy", "socks5h://127.0.0.1:1080",
             "--max-time", "10", "https://www.cloudflare.com/cdn-cgi/trace"])
    if r.returncode == 0:
        tun = "работает"
        for line in r.stdout.splitlines():
            if line.startswith("ip="):
                exit_ip = line[3:]
    else:
        tun = "НЕ РАБОТАЕТ"
    return sb, tun, exit_ip


def render(message=""):
    enabled = read_enabled()
    groups = []
    for group, items in CATALOG:
        groups.append(f"<h2>{html.escape(group)}</h2>")
        for tag, desc in items:
            chk = " checked" if tag in enabled else ""
            groups.append(
                f'<label><input type="checkbox" name="rs" value="{tag}"{chk}>'
                f'<span><span class="name">{tag}</span><br>'
                f'<span class="desc">{html.escape(desc)}</span></span></label>'
            )
    sb, tun, exit_ip = status()
    return PAGE.format(
        message=message,
        groups="\n".join(groups),
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
        if not self._authorized():
            return
        self._send(render())

    def do_POST(self):
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        known = {t for _, items in CATALOG for t, _ in items}
        write_rulesets(set(form.get("rs", [])) & known)
        for path, field in ((SERVICES, "services"), (NETWORKS, "networks")):
            if field in form:
                with open(path, "w") as fh:
                    fh.write(form[field][0].replace("\r\n", "\n"))

        ok, text = apply_config()
        if ok:
            # Дать sing-box подняться и подтянуть rule-set, иначе статус
            # сразу после перезапуска показывает «туннель не работает»
            # и пугает без причины.
            time.sleep(8)
        cls = "ok" if ok else "bad"
        self._send(render(f'<div class="msg {cls}">{html.escape(text)}</div>'))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(LISTEN, Handler).serve_forever()
