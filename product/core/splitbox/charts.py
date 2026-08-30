"""Графики для дашборда — инлайн-SVG, генерируемый на сервере.

Никаких библиотек и CDN: страница обязана открываться в сети без
интернета, а тянуть в коробку фронтенд-сборку ради двух графиков —
несоразмерно. SVG рисуется строкой и вставляется в шаблон.
"""
from __future__ import annotations

import html
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .stats import human_bytes

UP_COLOR = "#7dd3fc"      # отдано
DOWN_COLOR = "#f97316"    # принято
GRID = "#23282f"
TEXT = "#8b98a5"


def _tz(name: str):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def _fill_gaps(rows: list[dict], hours: int, step: int) -> list[dict]:
    """Ряд без дыр: там, где трафика не было, нужен ноль, иначе ломаная
    соединит соседние точки через пропуск и соврёт о нагрузке."""
    now = int(time.time())
    start = (now - hours * 3600) // step * step
    end = now // step * step
    have = {r["ts"]: r for r in rows}
    out = []
    ts = start
    while ts <= end:
        r = have.get(ts)
        out.append({"ts": ts, "up": r["up"] if r else 0,
                    "down": r["down"] if r else 0})
        ts += step
    return out


def area_chart(rows: list[dict], hours: int = 24, tz_name: str = "UTC",
               width: int = 900, height: int = 220) -> str:
    """График трафика во времени: две области — принято и отдано."""
    step = 60 if hours <= 48 else 3600
    # Ряд из одних нулей выглядит как сломанный график, поэтому пустую
    # историю показываем словами, а не плоской линией.
    if not any(r["up"] or r["down"] for r in rows):
        return ('<div class="hint" style="padding:24px 0">Данных пока нет — '
                'графики появятся через несколько минут работы.</div>')
    data = _fill_gaps(rows, hours, step)
    if len(data) < 2:
        return ('<div class="hint" style="padding:24px 0">Данных пока нет — '
                'графики появятся через несколько минут работы.</div>')

    pad_l, pad_b, pad_t = 58, 22, 10
    plot_w = width - pad_l - 10
    plot_h = height - pad_b - pad_t
    peak = max(max(d["up"], d["down"]) for d in data) or 1
    n = len(data)

    def x(i: int) -> float:
        return pad_l + plot_w * i / (n - 1)

    def y(v: int) -> float:
        return pad_t + plot_h * (1 - v / peak)

    def area(key: str, color: str) -> str:
        pts = " ".join(f"{x(i):.1f},{y(d[key]):.1f}" for i, d in enumerate(data))
        base = f"{x(n - 1):.1f},{y(0):.1f} {x(0):.1f},{y(0):.1f}"
        return (f'<polygon points="{pts} {base}" fill="{color}" '
                f'fill-opacity="0.16"/>'
                f'<polyline points="{pts}" fill="none" stroke="{color}" '
                f'stroke-width="1.8"/>')

    # Сетка и подписи величин
    grid = []
    for frac in (0, 0.5, 1):
        gy = pad_t + plot_h * frac
        grid.append(f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{width - 10}" '
                    f'y2="{gy:.1f}" stroke="{GRID}" stroke-width="1"/>')
        label = human_bytes(peak * (1 - frac) / (step / 8))
        grid.append(f'<text x="{pad_l - 8}" y="{gy + 4:.1f}" fill="{TEXT}" '
                    f'font-size="10" text-anchor="end">{label}/с</text>')

    # Подписи времени
    tz = _tz(tz_name)
    marks = []
    for i in (0, n // 2, n - 1):
        t = datetime.fromtimestamp(data[i]["ts"], tz).strftime("%H:%M")
        anchor = "start" if i == 0 else ("end" if i == n - 1 else "middle")
        marks.append(f'<text x="{x(i):.1f}" y="{height - 6}" fill="{TEXT}" '
                     f'font-size="10" text-anchor="{anchor}">{t}</text>')

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="График трафика">'
        + "".join(grid)
        + area("down", DOWN_COLOR) + area("up", UP_COLOR)
        + "".join(marks)
        + f'<text x="{width - 10}" y="{pad_t + 2}" fill="{DOWN_COLOR}" '
          f'font-size="10" text-anchor="end">принято</text>'
        + f'<text x="{width - 78}" y="{pad_t + 2}" fill="{UP_COLOR}" '
          f'font-size="10" text-anchor="end">отдано</text>'
        + "</svg>")


DIRECTION_LABEL = {
    "own": "свой сервер",
    "fast": "группа скорости",
    "direct": "напрямую",
    "other": "прочее",
}
DIRECTION_COLOR = {
    "own": "#38bdf8",
    "fast": "#f97316",
    "direct": "#4ade80",
    "other": "#8b98a5",
}


def donut(rows: list[dict], size: int = 190) -> str:
    """Кольцо «куда ушёл трафик»: доли направлений."""
    total = sum(r["total"] for r in rows)
    if not total:
        return '<div class="hint">Пока нет данных</div>'
    r = size / 2 - 16
    cx = cy = size / 2
    circ = 2 * 3.14159265 * r
    parts, offset = [], 0.0
    for row in rows:
        frac = row["total"] / total
        color = DIRECTION_COLOR.get(row["direction"], "#8b98a5")
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" '
            f'stroke="{color}" stroke-width="18" '
            f'stroke-dasharray="{circ * frac:.2f} {circ:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>')
        offset += circ * frac
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'role="img" aria-label="Распределение трафика">'
            + "".join(parts)
            + f'<text x="{cx}" y="{cy - 2}" fill="#e8eaed" font-size="15" '
              f'text-anchor="middle" font-weight="650">'
              f'{html.escape(human_bytes(total))}</text>'
            + f'<text x="{cx}" y="{cy + 15}" fill="{TEXT}" font-size="10" '
              f'text-anchor="middle">всего</text></svg>')
