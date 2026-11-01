from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qbit_agent", ROOT / "qbit_stats" / "agent.py")
agent = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["qbit_agent"] = agent
SPEC.loader.exec_module(agent)


def torrent(identity="a", category="films", tags="family,4k",
            up=100, down=50, upspeed=0, dlspeed=0, last_activity=None):
    return agent.TorrentCounter(
        identity=identity,
        category=category,
        tags=tuple(t for t in tags.split(",") if t),
        up=up,
        down=down,
        state="uploading",
        up_speed=upspeed,
        down_speed=dlspeed,
        last_activity=int(time.time()) if last_activity is None else last_activity,
    )


def snapshot(*torrents, alltime_up=1000, alltime_down=500,
             up_speed=10, down_speed=20):
    return agent.QbitSnapshot(
        status="connected",
        up_speed=up_speed,
        down_speed=down_speed,
        session_up=100,
        session_down=200,
        alltime_up=alltime_up,
        alltime_down=alltime_down,
        connections=12,
        dht_nodes=30,
        torrents=tuple(torrents),
        version="5.1.4",
    )


def test_counter_delta_handles_reset():
    assert agent.counter_delta(120, 100) == 20
    assert agent.counter_delta(5, 100) == 5
    assert agent.counter_delta(5, None) == 5


def test_first_snapshot_only_establishes_baseline(tmp_path):
    tracker = agent.DeltaTracker()
    result = tracker.add(snapshot(torrent()), time.time())
    assert result.up == 0 and result.down == 0
    assert result.categories == {}


def test_category_tag_and_activity_deltas():
    tracker = agent.DeltaTracker()
    now = time.time()
    tracker.add(snapshot(torrent(up=100, down=50), alltime_up=1000,
                         alltime_down=500), now)
    result = tracker.add(snapshot(
        torrent(up=160, down=90, upspeed=1000, dlspeed=20),
        torrent(identity="b", category="kids", tags="family",
                up=20, down=10, upspeed=500, last_activity=now - 60),
        alltime_up=1120, alltime_down=560,
        up_speed=1500, down_speed=20,
    ), now + 60)
    assert (result.up, result.down) == (120, 60)
    assert result.categories["films"] == (60, 40)
    assert result.categories["kids"] == (20, 10)
    assert result.categories[agent.UNKNOWN_CATEGORY] == (40, 10)
    assert result.tags["family"] == (80, 50)
    assert result.tags["4k"] == (60, 40)
    assert result.active == 2
    assert result.downloading == 1
    assert result.seeding == 2
    assert result.seen_24h == 2


def test_store_query_and_privacy_columns(tmp_path):
    path = tmp_path / "stats.db"
    conn = agent.connect(path)
    tracker = agent.DeltaTracker()
    now = time.time()
    first = snapshot(torrent())
    tracker.add(first, now)
    agent.store_snapshot(conn, first, agent.Aggregate(), now)
    second = snapshot(torrent(up=200, down=80), alltime_up=1100,
                      alltime_down=530, up_speed=900)
    result = tracker.add(second, now + 60)
    agent.store_snapshot(conn, second, result, now + 60)
    data = agent.query_stats(conn, 1)
    assert data["totals"]["up"] == 100
    assert data["totals"]["down"] == 30
    assert data["counts"]["total"] == 1
    assert data["categories"][0]["label"] == "films"
    columns = {row[1] for row in conn.execute("PRAGMA table_info(samples)")}
    assert "name" not in columns and "magnet" not in columns and "hash" not in columns
    conn.close()


def test_http_handler_auth_logic():
    from types import SimpleNamespace

    settings = agent.Settings(token="x" * 32)
    handler = agent.StatsHandler.__new__(agent.StatsHandler)
    handler.server = SimpleNamespace(settings=settings)
    handler.headers = {"Authorization": "Bearer " + "x" * 32}
    assert handler._authorized()
    handler.headers = {"Authorization": "Bearer wrong"}
    assert not handler._authorized()

import pytest  # noqa: E402 — нужен для pytest.raises после загрузки модуля
