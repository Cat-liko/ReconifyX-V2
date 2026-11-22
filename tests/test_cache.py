"""进程内缓存 fresh/stale/miss 与容量淘汰。"""

import types

import pytest

from app.core import cache
from app.core.cache import InMemoryBackend


@pytest.fixture
def clock(monkeypatch):
    """把 cache 的时间基准换成可控的假时钟。"""
    now = {"t": 1000.0}
    monkeypatch.setattr(cache, "_now", lambda: now["t"])
    monkeypatch.setattr(
        cache, "_settings", types.SimpleNamespace(CACHE_TTL_SECONDS=10, CACHE_STALE_MAX_SECONDS=100)
    )
    monkeypatch.setattr(cache, "_backend", InMemoryBackend(maxsize=4))
    return now


async def test_fresh_then_stale_then_miss(clock):
    await cache.set("k", "v")
    state, value = await cache.get_with_state("k")
    assert (state, value) == (cache.FRESH, "v")

    clock["t"] += 11  # 超过 fresh 窗口,仍在 stale 窗口
    state, value = await cache.get_with_state("k")
    assert (state, value) == (cache.STALE, "v")
    # STALE 时值仍然可兜底
    assert await cache.peek_stale("k") == "v"

    clock["t"] += 200  # 超过 stale 上限 → 视同未命中,并清掉条目
    state, value = await cache.get_with_state("k")
    assert (state, value) == (cache.MISS, None)
    assert await cache.peek_stale("k") is None


async def test_get_only_returns_fresh(clock):
    await cache.set("k", "v")
    assert await cache.get("k") == "v"
    clock["t"] += 11
    assert await cache.get("k") is None


async def test_peek_stale_expired_clears_entry(clock):
    await cache.set("k", "v")
    clock["t"] += 200
    assert await cache.peek_stale("k") is None
    # 过期条目应被顺手清掉,而不是留在内存里
    assert "k" not in cache._backend._store


async def test_missing_key_is_miss(clock):
    assert await cache.get_with_state("nope") == (cache.MISS, None)


async def test_maxsize_evicts_oldest_by_timestamp(clock):
    backend = InMemoryBackend(maxsize=2)
    await backend.set_entry("a", 1, 100.0)
    await backend.set_entry("b", 2, 200.0)
    await backend.set_entry("c", 3, 300.0)  # 超限,淘汰时间戳最老的 a
    assert await backend.get_entry("a") is None
    assert (await backend.get_entry("b"))[0] == 2
    assert (await backend.get_entry("c"))[0] == 3
