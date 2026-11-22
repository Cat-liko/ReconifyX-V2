"""缓存 fresh 窗口覆盖(fresh_ttl)—— 降级快照的"永远 STALE"语义。"""

import time

from app.core import cache


async def test_fresh_ttl_zero_is_always_stale():
    """降级的残缺快照:值得缓存(免得故障期间每次重打上游),但不能被当权威结果。"""
    await cache.set("k", ("value", True, []), fresh_ttl=0)
    state, value = await cache.get_with_state("k")
    assert state == cache.STALE
    assert value[0] == "value"

    # 依然可以被 peek_stale 取到(上游失败时的兜底来源)
    assert await cache.peek_stale("k") is not None


async def test_default_entry_is_fresh():
    await cache.set("k2", ("v", False, []))
    state, _ = await cache.get_with_state("k2")
    assert state == cache.FRESH


async def test_fresh_ttl_can_extend_window():
    await cache.set("k3", ("v",), fresh_ttl=10_000)
    state, _ = await cache.get_with_state("k3")
    assert state == cache.FRESH


async def test_expired_beyond_stale_max_is_miss():
    await cache.set("k4", ("v",))
    # 手动把存入时刻改到 stale 窗口之外
    value, _stored, ttl = cache._backend._store["k4"]
    cache._backend._store["k4"] = (value, time.time() - cache._settings.CACHE_STALE_MAX_SECONDS - 1, ttl)

    state, value = await cache.get_with_state("k4")
    assert state == cache.MISS
    assert value is None


async def test_stats_count_outcomes():
    cache._stats.update({"fresh": 0, "stale": 0, "miss": 0})
    await cache.set("s1", ("v",))
    await cache.get_with_state("s1")          # fresh
    await cache.get_with_state("missing")     # miss

    stats = cache.stats()
    assert stats["fresh"] == 1
    assert stats["miss"] == 1


async def test_size_reports_entries():
    await cache.set("z1", ("v",))
    await cache.set("z2", ("v",))
    assert await cache.size() == 2
