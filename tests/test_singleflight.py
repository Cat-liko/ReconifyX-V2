"""同键请求合并:并发只跑一次、异常广播、结束后可重跑。"""

import asyncio

from app.core.singleflight import SingleFlight


async def test_concurrent_calls_run_factory_once():
    sf = SingleFlight()
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return "value"

    results = await asyncio.gather(*[sf.do("k", factory) for _ in range(5)])

    assert results == ["value"] * 5
    assert calls["n"] == 1
    assert sf.stats()["leaders"] == 1
    assert sf.stats()["joined"] == 4


async def test_key_is_released_after_completion():
    sf = SingleFlight()
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        await asyncio.sleep(0.01)
        return calls["n"]

    assert await sf.do("k", factory) == 1
    assert sf.inflight == 0
    # 结束后同一个 key 必须能重新跑,否则缓存会永久卡死
    assert await sf.do("k", factory) == 2


async def test_exception_reaches_every_waiter():
    sf = SingleFlight()

    async def boom():
        await asyncio.sleep(0.02)
        raise RuntimeError("upstream failed")

    results = await asyncio.gather(
        *[sf.do("k", boom) for _ in range(3)], return_exceptions=True
    )
    assert all(isinstance(r, RuntimeError) for r in results)
    assert sf.inflight == 0


async def test_different_keys_do_not_block_each_other():
    sf = SingleFlight()

    async def factory(tag, delay):
        await asyncio.sleep(delay)
        return tag

    results = await asyncio.gather(
        sf.do("a", lambda: factory("a", 0.05)),
        sf.do("b", lambda: factory("b", 0.01)),
    )
    assert results == ["a", "b"]


async def test_cancelled_follower_does_not_cancel_shared_work():
    """一个客户端断开,不能把别人还在等的那次扫描一起取消。"""
    sf = SingleFlight()
    done = {"v": None}

    async def factory():
        await asyncio.sleep(0.08)
        done["v"] = True
        return "ok"

    leader = asyncio.create_task(sf.do("k", factory))
    await asyncio.sleep(0)  # 让 leader 先登记
    follower = asyncio.create_task(sf.do("k", factory))
    await asyncio.sleep(0.01)
    follower.cancel()

    assert await leader == "ok"
    assert done["v"] is True
