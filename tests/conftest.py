"""测试夹具:每个用例都从干净的进程状态开始,且绝不触碰真实外网。

业务代码里的 cache / job_store / single-flight 都是进程内单例,测试之间会互相污染:
  - 上一个用例写进缓存,下一个用例的 POST /scan 直接命中 FRESH;
  - 上一个用例留下一个还在飞的 single-flight 任务,它绑在**已经关闭的事件循环**上,
    下一个用例 await 它会直接 RuntimeError("bound to a different event loop")。

因此这里做三件事:
  1) 清空缓存与 job 存储;
  2) 清空 single-flight 的 in-flight 表与后台刷新去重集合;
  3) 把 DNS 情报查询换成固定桩 —— 单元测试不该依赖真实解析器,CI 上也不该有外网。
"""

import pytest

from app.core import cache
from app.schemas.scan import DnsIntel


async def _fake_dns_collect(domain: str, settings) -> DnsIntel:
    """离线桩:固定返回一条 A 记录,让发现层有 dns 字段可断言。"""
    return DnsIntel(domain=domain, a=["192.0.2.1"], ns=["ns1.example.net"], resolved=True)


@pytest.fixture(autouse=True)
def _clean_process_state(monkeypatch):
    cache._backend._store.clear()
    cache._stats.update({"fresh": 0, "stale": 0, "miss": 0})

    # app.main 持有的是同一个 job_store 实例,清它的内部容器即可
    from app.main import _pipeline_sf, _refreshing, _tasks, job_store

    job_store._jobs.clear()
    job_store._active.clear()
    _refreshing.clear()
    for sf in _pipeline_sf.values():
        sf._inflight.clear()
    _tasks.clear()

    # 离线:DNS 情报查询一律走桩,避免测试依赖真实 DNS
    monkeypatch.setattr("app.main.dns_service.collect", _fake_dns_collect)

    yield

    cache._backend._store.clear()
