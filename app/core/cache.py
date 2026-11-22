"""进程内缓存 —— stale-while-revalidate(过期先返回旧的,后台再刷新)。

我们本质是"数据搬运工":上游几个免费源(crt.sh / CertSpotter / FOFA)
零 SLA,随时可能限流或超时。若命中即返回、没命中就现拉,一旦上游抖动,用户拿到的
就是"接口失败/空结果"。为把上游的不稳定,吸收成我们这一层的稳定,采用两段窗口:

  fresh 窗口(默认 12h):命中直接返回,状态最新。
  stale 窗口(默认 7 天):fresh 过期但未超 stale 上限时,**先把旧数据返回给用户**,
    同时后台静默重拉刷新;下一个请求就能拿到新鲜结果。用户永远不用干等上游。
  超过 stale 上限:视同未命中,强制同步现拉。

另外:上游本次现拉失败(degraded)时,调用方可回退到这里的 stale 快照兜底,
避免把"残缺空结果"甩给用户。

============================================================================
可无痛切 Redis 的设计
----------------------------------------------------------------------------
本模块分两层:
  1) CacheBackend 抽象层:只管 (值, 存入时刻, fresh 窗口) 的存 / 取 / 删三个原子操作。
  2) 模块级公开函数(get_with_state / peek_stale / get / set):承载 fresh/stale
     判定这套业务逻辑,**与后端无关**。调用方只依赖这一层。

要切 Redis,只需新增一个 RedisBackend 实现同样三个方法,再把 _backend 换掉,
调用方(main.py)一行都不用动。为此已提前踩平两个坑:

  - 时间基准用 time.time()(wall-clock epoch)而非 monotonic:monotonic 是单进程
    相对时间,多 worker / Redis 跨进程无法比较。epoch 全局可比。
  - fresh/stale 判定不依赖后端自动过期:内存后端靠自身逻辑清理,Redis 后端可把
    原生 TTL 设为 stale 上限(CACHE_STALE_MAX_SECONDS)做兜底硬淘汰,fresh/stale
    的区分仍由存入时刻算出 —— 两种后端语义完全一致。

额外一层:fresh_ttl 覆盖。
  每条缓存可以自带一个 fresh 窗口(默认用全局 CACHE_TTL_SECONDS)。这条能力用来表达
  "这份数据可信,但我不希望它被当作新鲜结果"—— 典型场景是骨干源降级时拿到的残缺
  快照:它值得被缓存(否则故障期间每次请求都要重打一遍上游),但不该在 12 小时内被
  当作权威结果。把它的 fresh_ttl 设为 0,它就永远是 STALE:立刻返回给用户 + 触发
  后台刷新,下一次请求就有机会拿到完整数据。

RedisBackend 骨架示例(上线时填充,序列化在后端内部消化,不外泄给调用方):

    class RedisBackend(CacheBackend):
        def __init__(self, redis, stale_max):
            self._r = redis; self._stale_max = stale_max

        async def get_entry(self, key):
            raw = await self._r.get(key)
            if raw is None:
                return None
            payload = pickle.loads(raw)          # 或 JSON + pydantic 反序列化
            return payload["value"], payload["stored_at"], payload.get("fresh_ttl")

        async def set_entry(self, key, value, stored_at, fresh_ttl=None):
            raw = pickle.dumps(
                {"value": value, "stored_at": stored_at, "fresh_ttl": fresh_ttl}
            )
            await self._r.set(key, raw, ex=self._stale_max)   # 原生 TTL 兜底

        async def delete(self, key):
            await self._r.delete(key)
============================================================================
"""

import asyncio
import time
from typing import Any, Dict, Optional, Tuple

from app.core.config import get_settings

_settings = get_settings()

# 状态常量:命中新鲜 / 命中但已过期(可当 stale 用)/ 未命中
FRESH = "fresh"
STALE = "stale"
MISS = "miss"

# 缓存条目:(值, 存入时刻 epoch 秒, 该条目自己的 fresh 窗口;None = 用全局默认)
Entry = Tuple[Any, float, Optional[float]]


def _now() -> float:
    # wall-clock epoch:多进程 / Redis 可跨进程比较(monotonic 只在单进程内有意义)
    return time.time()


# ---------------- 后端抽象层:切 Redis 只需换这一层 ----------------


class CacheBackend:
    """后端只负责 (值, 存入时刻, fresh 窗口) 的原子存取删;不含任何 fresh/stale 判定。"""

    async def get_entry(self, key: str) -> Optional[Entry]:
        raise NotImplementedError

    async def set_entry(
        self, key: str, value: Any, stored_at: float, fresh_ttl: Optional[float] = None
    ) -> None:
        raise NotImplementedError

    async def delete(self, key: str) -> None:
        raise NotImplementedError

    async def size(self) -> int:
        raise NotImplementedError


class InMemoryBackend(CacheBackend):
    """进程内 dict 实现。TTLCache 到期直接删条目、撑不起"过期仍留作 stale",
    故用普通 dict 自记时间戳,并用容量上限做 LRU-by-age 淘汰。
    非线程安全,配一把 asyncio.Lock 兜住并发。"""

    def __init__(self, maxsize: int):
        self._store: Dict[str, Entry] = {}
        self._lock = asyncio.Lock()
        self._maxsize = maxsize

    async def get_entry(self, key: str) -> Optional[Entry]:
        async with self._lock:
            return self._store.get(key)

    async def set_entry(
        self, key: str, value: Any, stored_at: float, fresh_ttl: Optional[float] = None
    ) -> None:
        async with self._lock:
            self._store[key] = (value, stored_at, fresh_ttl)
            while len(self._store) > self._maxsize:
                oldest = min(self._store, key=lambda k: self._store[k][1])
                del self._store[oldest]

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def size(self) -> int:
        async with self._lock:
            return len(self._store)


# 当前后端:内存。上线切 Redis 时替换为 RedisBackend(...),下方公开函数无需改动。
_backend: CacheBackend = InMemoryBackend(maxsize=_settings.CACHE_MAXSIZE)

# 命中 / 未命中计数:只给 /metrics 观测用,不参与任何业务判定
_stats: Dict[str, int] = {"fresh": 0, "stale": 0, "miss": 0}


# ---------------- 公开 API:承载 fresh/stale 判定,与后端无关 ----------------


def _fresh_window(entry: Entry) -> float:
    """该条目生效的 fresh 窗口:条目自带优先,否则用全局配置。"""
    override = entry[2] if len(entry) > 2 else None
    return _settings.CACHE_TTL_SECONDS if override is None else override


async def get_with_state(key: str) -> Tuple[str, Optional[Any]]:
    """按新鲜度返回 (状态, 值)。

    - FRESH:值在 fresh 窗口内,可直接用。
    - STALE:值已过 fresh 但仍在 stale 上限内,可先返回旧的、并触发后台刷新。
    - MISS:无缓存或已超 stale 上限,需同步现拉(值为 None)。
    """
    entry = await _backend.get_entry(key)
    if entry is None:
        _stats["miss"] += 1
        return MISS, None
    value, stored_at = entry[0], entry[1]
    age = _now() - stored_at
    window = _fresh_window(entry)
    # 注意 window > 0 这个条件:fresh_ttl=0 表示"永远判 STALE"。若只用 age <= window,
    # 当两次 time.time() 落在同一微秒(age 恰好 0.0)时会被误判成 FRESH。
    if window > 0 and age <= window:
        _stats["fresh"] += 1
        return FRESH, value
    if age <= _settings.CACHE_STALE_MAX_SECONDS:
        _stats["stale"] += 1
        return STALE, value
    # 超过 stale 上限:清掉,当未命中处理(Redis 后端有原生 TTL,这里是双保险)
    await _backend.delete(key)
    _stats["miss"] += 1
    return MISS, None


async def peek_stale(key: str) -> Optional[Any]:
    """只取仍在 stale 上限内的旧值(用于上游现拉失败时兜底);无则 None。"""
    entry = await _backend.get_entry(key)
    if entry is None:
        return None
    value, stored_at = entry[0], entry[1]
    if _now() - stored_at <= _settings.CACHE_STALE_MAX_SECONDS:
        return value
    await _backend.delete(key)
    return None


async def get(key: str) -> Optional[Any]:
    """兼容旧接口:仅在 fresh 窗口内返回值,否则 None。"""
    state, value = await get_with_state(key)
    return value if state == FRESH else None


async def set(key: str, value: Any, fresh_ttl: Optional[float] = None) -> None:
    """写入缓存。

    fresh_ttl=None → 用全局 CACHE_TTL_SECONDS;
    fresh_ttl=0    → 永远判 STALE(立刻返回 + 后台刷新),用于降级的残缺快照。
    """
    await _backend.set_entry(key, value, _now(), fresh_ttl)


async def size() -> int:
    """当前条目数(仅观测用)。"""
    return await _backend.size()


def stats() -> Dict[str, int]:
    """缓存命中统计快照(供 /metrics 导出)。"""
    return dict(_stats)
