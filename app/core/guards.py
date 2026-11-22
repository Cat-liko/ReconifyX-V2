"""请求守卫 —— API Key 鉴权 + 每 IP 令牌桶限流。

定位先说清楚
------------
**默认不鉴权**。本工具默认只监听 127.0.0.1,单机单用户,加鉴权只会碍事。
但一旦你把 ``HOST`` 改成 0.0.0.0(容器/内网共享),任何人都能用它去打任意域名 ——
这时候 ``API_KEY`` 就是必须的。所以这里的策略是:

  - ``API_KEY`` 为空 → 完全跳过鉴权检查(不是"空 key 也能过",而是不启用这道闸);
  - ``API_KEY`` 非空 → 所有"会对外发起探测"的路径都要求 ``X-API-Key`` 头,
    比较用 ``hmac.compare_digest`` 做定长比较,避免时序侧信道。

限流是**防误用**而不是安全边界:真正的边界是 API_KEY 和监听地址。令牌桶按客户端 IP
计数,只约束 API 路径,静态页与健康检查不计入 —— 否则浏览器一刷新就把额度耗光。
"""

import hmac
import time
from typing import Dict, Tuple

# 需要守卫的路径前缀(会对外发起真实探测的端点)
GUARDED_PREFIXES = ("/scan", "/dns", "/history", "/debug")

# 不做限流的路径(健康检查与指标是给探针高频拉取的)
UNMETERED_PATHS = frozenset({"/healthz", "/readyz", "/metrics", "/openapi.json", "/docs", "/redoc"})


def requires_guard(path: str) -> bool:
    """该路径是否需要鉴权 / 限流。"""
    if path in UNMETERED_PATHS:
        return False
    return any(path.startswith(prefix) for prefix in GUARDED_PREFIXES)


def api_key_ok(expected: str, provided: "str | None") -> bool:
    """校验 API Key。expected 为空 → 未启用鉴权,一律通过。"""
    if not expected:
        return True
    if not provided:
        return False
    # 定长比较:直接 != 会泄露"前几个字符对了"的时间信息
    return hmac.compare_digest(expected, provided)


class TokenBucket:
    """每 key 一个令牌桶(按客户端 IP)。

    参数含义:
      per_minute: 每分钟补充的令牌数(稳态速率);
      burst:      桶容量(允许的瞬时突发)。

    实现刻意简单:惰性补充(每次访问按经过时间补),不为每个 key 起定时器。
    条目数超过上限时清理久未访问的 key,防止被伪造源 IP 打爆内存。
    """

    __slots__ = ("_rate", "_capacity", "_buckets", "_max_buckets", "_idle_seconds")

    def __init__(self, per_minute: int, burst: int):
        self._rate = max(1, per_minute) / 60.0     # 每秒补充的令牌
        self._capacity = max(1, burst)
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._max_buckets = 4096
        self._idle_seconds = 600.0

    def allow(self, key: str, now: "float | None" = None) -> bool:
        """取一个令牌。返回 False 表示应回 429。"""
        now = time.time() if now is None else now
        tokens, last = self._buckets.get(key, (float(self._capacity), now))
        # 惰性补充
        tokens = min(self._capacity, tokens + (now - last) * self._rate)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            self._maybe_prune(now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        self._maybe_prune(now)
        return True

    def _maybe_prune(self, now: float) -> None:
        if len(self._buckets) <= self._max_buckets:
            return
        stale = [k for k, (_, ts) in self._buckets.items() if now - ts > self._idle_seconds]
        for key in stale:
            self._buckets.pop(key, None)
        # 还是太多(可能是被大量不同源 IP 刷):直接清空,宁可短暂放宽也不无限涨
        if len(self._buckets) > self._max_buckets:
            self._buckets.clear()

    def retry_after_seconds(self, key: str) -> int:
        """给 429 响应用:距离能再取到 1 个令牌还有多久。"""
        tokens, _last = self._buckets.get(key, (0.0, 0.0))
        missing = max(0.0, 1.0 - tokens)
        return max(1, int(missing / self._rate) + 1)

    def size(self) -> int:
        return len(self._buckets)
