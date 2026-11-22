"""同键请求合并(single-flight)—— 把并发的重复工作收敛成一次。

为什么需要它
------------
一次 Ultra 扫描要打十几秒。前端是"POST 拿 job_id 再轮询",但真实世界里同一个域名
经常被同时点好几次:用户手抖双击、脚本重试、CI 并发跑、同事之间互相发链接。没有这层
合并时,N 个并发请求会**各自**去 crt.sh + CertSpotter + FOFA 拉一遍,再各自探活上千个
子域 —— 上游看到的是 N 倍流量,我们拿到的是 N 份一模一样的结果。

缓存解决的是"先后",这一层解决的是"同时":
  - 缓存命中要等前一次**已经写完**;
  - single-flight 让后来的请求直接**搭上**前一个还在飞的结果。
两者叠加才是完整的:先看缓存(fresh 秒回 / stale 先给旧的),未命中再走 single-flight。

实现要点
--------
1. 只有第一个调用者是 leader,真正执行 factory;其余 joined 直接 await 同一个 Task。
2. follower 用 ``asyncio.shield`` 等待:某个 HTTP 客户端断开导致它自己的协程被取消时,
   **不能**顺带把别人还在等的那次扫描取消掉。
3. leader 被取消时任务仍然继续跑完(同理 shield),结果照样进缓存,下一个请求直接命中。
4. done_callback 里主动 ``task.exception()`` 取一次,避免"exception was never retrieved"
   警告 —— 异常仍然会 **原样抛给** 每一个 await 方。
"""

import asyncio
from typing import Any, Awaitable, Callable, Dict, TypeVar

T = TypeVar("T")


class SingleFlight:
    """按 key 合并并发调用。非线程安全,只在单个事件循环内使用。"""

    __slots__ = ("_inflight", "_leaders", "_joined")

    def __init__(self) -> None:
        self._inflight: Dict[str, "asyncio.Task[Any]"] = {}
        self._leaders = 0
        self._joined = 0

    async def do(self, key: str, factory: Callable[[], Awaitable[T]]) -> T:
        """执行(或搭上)key 对应的一次调用。

        factory 必须自己处理降级/异常语义;这里对异常是透传,不做吞掉 ——
        第一个请求拿到什么错误,后来的每个请求都拿到同样的错误,行为一致。
        """
        task = self._inflight.get(key)
        if task is None:
            self._leaders += 1
            task = asyncio.ensure_future(factory())
            self._inflight[key] = task
            task.add_done_callback(lambda t, k=key: self._finish(k, t))
        else:
            self._joined += 1
        # shield:等待方被取消时不要把共享任务一起取消
        return await asyncio.shield(task)

    def _finish(self, key: str, task: "asyncio.Task[Any]") -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        # 取一次异常,标记为已消费;真正的结果/异常仍会抛给每个 await 方
        if not task.cancelled():
            task.exception()

    @property
    def inflight(self) -> int:
        return len(self._inflight)

    def stats(self) -> Dict[str, int]:
        """给 /metrics 用的计数:leader=真正干活,joined=白搭车的。"""
        return {
            "leaders": self._leaders,
            "joined": self._joined,
            "inflight": len(self._inflight),
        }
