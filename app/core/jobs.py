"""进程内异步任务(job)存储 —— 轮询式异步扫描的任务状态管理。

异步扫描把「长扫描」拆成「快 POST 拿 job_id → 多次快 GET 轮询」。本模块负责:
  - 存 job 的完整状态机(queued → running → completed | failed)
  - 同 (domain, plan) 的去重索引:已有未完成任务时复用 job_id,避免快速重复 POST 打爆上游
  - 懒清理:终结(completed/failed)的 job 超过 TTL 后被清理;容量上限时淘汰最老的**终结**任务

一条重要的淘汰规则
------------------
淘汰**只能**发生在终态任务上。旧实现按 ``created_at`` 淘汰最老的一条,不管它是不是
还在跑 —— 于是容量打满时,一个正在执行的扫描会被从字典里删掉:它的后台任务还在跑
(持有对象引用),结果也照样写缓存,但客户端轮询却拿到 404。用户看到的是"扫到一半
任务消失了",而且完全无法排查。

现在的策略:
  1. 先清掉"已终结且超过 TTL"的;
  2. 仍超限则淘汰最老的**终结**任务;
  3. 如果全部都在跑(queued/running),**宁可短暂超过上限**也不踢 —— 并在日志里留痕。
     "全部在跑"意味着上限正好等于当前并发扫的域数,内存压力是暂时的、可自愈的。

本地自部署开源版:单用户/可信环境,不做调用方隔离。当前默认单 worker,进程内即可;
切多 worker / Redis 时把本模块换成对应后端实现,main.py 只需换掉 job_store 实例。
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.config import get_settings

logger = logging.getLogger("reconifyx.jobs")

_settings = get_settings()

# job 状态机
QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
TERMINAL_STATES = frozenset({COMPLETED, FAILED})


@dataclass
class Job:
    """单个异步扫描任务的完整状态。可变:后台任务直接改字段(asyncio 单线程,改字段无需锁)。"""

    job_id: str
    domain_key: str
    plan: str            # 归一化小写:basic / pro / ultra
    status: str          # queued / running / completed / failed
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    from_cache: bool = False          # True=缓存 FRESH 命中秒回,数据非本次新算
    saved_path: Optional[str] = None  # 结果落盘路径(实际扫描完成后由 main._save_result 设置)
    result: Any = None                # ScanData / ProScanData / UltraScanData
    degraded: Optional[bool] = None
    sources: Optional[list] = None
    error: Optional[str] = None

    @property
    def elapsed_ms(self) -> Optional[int]:
        """已耗时(毫秒)。running 时按当前时间算,终结后按 finished_at 定格。"""
        if self.started_at is None:
            return None
        end = self.finished_at if self.finished_at is not None else time.time()
        return int((end - self.started_at) * 1000)


class JobStore:
    """进程内 job 存储 + (domain, plan) 去重索引。非线程安全,asyncio.Lock 兜并发。"""

    def __init__(self, maxsize: int, ttl: float):
        self._jobs: Dict[str, Job] = {}
        # (domain, plan) -> job_id,仅 queued/running 占用;终结时由 release_active 清掉
        self._active: Dict[tuple, str] = {}
        self._lock = asyncio.Lock()
        self._maxsize = max(1, maxsize)
        self._ttl = ttl

    # ---------------- 写入 ----------------

    async def add(self, job: Job) -> None:
        async with self._lock:
            self._jobs[job.job_id] = job
            self._purge_expired_locked()
            while len(self._jobs) > self._maxsize:
                victim = self._oldest_terminal_locked()
                if victim is None:
                    # 全部在跑:宁可暂时超限,也不能让正在轮询的任务突然 404
                    logger.warning(
                        "job store over capacity (%d > %d) with no terminal job to evict; "
                        "all in-flight jobs are kept",
                        len(self._jobs),
                        self._maxsize,
                    )
                    break
                self._release_active_of(self._jobs[victim])
                del self._jobs[victim]

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            # 懒清理:已终结且超过 TTL 的直接删除,防内存膨胀
            if self._is_expired_locked(job):
                self._release_active_of(job)
                del self._jobs[job_id]
                return None
            return job

    # ---------------- 去重索引 ----------------

    async def find_active(self, domain: str, plan: str) -> Optional[str]:
        async with self._lock:
            return self._active.get((domain, plan))

    async def reserve_active(self, domain: str, plan: str, job_id: str) -> Optional[str]:
        """原子地"占坑":同 (domain, plan) 已有未完成任务时返回其 job_id(调用方复用之);
        否则登记本次 job_id 并返回 None。

        为什么是"一次锁里完成判断+登记",而不是 find_active 再 mark_active:
        两步法是两次独立加锁,中间存在 await 点。当前单事件循环 + 内存后端下靠
        "临界区恰好不 yield"侥幸不炸,但本模块注释里规划了切 Redis / 多 worker,
        那时这个窗口就会变成真实的竞态 —— 同一 (domain, plan) 会开出两个任务、
        对整个目标域打两遍上游。用一次锁把判断和登记做成原子操作,与后端无关。
        """
        async with self._lock:
            existing = self._active.get((domain, plan))
            if existing is not None:
                return existing
            self._active[(domain, plan)] = job_id
            return None

    async def release_active(self, domain: str, plan: str, job_id: str) -> None:
        async with self._lock:
            # 只删自己占用的索引:防止任务 A 完成后误删任务 B 刚登记的新索引
            if self._active.get((domain, plan)) == job_id:
                del self._active[(domain, plan)]

    # ---------------- 内部工具(必须在锁内调用) ----------------

    def _is_expired_locked(self, job: Job) -> bool:
        return job.finished_at is not None and (time.time() - job.finished_at) > self._ttl

    def _purge_expired_locked(self) -> None:
        expired: List[str] = [
            job_id for job_id, job in self._jobs.items() if self._is_expired_locked(job)
        ]
        for job_id in expired:
            self._release_active_of(self._jobs[job_id])
            del self._jobs[job_id]

    def _oldest_terminal_locked(self) -> Optional[str]:
        """最老的**已终结**任务 id;没有终结任务时返回 None(绝不返回在跑的任务)。"""
        best_id: Optional[str] = None
        best_at: Optional[float] = None
        for job_id, job in self._jobs.items():
            if job.status not in TERMINAL_STATES:
                continue
            stamp = job.finished_at if job.finished_at is not None else job.created_at
            if best_at is None or stamp < best_at:
                best_id, best_at = job_id, stamp
        return best_id

    def _release_active_of(self, job: Job) -> None:
        """内部:淘汰 job 时同步清其去重索引(需在锁内调用)。"""
        key = (job.domain_key, job.plan)
        if self._active.get(key) == job.job_id:
            del self._active[key]

    # ---------------- 观测 ----------------

    async def stats(self) -> Dict[str, int]:
        """给 /metrics 用的快照:按状态计数 + 总数。"""
        async with self._lock:
            counts = {QUEUED: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0}
            for job in self._jobs.values():
                if job.status in counts:
                    counts[job.status] += 1
            counts["total"] = len(self._jobs)
            counts["inflight"] = counts[QUEUED] + counts[RUNNING]
            return counts


job_store = JobStore(maxsize=_settings.JOB_STORE_MAXSIZE, ttl=_settings.JOB_TTL_SECONDS)
