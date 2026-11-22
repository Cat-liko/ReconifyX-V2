"""ReconifyX —— 本地自部署的攻击面管理(ASM)平台。

一个输入口(主域名),三条逐渐加深的管线(Basic / Pro / Ultra),统一输出
"资产清单 + 邮件伪造风险 + 子域名接管风险 + 风险总账 + 与上次扫描的差异"。

本模块只做**编排**,不实现任何检测逻辑:
    basic.py            被动子域名发现(证书透明度 + FOFA)
    dns_service.py      主域 DNS 情报
    probe_service.py    高并发 HTTP 探活(+ 安全响应头)
    tls_service.py      TLS 证书情报
    audit_service.py    SPF / DMARC 邮件伪造审计
    takeover_service.py 子域名接管检测(CNAME × 正文指纹)
    risk_service.py     把以上发现汇成风险分
    diff_service.py     与上一次扫描的集合差异
    export_service.py   JSON / CSV / Markdown 导出

编排层要解决的四件事:
  1) **延迟**:Pro/Ultra 的三条支线(HTTP 探活 / DNS 审计 / DNS 扇出)必须并发,
     墙钟取 max 而不是求和;发现层的 DNS 情报与子域名发现也要并发。
  2) **上游抖动**:stale-while-revalidate 缓存 + single-flight 合并并发请求 +
     降级快照永远判 STALE(立刻返回 + 后台刷新)。
  3) **长任务**:POST /scan 毫秒级返回 job_id,客户端轮询;job 有 TTL 与淘汰策略。
  4) **安全边界**:域名校验、落盘文件名消毒、可选 API Key、每 IP 限流。
"""

import asyncio
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from app.core import cache
from app.core.config import get_settings
from app.core.domain import normalize_domain
from app.core.guards import TokenBucket, api_key_ok, requires_guard
from app.core.history import HistoryStore
from app.core.jobs import COMPLETED, FAILED, QUEUED, RUNNING, Job, job_store
from app.core.loop_hygiene import quiet_windows_reset_noise
from app.core.metrics import METRICS, observe_request, render_text
from app.core.singleflight import SingleFlight
from app.schemas.scan import (
    ApiMeta,
    BatchScanAccepted,
    BatchScanCreate,
    DnsIntel,
    HistoryEntry,
    PlanCapability,
    PlanNotAvailableResponse,
    ProScanData,
    ProScanResponse,
    ScanData,
    ScanDiff,
    ScanInfo,
    ScanJobAccepted,
    ScanJobCreate,
    ScanJobStatus,
    ScanResponse,
    UltraScanData,
    UltraScanResponse,
    utcnow_iso,
)
from app.services import (
    audit_service,
    basic,
    diff_service,
    dns_service,
    export_service,
    probe_service,
    risk_service,
    takeover_service,
)

settings = get_settings()

logger = logging.getLogger("reconifyx")

if not logging.getLogger().handlers:
    # 只在没有任何 handler 时配置(uvicorn / pytest 各自会配),避免重复输出
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

# httpx / httpcore 默认每条请求打一条 INFO。一次 Ultra 扫描可能有上千次请求,
# 这些"HTTP Request: GET ..."会淹没真正要看的东西(CLI 的 stderr、服务端日志都是)。
# 协议层细节只在 LOG_LEVEL=debug 时才放开。
if settings.LOG_LEVEL.upper() != "DEBUG":
    for _noisy in ("httpx", "httpcore"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)

# 后台刷新去重:同一缓存键同时只跑一个刷新任务,避免 stale 命中风暴打爆上游。
# 注意这与 single-flight 是两道不同的闸:这里是"别开新任务",single-flight 是
# "开了也合流"。两者叠加才能保证上游只会看到一次请求。
_refreshing: set[str] = set()

# 后台任务强引用集合。asyncio 文档明确要求保存 create_task 的返回值:事件循环
# 只持有弱引用,任务在等待 I/O 时可能被 GC 回收,表现成"后台刷新偶发不执行"。
_tasks: set[asyncio.Task] = set()

# single-flight:发现层一把,完整管线各一把(键都带计划前缀,互不干扰)
_discovery_sf = SingleFlight()
_pipeline_sf: Dict[str, SingleFlight] = {
    "basic": SingleFlight(),
    "pro": SingleFlight(),
    "ultra": SingleFlight(),
}

# 扫描历史(SQLite)。所有方法在 history 未就绪时都是安全空操作。
history = HistoryStore(
    path=settings.HISTORY_DB_PATH,
    enabled=settings.HISTORY_ENABLED,
    max_per_domain=settings.HISTORY_MAX_SCANS_PER_DOMAIN,
)

# 每 IP 令牌桶
_limiter = TokenBucket(settings.RATE_LIMIT_PER_MINUTE, settings.RATE_LIMIT_BURST)


# ==================== 小工具 ====================


def _spawn(coro) -> asyncio.Task:
    """创建后台任务并登记强引用,任务结束后自动注销。"""
    task = asyncio.create_task(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task


def _plan_display(plan_norm: str) -> str:
    """小写计划名 → 对外展示的计划名。"""
    return {
        "basic": settings.PLAN_BASIC,
        "pro": settings.PLAN_PRO,
        "ultra": settings.PLAN_ULTRA,
    }.get(plan_norm, settings.PLAN_BASIC)


def _valid_plans() -> Tuple[str, ...]:
    return (
        settings.PLAN_BASIC.lower(),
        settings.PLAN_PRO.lower(),
        settings.PLAN_ULTRA.lower(),
    )


def _pro_key(domain_key: str) -> str:
    """Pro 缓存键加计划前缀,与 Basic 的裸域名键隔离,防止两种结构互相覆盖。"""
    return f"pro::{domain_key}"


def _ultra_key(domain_key: str) -> str:
    """Ultra 缓存键加计划前缀,与 Basic/Pro 隔离,防止三种结构互相覆盖。"""
    return f"ultra::{domain_key}"


def _plan_cache_key(domain_key: str, plan_norm: str) -> str:
    if plan_norm == "pro":
        return _pro_key(domain_key)
    if plan_norm == "ultra":
        return _ultra_key(domain_key)
    return domain_key


def _probe_coverage_note(total: int, complete: bool) -> str:
    """探活覆盖度的英文人读说明(始终带上限 cap,截断时给出跳过数)。"""
    cap = settings.PRO_MAX_PROBE_TARGETS
    if complete:
        return f"Full coverage: probed all {total} targets (cap {cap})."
    return (
        f"Partial coverage: cap {cap} targets — probed the first {cap} of {total} "
        f"({total - cap} skipped). Raise the cap or re-query for full coverage."
    )


def _epoch_to_iso(ts: Optional[float]) -> Optional[str]:
    """epoch 秒转 ISO 字符串,与 utcnow_iso() 同风格(UTC + Z 后缀)。"""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _error(
    status: int,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    **extra: Any,
) -> JSONResponse:
    """统一的错误响应体。前端与 CLI 都靠 ``message`` 字段拿人读文案。"""
    content: Dict[str, Any] = {"status": "error", "message": message}
    content.update(extra)
    return JSONResponse(status_code=status, content=content, headers=headers)


# ==================== 缓存写入策略 ====================


async def _store_cached(key: str, payload: Any, degraded: bool) -> None:
    """把结果写进缓存,并区分"完整快照"与"降级快照"。

    降级快照(骨干源全挂)不是没用:它比"接口失败"好,也比"故障期间每个请求都重打
    一遍上游"好。但它不该在 12 小时内被当成权威结果。所以:
      - 用 ``fresh_ttl=0`` 存 → 立刻判 STALE:本次能秒回给用户,同时触发后台刷新;
      - 若已有 FRESH 的完整快照,不覆盖(拿残缺结果盖掉好数据是纯粹的倒退)。
    """
    if degraded:
        state, _ = await cache.get_with_state(key)
        if state == cache.FRESH:
            return
        await cache.set(key, payload, fresh_ttl=0)
    else:
        await cache.set(key, payload)


# ==================== 三条管线 ====================


async def _run_discovery(domain_key: str):
    """Basic:被动子域名发现 + DNS 情报(两条并发),产出 ScanData。"""
    (subdomains, assets, degraded, sources), dns_intel = await asyncio.gather(
        basic.discover(domain_key, settings),
        dns_service.collect(domain_key, settings),
    )
    data = ScanData(
        total_found=len(subdomains),
        subdomains=subdomains,
        total_assets=len(assets),
        assets=assets,
        dns=dns_intel,
    )
    data.risk = risk_service.assess(data)
    await _store_cached(domain_key, (data, degraded, sources), degraded)
    return data, degraded, sources


async def _ensure_discovery(domain_key: str):
    """拿一份可用的发现结果:FRESH 直接复用,否则走 single-flight 重拉。

    Pro / Ultra 复用 Basic 的发现结果有两个好处:
      1) 先 Basic 后 Pro 的场景不会白打一遍上游;
      2) 并发的 Basic/Pro/Ultra 请求会合流到同一次发现(而不是三份)。
    """
    state, cached = await cache.get_with_state(domain_key)
    if state == cache.FRESH and cached is not None:
        return cached
    return await _discovery_sf.do(domain_key, lambda: _run_discovery(domain_key))


async def _run_pro_discovery(domain_key: str):
    """Pro:发现 → (HTTP 探活 + 全域邮件审计)并发 → ProScanData。

    时效关键:探活(HTTP)与邮件审计(DNS)彼此独立,用 asyncio.gather 并发跑 ——
    HTTP 的网络等待与 DNS 的等待完全重叠,不串行累加。
    """
    base, degraded, sources = await _ensure_discovery(domain_key)

    probe_targets = base.subdomains if base.subdomains else [domain_key]

    (live_assets, probe_complete), email_report = await asyncio.gather(
        probe_service.probe_liveness(probe_targets, settings),
        audit_service.audit_email_security_full(domain_key, base.subdomains, settings),
    )

    data = ProScanData(
        total_found=base.total_found,
        subdomains=base.subdomains,
        total_assets=base.total_assets,
        assets=base.assets,
        dns=base.dns,
        total_live=len(live_assets),
        live_assets=live_assets,
        probe_complete=probe_complete,
        probe_note=_probe_coverage_note(len(probe_targets), probe_complete),
        email_audit=email_report,
    )
    data.risk = risk_service.assess(data)
    await _store_cached(_pro_key(domain_key), (data, degraded, sources), degraded)
    return data, degraded, sources


async def _run_ultra_discovery(domain_key: str):
    """Ultra:发现 → 三支线并发(探活含正文 / 邮件审计 / CNAME 扇出)→ 纯 CPU 聚合接管。

    接管检测拆两阶段(关键性能设计):
      阶段 A(asyncio.gather,墙钟取 max):probe(HTTP 抓正文)+ audit(DNS 扇出)
        + fanout_cname(DNS 扇出)。CNAME 扇出只依赖子域列表,与 probe/audit 完全并发。
      阶段 B(纯 CPU,零额外墙钟):assemble_takeover 拿 probe 复用出的正文 × CNAME 链
        做指纹交叉判定。若把两阶段合成一个依赖正文的函数,只能串行,总耗时会接近
        三者之和而不是最大值。
    """
    base, degraded, sources = await _ensure_discovery(domain_key)

    probe_targets = base.subdomains if base.subdomains else [domain_key]

    probe_result, email_report, cname_fanout = await asyncio.gather(
        probe_service.probe_liveness_with_bodies(probe_targets, settings),
        audit_service.audit_email_security_full(domain_key, base.subdomains, settings),
        takeover_service.fanout_cname(domain_key, base.subdomains, settings),
    )
    live_assets, probe_bodies, probe_complete = probe_result

    takeover_report = takeover_service.assemble_takeover(
        cname_fanout, probe_bodies, settings
    )

    data = UltraScanData(
        total_found=base.total_found,
        subdomains=base.subdomains,
        total_assets=base.total_assets,
        assets=base.assets,
        dns=base.dns,
        total_live=len(live_assets),
        live_assets=live_assets,
        probe_complete=probe_complete,
        probe_note=_probe_coverage_note(len(probe_targets), probe_complete),
        email_audit=email_report,
        takeover=takeover_report,
    )
    data.risk = risk_service.assess(data)
    await _store_cached(_ultra_key(domain_key), (data, degraded, sources), degraded)
    return data, degraded, sources


def _runner_for(plan_norm: str):
    """计划名 → 管线入口。"""
    if plan_norm == "pro":
        return _run_pro_discovery
    if plan_norm == "ultra":
        return _run_ultra_discovery
    return _run_discovery


async def _run_plan(domain_key: str, plan_norm: str):
    """带 single-flight 的完整管线执行。同键并发只跑一次。"""
    sf = _pipeline_sf.get(plan_norm, _pipeline_sf["basic"])
    return await sf.do(domain_key, lambda: _runner_for(plan_norm)(domain_key))


async def _background_refresh(domain_key: str, plan: str = "basic") -> None:
    """stale 命中时后台静默重拉;失败也不影响已返回给用户的旧数据。"""
    try:
        await _run_plan(domain_key, plan)
    except Exception:  # noqa: BLE001 - 后台任务,旧数据仍在,只记日志不外溢
        logger.warning(
            "background refresh failed for %s (plan=%s); serving stale cache",
            domain_key,
            plan,
            exc_info=True,
        )
    finally:
        _refreshing.discard(_plan_cache_key(domain_key, plan))


# ==================== 同步端点(/debug/scan)的缓存分级 ====================


def _info(
    domain: str,
    plan_norm: str,
    *,
    cached: bool,
    degraded: bool,
    sources: Any,
    stale: bool = False,
    elapsed_ms: Optional[int] = None,
) -> ScanInfo:
    return ScanInfo(
        domain=domain,
        plan=_plan_display(plan_norm),
        timestamp=utcnow_iso(),
        cached=cached,
        degraded=degraded,
        stale=stale,
        sources=sources or [],
        version=settings.VERSION,
        elapsed_ms=elapsed_ms,
    )


async def _serve_cached(
    domain_key: str,
    plan_norm: str,
    response_cls: Any,
    label: str,
) -> Any:
    """Basic / Pro / Ultra 共用的 stale-while-revalidate 读路径。

    三种计划的缓存语义完全一致,只有"跑哪条管线"和"包哪个响应模型"不同。把它们
    复制三遍是 bug 温床(以前就出现过 Pro/Ultra 两处兜底逻辑逐渐漂移)。这里收成一份。
    """
    started = time.perf_counter()
    key = _plan_cache_key(domain_key, plan_norm)
    state, cached = await cache.get_with_state(key)

    if state == cache.FRESH and cached is not None:
        data, degraded, sources = cached
        return response_cls(
            info=_info(
                domain_key, plan_norm, cached=True, degraded=degraded, sources=sources,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            ),
            data=data,
        )

    if state == cache.STALE and cached is not None:
        data, degraded, sources = cached
        # 后台刷新去重:同一个键同时只允许一个刷新任务
        if key not in _refreshing:
            _refreshing.add(key)
            _spawn(_background_refresh(domain_key, plan_norm))
        return response_cls(
            info=_info(
                domain_key, plan_norm, cached=True, degraded=degraded, sources=sources,
                stale=True, elapsed_ms=int((time.perf_counter() - started) * 1000),
            ),
            data=data,
        )

    # --- MISS:同步现拉 ---
    try:
        data, degraded, sources = await _run_plan(domain_key, plan_norm)
    except Exception as exc:  # noqa: BLE001 - 兜底,避免 500 泄漏内部细节
        stale_cached = await cache.peek_stale(key)
        if stale_cached is not None:
            s_data, s_degraded, s_sources = stale_cached
            return response_cls(
                info=_info(
                    domain_key, plan_norm, cached=True, degraded=s_degraded,
                    sources=s_sources, stale=True,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                ),
                data=s_data,
            )
        logger.warning("%s pipeline failed for %s", label, domain_key, exc_info=True)
        return _error(502, f"{label} 发现/检测调用失败: {exc}")

    # 现拉成功但骨干源全挂:优先返回略旧但完整的 stale 快照
    if degraded:
        stale_cached = await cache.peek_stale(key)
        if stale_cached is not None:
            s_data, s_degraded, s_sources = stale_cached
            return response_cls(
                info=_info(
                    domain_key, plan_norm, cached=True, degraded=s_degraded,
                    sources=s_sources, stale=True,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                ),
                data=s_data,
            )

    return response_cls(
        info=_info(
            domain_key, plan_norm, cached=False, degraded=degraded, sources=sources,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        ),
        data=data,
    )


# ==================== 结果落盘 ====================


def build_payload(
    *,
    job_id: str,
    domain_key: str,
    plan_norm: str,
    result: Any,
    degraded: Optional[bool],
    sources: Any,
    created_at: float,
    finished_at: Optional[float] = None,
    from_cache: bool = False,
    elapsed_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """把一次扫描的产物组装成自包含 dict。

    落盘 / 导出 / diff 全都用这一份,避免三处各写一遍字段顺序与命名。
    CLI 没有 Job 对象时也直接调它。
    """
    return {
        "job_id": job_id,
        "domain": domain_key,
        "plan": _plan_display(plan_norm),
        "plan_key": plan_norm,
        "status": COMPLETED,
        "created_at": _epoch_to_iso(created_at),
        "finished_at": _epoch_to_iso(finished_at),
        "elapsed_ms": elapsed_ms,
        "from_cache": from_cache,
        "degraded": degraded,
        "sources": [
            s.model_dump() if hasattr(s, "model_dump") else dict(s) for s in (sources or [])
        ],
        "result": result.model_dump() if result is not None else None,
    }


def _job_payload(job: Job) -> Dict[str, Any]:
    """Job → 自包含 dict(落盘、导出、diff 共用)。"""
    return build_payload(
        job_id=job.job_id,
        domain_key=job.domain_key,
        plan_norm=job.plan,
        result=job.result,
        degraded=job.degraded,
        sources=job.sources,
        created_at=job.created_at,
        finished_at=job.finished_at,
        from_cache=job.from_cache,
        elapsed_ms=job.elapsed_ms,
    )


# 落盘文件名里允许出现的字符:域名只可能是这些,其余一律替换掉。
_UNSAFE_FILENAME_CHARS = re.compile(r"[^a-z0-9.-]")


def _write_text_atomic(out_dir: Path, fname: str, text: str) -> Path:
    """原子写:先写临时文件再 rename。中途崩溃/断电不会留下半个 JSON。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = (out_dir / fname).resolve()
    # 兜底:解析后的路径必须仍在 out_dir 之内(防 `..` / 盘符 / 绝对路径逃逸)
    if path.parent != out_dir.resolve():
        raise ValueError(f"refusing to write outside {out_dir!r}: {path!r}")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


async def _save_result(job: Job) -> None:
    """把实际扫描完成的结果落盘到 res/ 目录。

    两处关键设计:
      1) **放到线程里**。一次千级子域的 Ultra 结果有数 MB,JSON 序列化 + 磁盘写入放在
         事件循环上会卡住所有并发请求几十到上百毫秒 —— 这段时间里所有轮询都在排队。
      2) **文件名纵深防御**。domain 是攻击者可控值,API 层已校验,这里再做一次字符消毒
         + 目录包含性校验。文件名是外部输入进入文件系统的最后一跳。
    """
    try:
        payload = _job_payload(job)
        out_dir = Path(settings.RESULT_DIR)
        ts = datetime.fromtimestamp(job.finished_at or time.time()).strftime("%Y%m%d_%H%M%S")
        safe_domain = _UNSAFE_FILENAME_CHARS.sub("_", job.domain_key)[:100] or "domain"
        safe_plan = _UNSAFE_FILENAME_CHARS.sub("_", job.plan)[:20] or "plan"
        fname = f"{safe_domain}_{safe_plan}_{ts}_{job.job_id[:8]}.json"

        text = await asyncio.to_thread(
            lambda: json.dumps(payload, ensure_ascii=False, indent=2)
        )
        size = len(text.encode("utf-8"))
        if size > settings.RESULT_MAX_BYTES:
            logger.warning(
                "job %s result is %d bytes (> RESULT_MAX_BYTES=%d); not writing to disk",
                job.job_id,
                size,
                settings.RESULT_MAX_BYTES,
            )
            return
        path = await asyncio.to_thread(_write_text_atomic, out_dir, fname, text)
        job.saved_path = str(path)
    except Exception:  # noqa: BLE001 - 落盘失败不阻塞扫描结果,但要留痕
        logger.warning("failed to save result for job %s", job.job_id, exc_info=True)


# ==================== job 执行 ====================


async def _finalize_completed(job: Job) -> None:
    """扫描完成后的收尾:落盘 + 写历史快照。两件事都不允许影响 job 的成败。"""
    await _save_result(job)

    if job.result is None:
        return
    try:
        risk = getattr(job.result, "risk", None)
        snapshot = diff_service.build_snapshot(
            domain=job.domain_key,
            plan=job.plan,
            job_id=job.job_id,
            finished_at=job.finished_at or time.time(),
            result=job.result,
            risk_score=int(getattr(risk, "risk_score", 0) or 0),
            degraded=bool(job.degraded),
        )
        await history.record(snapshot)
    except Exception:  # noqa: BLE001 - 历史是增强,不能影响主流程
        logger.warning("failed to record history for job %s", job.job_id, exc_info=True)


async def _execute_job(job: Job) -> None:
    """后台跑一次扫描:复用 _run_plan,零重写检测逻辑。

    job 是可变对象,这里直接改字段;无论成败都落 finished_at 并释放去重索引,
    让同 (domain, plan) 的下一次 POST 能开新任务。

    一个刻意的顺序:**先落盘 + 写历史,最后才把状态翻成 completed**。
    反过来(状态先 completed,副作用后做)会产生一个真实竞态 —— 客户端轮询到
    completed、立刻去读 saved_path,拿到的却是 None,再刷新一次又出现了。
    """

    job.status = RUNNING
    job.started_at = time.time()
    started = job.started_at
    try:
        job.result, job.degraded, job.sources = await _run_plan(job.domain_key, job.plan)
        job.finished_at = time.time()
        await _finalize_completed(job)
        job.status = COMPLETED
        METRICS.inc("reconifyx_scans_total", plan=job.plan)
    except Exception as exc:  # noqa: BLE001 - 失败落到 failed 状态,GET 时透出
        job.error = str(exc)
        job.status = FAILED
        METRICS.inc("reconifyx_scan_failures_total", plan=job.plan)
        logger.warning("scan job %s failed", job.job_id, exc_info=True)
    finally:
        if job.finished_at is None:
            job.finished_at = time.time()
        METRICS.inc("reconifyx_scan_seconds_sum", job.finished_at - started)
        await job_store.release_active(job.domain_key, job.plan, job.job_id)


async def _create_job(domain_key: str, plan_norm: str) -> ScanJobAccepted:
    """提交一次扫描。三级决策:
      1) 缓存 FRESH 命中 → 秒回 completed job(result 来自缓存),不打上游;
      2) 同 (domain, plan) 已有未完成任务 → 复用其 job_id,防重复打爆上游;
      3) 否则开后台 asyncio 任务跑检测,客户端轮询 GET /scan/{job_id}。
    """
    ckey = _plan_cache_key(domain_key, plan_norm)
    state, cached = await cache.get_with_state(ckey)
    if state == cache.FRESH and cached is not None:
        data, degraded, sources = cached
        now = time.time()
        job = Job(
            job_id=uuid4().hex,
            domain_key=domain_key,
            plan=plan_norm,
            status=COMPLETED,
            created_at=now,
            started_at=now,
            finished_at=now,
            from_cache=True,
            result=data,
            degraded=degraded,
            sources=sources,
        )
        await job_store.add(job)
        return ScanJobAccepted(
            job_id=job.job_id, status=COMPLETED, domain=domain_key, plan=plan_norm
        )

    job = Job(
        job_id=uuid4().hex,
        domain_key=domain_key,
        plan=plan_norm,
        status=QUEUED,
        created_at=time.time(),
    )
    # 原子占坑:判断与登记在同一次加锁内完成,不给"两个请求同时判定为空"留窗口
    existing = await job_store.reserve_active(domain_key, plan_norm, job.job_id)
    if existing:
        return ScanJobAccepted(
            job_id=existing, status=QUEUED, domain=domain_key, plan=plan_norm
        )

    await job_store.add(job)
    _spawn(_execute_job(job))
    return ScanJobAccepted(job_id=job.job_id, status=QUEUED, domain=domain_key, plan=plan_norm)


# ==================== 静态资源 ====================


def _static_dir() -> Path:
    """WebUI 静态目录。

    PyInstaller 把 ``app/static`` 解包到 ``sys._MEIPASS``;普通 Python 运行时文件就在
    本模块旁边。同一段逻辑同时支持源码运行与 ReconifyX.exe。
    """
    import sys

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "app" / "static"
    return Path(__file__).parent / "static"


STATIC_DIR = _static_dir()


# ==================== 应用 ====================


@asynccontextmanager
async def lifespan(_app: FastAPI):
    quiet_windows_reset_noise()
    await history.init()
    METRICS.gauge(
        "reconifyx_build_info", 1, version=settings.VERSION, project=settings.PROJECT_NAME
    )
    logger.info("%s v%s ready", settings.PROJECT_NAME, settings.VERSION)
    try:
        yield
    finally:
        await history.close()


app = FastAPI(
    title=f"{settings.PROJECT_NAME} API",
    description=(
        "攻击面管理 · 发现引擎 (Basic / Pro / Ultra)。"
        "所有端点默认只服务本机;对外暴露时请设置 API_KEY。"
    ),
    version=settings.VERSION,
    lifespan=lifespan,
)


@app.middleware("http")
async def _guard_middleware(request: Request, call_next):
    """鉴权 + 限流 + 安全响应头 + 访问计时的统一入口。

    放在中间件里而不是逐端点 Depends:保护的是"路径族",新增端点时不会漏。
    """
    path = request.url.path
    started = time.perf_counter()

    if requires_guard(path):
        if not api_key_ok(settings.API_KEY, request.headers.get("x-api-key")):
            METRICS.inc("reconifyx_auth_failed_total")
            # RFC 7235:401 必须带 WWW-Authenticate,否则客户端不知道该用哪种
            # 方案重试。这里用自定义 scheme,和 X-API-Key 头对上。
            return _error(
                401,
                "missing or invalid X-API-Key",
                headers={"WWW-Authenticate": 'ApiKey realm="reconifyx", header="X-API-Key"'},
            )
        client = request.client.host if request.client else "unknown"
        if not _limiter.allow(client):
            METRICS.inc("reconifyx_rate_limited_total")
            response = _error(429, "rate limit exceeded, slow down")
            response.headers["Retry-After"] = str(_limiter.retry_after_seconds(client))
            return response

    response = await call_next(request)

    # 安全响应头:本服务只提供 JSON + 一个自带资源的页面,可以配得很紧
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()"
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self'; script-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    )
    # API 结果里含目标域名与资产信息,不该被浏览器/中间代理缓存
    response.headers.setdefault("Cache-Control", "no-store")

    observe_request(path, response.status_code, time.perf_counter() - started)
    return response


# ---------------- 页面与静态资源 ----------------


def _asset(name: str, media_type: str) -> Response:
    path = STATIC_DIR / name
    if not path.is_file():
        return _error(500, f"UI asset missing: {name}")
    return FileResponse(path, media_type=media_type)


@app.get("/", include_in_schema=False)
async def index():
    """本地 WebUI:选计划 + 传主域名,前端轮询异步扫描并展示结果。"""
    return _asset("index.html", "text/html; charset=utf-8")


@app.get("/app.js", include_in_schema=False)
async def ui_script():
    return _asset("app.js", "application/javascript; charset=utf-8")


@app.get("/style.css", include_in_schema=False)
async def ui_style():
    return _asset("style.css", "text/css; charset=utf-8")


@app.get("/favicon.svg", include_in_schema=False)
async def favicon():
    return _asset("favicon.svg", "image/svg+xml")


# ---------------- 元信息 ----------------


def _api_meta() -> ApiMeta:
    return ApiMeta(
        name=settings.PROJECT_NAME,
        version=settings.VERSION,
        auth_required=bool(settings.API_KEY),
        rate_limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
        history_enabled=bool(settings.HISTORY_ENABLED),
        tls_enabled=bool(settings.PROBE_TLS_ENABLED),
        plans=[
            PlanCapability(
                name=settings.PLAN_BASIC,
                title="发现",
                description="被动子域名发现 + DNS 情报",
                features=[
                    "证书透明度(crt.sh + CertSpotter 互为热备)",
                    "FOFA 增强(IP / 端口 / 指纹,可选)",
                    "A / AAAA / NS / MX / TXT / CAA / SOA",
                ],
            ),
            PlanCapability(
                name=settings.PLAN_PRO,
                title="发现 + 探活审计",
                description="在 Basic 之上做高并发 HTTP 探活与全域邮件审计",
                features=[
                    "HTTP 探活(状态码 / 标题 / Server)",
                    "TLS 证书情报(有效期 / 信任链)",
                    "安全响应头评估(HSTS / CSP / Cookie)",
                    "SPF + DMARC 全域邮件伪造审计",
                ],
            ),
            PlanCapability(
                name=settings.PLAN_ULTRA,
                title="发现 + 探活审计 + 接管检测",
                description="在 Pro 之上做子域名接管检测(CNAME × 正文指纹双信号)",
                features=[
                    "CNAME 链解析与托管商识别",
                    "悬空页面指纹交叉验证",
                    "High / Low 置信度分级,严控误报",
                ],
            ),
        ],
        limits={
            "probe_targets": settings.PRO_MAX_PROBE_TARGETS,
            "probe_concurrency": settings.PROBE_CONCURRENCY_CAP,
            "audit_targets": settings.PRO_MAX_AUDIT_TARGETS,
            "takeover_targets": settings.ULTRA_MAX_TAKEOVER_TARGETS,
            "tls_targets": settings.PROBE_TLS_MAX_TARGETS,
            "batch_domains": settings.BATCH_MAX_DOMAINS,
            "job_ttl_seconds": settings.JOB_TTL_SECONDS,
            "cache_ttl_seconds": settings.CACHE_TTL_SECONDS,
            "cache_stale_max_seconds": settings.CACHE_STALE_MAX_SECONDS,
        },
    )


@app.get("/api/meta", response_model=ApiMeta, tags=["meta"])
async def api_meta():
    """给 WebUI / CLI 的能力与限额元信息。前端据此渲染计划卡片与鉴权输入框。"""
    return _api_meta()


# ---------------- 健康检查与指标 ----------------


@app.get("/healthz", include_in_schema=False)
async def healthz():
    """存活探针:只证明进程还能响应,不触碰任何外部依赖。"""
    return {"status": "ok", "version": settings.VERSION}


@app.get("/readyz", include_in_schema=False)
async def readyz():
    """就绪探针:额外检查历史库是否可用(不可用时服务仍可扫描,只是没有 diff)。"""
    return {
        "status": "ok",
        "version": settings.VERSION,
        "history": bool(history.enabled),
        "auth_required": bool(settings.API_KEY),
    }


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint():
    """Prometheus 文本格式指标。高频拉取,因此不计入限流。"""
    jobs = await job_store.stats()
    hist = await history.stats()
    METRICS.gauge("reconifyx_jobs", jobs["inflight"], state="inflight")
    METRICS.gauge("reconifyx_jobs", jobs["total"], state="total")
    METRICS.gauge("reconifyx_cache_entries", await cache.size())
    for state, value in cache.stats().items():
        METRICS.inc("reconifyx_cache_events_total", value, outcome=state)
    for phase, value in _discovery_sf.stats().items():
        METRICS.gauge("reconifyx_singleflight_total", value, scope="discovery", phase=phase)
    METRICS.gauge("reconifyx_history_scans", hist.get("scans", 0))
    METRICS.gauge("reconifyx_history_domains", hist.get("domains", 0))
    return Response(content=render_text(), media_type="text/plain; version=0.0.4; charset=utf-8")


# ---------------- 扫描:异步 job ----------------


@app.post(
    "/scan",
    response_model=ScanJobAccepted,
    status_code=202,
    tags=["scan"],
    responses={400: {"model": PlanNotAvailableResponse}},
)
async def create_scan(body: ScanJobCreate):
    """提交一次异步扫描,毫秒级返回 job_id。

    domain 已由 ScanJobCreate 归一化 + 校验为合法 FQDN(它会进入缓存键与结果文件名)。
    """
    plan_norm = body.plan.strip().lower()

    # 未知计划兜底:及时返回 400 + 可用计划清单,而不是给出一个永远轮询不到结果的 job
    if plan_norm not in _valid_plans():
        return JSONResponse(
            status_code=400,
            content=PlanNotAvailableResponse(
                requested_plan=body.plan,
                message=f"Unsupported plan '{body.plan}'. Available: Basic / Pro / Ultra.",
            ).model_dump(),
        )

    return await _create_job(body.domain, plan_norm)


@app.post(
    "/scan/batch",
    response_model=BatchScanAccepted,
    status_code=202,
    tags=["scan"],
)
async def create_batch_scan(body: BatchScanCreate):
    """批量提交:同一个计划 + 多个域名。

    语义是"尽量都排上":每个域名独立成一个 job(独立轮询、独立去重),不会因为其中
    一个域名缓存命中就整批秒回。上限由 ``BATCH_MAX_DOMAINS`` 控制。
    """
    plan_norm = body.plan.strip().lower()
    if plan_norm not in _valid_plans():
        return JSONResponse(
            status_code=400,
            content=PlanNotAvailableResponse(
                requested_plan=body.plan,
                message=f"Unsupported plan '{body.plan}'. Available: Basic / Pro / Ultra.",
            ).model_dump(),
        )
    if len(body.domains) > settings.BATCH_MAX_DOMAINS:
        return _error(
            400,
            f"too many domains ({len(body.domains)}); limit is {settings.BATCH_MAX_DOMAINS}",
        )

    jobs = [await _create_job(domain, plan_norm) for domain in body.domains]
    return BatchScanAccepted(plan=plan_norm, jobs=jobs)


@app.get("/scan/{job_id}", response_model=ScanJobStatus, tags=["scan"])
async def get_scan(job_id: str):
    """轮询任务状态。completed 时携带完整结果;过期/不存在返 404。"""
    job = await job_store.get(job_id)  # 内部懒清理:过期即删并返 None
    if job is None:
        return _error(404, "job not found or expired")
    return ScanJobStatus(
        job_id=job.job_id,
        domain=job.domain_key,
        plan=_plan_display(job.plan),
        status=job.status,
        created_at=_epoch_to_iso(job.created_at) or "",
        finished_at=_epoch_to_iso(job.finished_at),
        from_cache=job.from_cache,
        degraded=job.degraded,
        sources=job.sources if job.sources is not None else [],
        error=job.error,
        saved_path=job.saved_path,
        elapsed_ms=job.elapsed_ms,
        result=job.result,
    )


async def _completed_job(job_id: str):
    """取一个已完成且有结果的 job;失败时返回 (None, 错误响应)。"""
    job = await job_store.get(job_id)
    if job is None:
        return None, _error(404, "job not found or expired (results are kept for a limited time)")
    if job.status == FAILED:
        return None, _error(409, f"job failed: {job.error or 'unknown error'}")
    if job.status != COMPLETED or job.result is None:
        return None, _error(409, f"job is not finished yet (status={job.status})")
    return job, None


@app.get("/scan/{job_id}/export", tags=["scan"])
async def export_scan(job_id: str, format: str = Query("json", description="json / csv / md")):
    """导出结果:json(完整快照)/ csv(一行一个主机)/ md(人读报告)。"""
    fmt = format.strip().lower()
    if fmt not in export_service.EXPORT_FORMATS:
        return _error(400, f"unsupported format '{format}'; use json / csv / md")

    job, err = await _completed_job(job_id)
    if err is not None:
        return err

    payload = _job_payload(job)
    content, media_type, _ext = await asyncio.to_thread(
        export_service.render, fmt, payload
    )
    filename = export_service.suggested_filename(payload, fmt)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/scan/{job_id}/diff", response_model=ScanDiff, tags=["scan"])
async def scan_diff(job_id: str):
    """本次结果与同域名上一次扫描的差异(新增/消失的子域、URL、接管信号、IP)。"""
    job, err = await _completed_job(job_id)
    if err is not None:
        return err

    risk = getattr(job.result, "risk", None)
    current = diff_service.build_snapshot(
        domain=job.domain_key,
        plan=job.plan,
        job_id=job.job_id,
        finished_at=job.finished_at or time.time(),
        result=job.result,
        risk_score=int(getattr(risk, "risk_score", 0) or 0),
        degraded=bool(job.degraded),
    )
    previous = await history.previous(job.domain_key, job.plan, job.job_id)
    return diff_service.compute_diff(job.domain_key, previous, current)


# ---------------- 历史 / DNS ----------------


@app.get("/history", tags=["history"])
async def list_history(
    domain: str = Query(..., description="主域名"),
    limit: int = Query(20, ge=1, le=200, description="返回条数"),
):
    """某域名的历史扫描列表(新的在前)。用于看风险分随时间的变化。"""
    try:
        domain_key = normalize_domain(domain)
    except ValueError as exc:
        return _error(400, str(exc))

    rows = await history.recent(domain_key, limit)
    entries = [
        HistoryEntry(
            job_id=str(row.get("job_id") or ""),
            plan=_plan_display(str(row.get("plan") or "basic")),
            finished_at=_epoch_to_iso(row.get("finished_at")) or "",
            risk_score=int(row.get("risk_score") or 0),
            degraded=bool(row.get("degraded")),
            total_found=int(row.get("total_found") or 0),
            total_live=int(row.get("total_live") or 0),
        )
        for row in rows
    ]
    return {"status": "success", "domain": domain_key, "count": len(entries), "entries": entries}


@app.get("/dns", response_model=DnsIntel, tags=["dns"])
async def dns_lookup(domain: str = Query(..., description="主域名")):
    """只查 DNS 情报(A/AAAA/NS/MX/TXT/CAA/SOA),不跑子域名发现。

    这是"轻量一眼":判断域名托管在哪、有没有 CAA、邮件记录齐不齐,
    几百毫秒就能回答,不需要等整个扫描。
    """
    try:
        domain_key = normalize_domain(domain)
    except ValueError as exc:
        return _error(400, str(exc))

    key = f"dns::{domain_key}"
    state, cached = await cache.get_with_state(key)
    if state == cache.FRESH and cached is not None:
        return cached

    intel = await dns_service.collect(domain_key, settings)
    # DNS 记录变化远没子域名快,单独用一个 5 分钟窗口,避免把 namespace 挤满
    if intel is not None:
        await cache.set(key, intel, fresh_ttl=300)
        return intel
    return _error(503, "DNS intel is disabled (DNS_INTEL_ENABLED=false)")


# ---------------- 同步调试端点 ----------------


@app.get(
    "/debug/scan",
    # 不锁死 response_model:同一端点按 plan 返回 ScanResponse / ProScanResponse /
    # UltraScanResponse 三种结构。锁死会把 Pro 的 live_assets/email_audit 裁掉。
    responses={200: {"model": ScanResponse}, 502: {}},
    tags=["debug"],
)
async def scan(
    domain: str = Query(..., min_length=3, description="待测绘的主域名,如 example.com"),
    plan: str = Query("Basic", description="订阅计划:Basic / Pro / Ultra"),
):
    """同步扫描(阻塞至完成)。适合脚本与调试;生产请用 POST /scan + 轮询。"""
    plan_norm = plan.strip().lower()

    # 同步调试端点也要过同一套域名校验:它同样会把 domain 写进缓存键。
    try:
        domain_key = normalize_domain(domain)
    except ValueError as exc:
        return _error(400, str(exc))

    # 未知计划:与 POST /scan 保持一致返回 400(以前这里返回 200,前端会当成成功)
    if plan_norm not in _valid_plans():
        return JSONResponse(
            status_code=400,
            content=PlanNotAvailableResponse(
                requested_plan=plan,
                message=f"Unsupported plan '{plan}'. Available: Basic / Pro / Ultra.",
            ).model_dump(),
        )

    if plan_norm == "pro":
        return await _serve_cached(domain_key, plan_norm, ProScanResponse, "Pro")
    if plan_norm == "ultra":
        return await _serve_cached(domain_key, plan_norm, UltraScanResponse, "Ultra")
    return await _serve_cached(domain_key, plan_norm, ScanResponse, "Basic")


# ---------------- 编程入口(CLI / 库调用)----------------


async def scan_domain(domain: str, plan: str = "Basic"):
    """直接跑一次完整管线,不经过 HTTP 与 job 编排。

    供 CLI 与把 ReconifyX 当库用的脚本调用。返回
    ``(domain_key, plan_norm, data, degraded, sources)``。

    与 API 路径共享同一条管线函数,所以缓存、single-flight、降级语义完全一致:
    CLI 跑过的域名,紧接着用 API 查会直接命中缓存。
    """
    domain_key = normalize_domain(domain)
    plan_norm = (plan or "basic").strip().lower()
    if plan_norm not in _valid_plans():
        raise ValueError(
            f"unsupported plan {plan!r}; use one of {', '.join(_valid_plans())}"
        )
    # CLI 路径不经过 FastAPI 的 lifespan,这里自己装一次(幂等)
    quiet_windows_reset_noise()
    data, degraded, sources = await _run_plan(domain_key, plan_norm)
    return domain_key, plan_norm, data, degraded, sources


@app.get("/api/plans", include_in_schema=False)
async def plans_alias():
    """兼容别名:部分脚本先探测能力再提交扫描。"""
    return _api_meta()


# 让 `python -m app.main` 也能直接起服务(打包后的 exe 走 launcher.py)
if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host=settings.HOST, port=settings.PORT, log_level=settings.LOG_LEVEL)


# 显式导出,方便测试与外部脚本 `from app.main import app`
__all__ = [
    "app",
    "build_payload",
    "history",
    "job_store",
    "scan_domain",
    "settings",
]
