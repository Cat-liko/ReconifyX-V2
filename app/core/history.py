"""扫描历史(SQLite)—— 支撑"这一次比上一次多了什么"的差异对比。

为什么必须有它
--------------
ASM 的价值不在"列一次清单",而在**变化**:新冒出来的子域、突然开始解析的域名、昨天
还活着今天掉线的服务、新出现的可接管记录。只看单次结果,这些全都是噪声;有历史基线,
它们才是信号。所以每完成一次真实扫描,我们把一份"快照"写进本地 SQLite。

为什么是 SQLite
---------------
标准库自带、零运维、单文件、并发写有锁。对"本地自部署 + 单进程"这个定位,它比
引入外部存储更合适。写入放在线程里(async to_thread),绝不阻塞事件循环 ——
一次 1000 子域的扫描快照有几百 KB,JSON 序列化 + 磁盘 fsync 放在 loop 上会卡住
所有并发请求。

设计取舍
--------
- 表只存"快照",不存关系型结构:查询模式只有两种(取某域最近的 N 次、取上一次),
  为此拆十几张表毫无收益。
- 快照里存**三个关键集合**(子域名 / 存活 URL / 疑似接管域名)而不是完整 result。
  对比只需要集合差异;完整结果在 ``res/`` 的 JSON 里,也可以通过 job 拿。
- 每次写入后按 ``HISTORY_MAX_SCANS_PER_DOMAIN`` 裁剪,数据库不会无限增长。
- 所有失败都被吞掉并记日志:历史是"增强",它挂了不能影响扫描本身。
"""

import asyncio
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("reconifyx.history")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT    NOT NULL,
    plan         TEXT    NOT NULL,
    job_id       TEXT    NOT NULL,
    finished_at  REAL    NOT NULL,
    risk_score   INTEGER NOT NULL DEFAULT 0,
    degraded     INTEGER NOT NULL DEFAULT 0,
    total_found  INTEGER NOT NULL DEFAULT 0,
    total_live   INTEGER NOT NULL DEFAULT 0,
    snapshot     TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_domain
    ON scans (domain, plan, finished_at DESC);
"""

# 列表接口返回的行(不含体积最大的 snapshot 字段)
_LIGHT_COLUMNS = (
    "job_id, plan, finished_at, risk_score, degraded, total_found, total_live"
)

# 快照里参与差异对比的集合字段
SNAPSHOT_SET_FIELDS = ("subdomains", "live_urls", "takeover_domains", "ip_assets")


class HistoryStore:
    """扫描历史仓库。单连接 + threading.Lock,所有 IO 都丢到线程里跑。"""

    def __init__(self, path: str, enabled: bool, max_per_domain: int):
        self._path = Path(path)
        self._enabled = enabled
        self._max_per_domain = max(1, max_per_domain)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._ready = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def init(self) -> None:
        """建库建表。失败只记日志并自我停用,不阻断服务启动。"""
        if not self._enabled:
            return
        try:
            await asyncio.to_thread(self._init_sync)
            self._ready = True
            logger.info("scan history ready at %s", self._path)
        except Exception:  # noqa: BLE001 - 历史是增强,坏了不能拖死服务
            self._enabled = False
            logger.warning("scan history disabled: cannot open %s", self._path, exc_info=True)

    def _init_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        # WAL:读写不互相阻塞;NORMAL 同步在"进程崩溃最多丢最后一个事务"与性能间取平衡
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        conn.commit()
        self._conn = conn

    async def close(self) -> None:
        if self._conn is None:
            return
        try:
            await asyncio.to_thread(self._close_sync)
        except Exception:  # noqa: BLE001
            logger.warning("failed to close history db", exc_info=True)

    def _close_sync(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ---------------- 写入 ----------------

    async def record(self, snapshot: Dict[str, Any]) -> None:
        """记录一次完成的扫描。snapshot 需含 domain / plan / job_id / finished_at。"""
        if not (self._enabled and self._ready):
            return
        try:
            await asyncio.to_thread(self._record_sync, snapshot)
        except Exception:  # noqa: BLE001
            logger.warning("failed to record scan history", exc_info=True)

    def _record_sync(self, snapshot: Dict[str, Any]) -> None:
        domain = str(snapshot.get("domain") or "")
        plan = str(snapshot.get("plan") or "")
        if not domain or not plan or self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (domain, plan, job_id, finished_at, risk_score,"
                " degraded, total_found, total_live, snapshot)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    domain,
                    plan,
                    str(snapshot.get("job_id") or ""),
                    float(snapshot.get("finished_at") or time.time()),
                    int(snapshot.get("risk_score") or 0),
                    1 if snapshot.get("degraded") else 0,
                    int(snapshot.get("total_found") or 0),
                    int(snapshot.get("total_live") or 0),
                    json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            # 裁剪:只留最近 N 次(按 finished_at 倒序,含刚插入的这条)
            self._conn.execute(
                "DELETE FROM scans WHERE domain=? AND plan=? AND id NOT IN ("
                " SELECT id FROM scans WHERE domain=? AND plan=?"
                " ORDER BY finished_at DESC, id DESC LIMIT ?)",
                (domain, plan, domain, plan, self._max_per_domain),
            )
            self._conn.commit()

    # ---------------- 读取 ----------------

    async def previous(
        self, domain: str, plan: str, exclude_job_id: str
    ) -> Optional[Dict[str, Any]]:
        """取该 (domain, plan) 上一次**不同于本次**的完整快照(差异对比的基线)。"""
        if not (self._enabled and self._ready):
            return None
        try:
            return await asyncio.to_thread(
                self._previous_sync, domain, plan, exclude_job_id
            )
        except Exception:  # noqa: BLE001
            logger.warning("failed to read previous scan", exc_info=True)
            return None

    def _previous_sync(
        self, domain: str, plan: str, exclude_job_id: str
    ) -> Optional[Dict[str, Any]]:
        if self._conn is None:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT snapshot FROM scans WHERE domain=? AND plan=? AND job_id<>?"
                " ORDER BY finished_at DESC, id DESC LIMIT 1",
                (domain, plan, exclude_job_id),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    async def recent(self, domain: str, limit: int = 20) -> List[Dict[str, Any]]:
        """某域名的历史扫描列表(不含 snapshot 正文),按时间倒序。"""
        if not (self._enabled and self._ready):
            return []
        try:
            return await asyncio.to_thread(self._recent_sync, domain, limit)
        except Exception:  # noqa: BLE001
            logger.warning("failed to list scan history", exc_info=True)
            return []

    def _recent_sync(self, domain: str, limit: int) -> List[Dict[str, Any]]:
        if self._conn is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_LIGHT_COLUMNS} FROM scans WHERE domain=?"
                " ORDER BY finished_at DESC, id DESC LIMIT ?",
                (domain, max(1, min(limit, 200))),
            ).fetchall()
        return [
            {
                "job_id": r[0],
                "plan": r[1],
                "finished_at": r[2],
                "risk_score": r[3],
                "degraded": bool(r[4]),
                "total_found": r[5],
                "total_live": r[6],
            }
            for r in rows
        ]

    async def stats(self) -> Dict[str, int]:
        """给 /metrics 的基本统计。"""
        if not (self._enabled and self._ready):
            return {"scans": 0, "domains": 0}
        try:
            return await asyncio.to_thread(self._stats_sync)
        except Exception:  # noqa: BLE001
            return {"scans": 0, "domains": 0}

    def _stats_sync(self) -> Dict[str, int]:
        if self._conn is None:
            return {"scans": 0, "domains": 0}
        with self._lock:
            scans = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            domains = self._conn.execute(
                "SELECT COUNT(DISTINCT domain) FROM scans"
            ).fetchone()[0]
        return {"scans": int(scans), "domains": int(domains)}
