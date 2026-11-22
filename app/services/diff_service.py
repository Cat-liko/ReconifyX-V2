"""扫描差异对比 —— 回答"这一次比上一次多了/少了什么"。

输入是两份"快照"(见 ``app/core/history.py`` 里写入的结构),输出的差异只做集合运算:

  新增子域名 / 消失子域名 / 新上线 URL / 不再存活 URL / 新出现接管信号 / 新增 IP

一条重要的产品决定:没有历史基线时 ``baseline=True``,所有 ``new_*`` 保持为空。
把"第一次看到的全部"渲染成"新增"是这类工具最常见的误导 —— 用户会以为一夜之间
冒出了几百个子域。
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from app.schemas.scan import ScanDiff

#: 单个清单字段最多返回多少条差异(超大域的变化列表本身也是噪音)
_MAX_ITEMS = 500


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).replace(
        tzinfo=None
    ).isoformat() + "Z"


def _as_set(snapshot: Optional[Dict[str, Any]], field: str) -> Set[str]:
    if not snapshot:
        return set()
    value = snapshot.get(field)
    if not isinstance(value, list):
        return set()
    return {str(v) for v in value if v}


def _clamp(values: Set[str]) -> List[str]:
    return sorted(values)[:_MAX_ITEMS]


def compute_diff(
    domain: str, previous: Optional[Dict[str, Any]], current: Dict[str, Any]
) -> ScanDiff:
    """对比两次快照。``current`` 是本次快照,``previous`` 是上一次(可缺省)。"""
    if not previous:
        return ScanDiff(domain=domain, baseline=True)

    cur_sub = _as_set(current, "subdomains")
    cur_live = _as_set(current, "live_urls")
    cur_takeover = _as_set(current, "takeover_domains")
    cur_ips = _as_set(current, "ip_assets")

    prev_sub = _as_set(previous, "subdomains")
    prev_live = _as_set(previous, "live_urls")
    prev_takeover = _as_set(previous, "takeover_domains")
    prev_ips = _as_set(previous, "ip_assets")

    return ScanDiff(
        domain=domain,
        baseline=False,
        compared_to_job_id=previous.get("job_id") or None,
        compared_at=_iso(previous.get("finished_at")),
        new_subdomains=_clamp(cur_sub - prev_sub),
        removed_subdomains=_clamp(prev_sub - cur_sub),
        new_live_urls=_clamp(cur_live - prev_live),
        removed_live_urls=_clamp(prev_live - cur_live),
        # 接管只看"新出现":消失的接管信号不值得报警(可能只是 DNS 被清掉了)
        new_takeover_domains=_clamp(cur_takeover - prev_takeover),
        new_ip_assets=_clamp(cur_ips - prev_ips),
    )


def build_snapshot(
    *,
    domain: str,
    plan: str,
    job_id: str,
    finished_at: float,
    result: Any,
    risk_score: int,
    degraded: bool,
) -> Dict[str, Any]:
    """把一次扫描结果压成差异对比所需的快照。"""
    subdomains = list(getattr(result, "subdomains", []) or [])
    live_urls = [a.url for a in (getattr(result, "live_assets", []) or []) if a.url]
    ip_assets = [a.ip for a in (getattr(result, "assets", []) or []) if a.ip]

    takeover_domains: List[str] = []
    takeover = getattr(result, "takeover", None)
    if takeover is not None:
        takeover_domains = [f.domain for f in (takeover.findings or []) if f.domain]

    return {
        "domain": domain,
        "plan": plan,
        "job_id": job_id,
        "finished_at": finished_at,
        "risk_score": risk_score,
        "degraded": bool(degraded),
        "total_found": int(getattr(result, "total_found", 0) or 0),
        "total_live": int(getattr(result, "total_live", 0) or 0),
        "total_assets": int(getattr(result, "total_assets", 0) or 0),
        "subdomains": subdomains,
        "live_urls": live_urls,
        "takeover_domains": takeover_domains,
        "ip_assets": ip_assets,
    }
