"""结果导出 —— 一份扫描结果,三种落地形态。

为什么要做
----------
工具在网页里看是一回事,交付给同事 / 写进工单 / 贴到周报里是另一回事。三种形态各有
明确用途,不是"多导出几个格式"的凑数:

  json  机器可读的完整快照(与 ``res/*.json`` 落盘内容逐字节一致),给脚本和 SIEM 用;
  csv   一行一个主机,给表格 / Excel / 数据透视用(带 UTF-8 BOM,Excel 直接认中文);
  md    人读报告,给工单 / PR / Wiki 用,可直接粘进任意 Markdown 渲染器。

所有渲染都是纯函数(输入就是落盘的那份 dict),因此可以在线程里跑,也不依赖 FastAPI。
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional

#: 支持的导出格式 → (MIME, 扩展名)
EXPORT_FORMATS = {
    "json": ("application/json; charset=utf-8", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "md": ("text/markdown; charset=utf-8", "md"),
}

# CSV 列顺序:先身份(host/ip),再存活证据,再风险信号,最后来源
_CSV_COLUMNS = [
    "host",
    "ip",
    "ports",
    "url",
    "status_code",
    "title",
    "server",
    "content_type",
    "tls_verified",
    "tls_subject",
    "tls_issuer",
    "tls_days_left",
    "tls_error",
    "headers_grade",
    "headers_score",
    "takeover_confidence",
    "takeover_provider",
    "email_risk",
    "in_subdomains",
    "in_assets",
]


def _md_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _limit(items: List[Any], n: int) -> List[Any]:
    return items[:n]


# ==================== JSON ====================


def render_json(payload: Dict[str, Any]) -> str:
    """完整快照。缩进 2 空格:人也能看,机器也能解析。"""
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ==================== CSV ====================


def _blank_row() -> Dict[str, Any]:
    return {col: "" for col in _CSV_COLUMNS}


def render_csv(payload: Dict[str, Any]) -> str:
    """一行一个主机。把散落在各章节的信息按 host/IP 聚到一起。"""
    result: Dict[str, Any] = payload.get("result") or {}
    rows: Dict[str, Dict[str, Any]] = {}

    def row_for(key: str) -> Dict[str, Any]:
        row = rows.get(key)
        if row is None:
            row = rows[key] = _blank_row()
        return row

    # 1) 子域名清单(即使没探活也要有一行,否则"发现了但没探"的资产会凭空消失)
    for host in result.get("subdomains") or []:
        row = row_for(str(host))
        row["host"] = host
        row["in_subdomains"] = "yes"

    # 2) IP 资产。优先挂到它的主机名那一行(表格里"一个主机一行"最好用),
    #    没有主机名的裸 IP 才单独成行 —— 否则有价值的端口/指纹会被孤立在另一行。
    for asset in result.get("assets") or []:
        ip = str(asset.get("ip") or "")
        if not ip:
            continue
        ports = ",".join(str(p) for p in (asset.get("ports") or []))
        hosts = [str(h) for h in (asset.get("hostnames") or []) if h]
        for key in hosts or [ip]:
            row = row_for(key)
            row["in_assets"] = "yes"
            if not row["ip"]:
                row["ip"] = ip
            elif ip not in row["ip"].split(","):
                # 一个主机名挂多个 IP(CDN / 双栈)时全部保留,而不是后写覆盖前写
                row["ip"] = f"{row['ip']},{ip}"
            if ports:
                row["ports"] = ports

    # 3) 存活资产
    for live in result.get("live_assets") or []:
        url = str(live.get("url") or "")
        host = str(live.get("host") or "")
        key = host or url
        if not key:
            continue
        # 同一个 host 可能同时出现在子域名清单里,按 host 合并
        row = row_for(key)
        if not row["host"]:
            row["host"] = host
        row["url"] = url
        row["status_code"] = live.get("status_code", "")
        row["title"] = live.get("title") or ""
        row["server"] = live.get("server") or ""
        row["content_type"] = live.get("content_type") or ""
        tls = live.get("tls") or {}
        if tls:
            row["tls_verified"] = tls.get("verified", "")
            row["tls_subject"] = tls.get("subject") or ""
            row["tls_issuer"] = tls.get("issuer") or ""
            if tls.get("days_left") is not None:
                row["tls_days_left"] = tls.get("days_left")
            row["tls_error"] = tls.get("verification_error") or tls.get("error") or ""
        security = live.get("security") or {}
        if security:
            row["headers_grade"] = security.get("grade", "")
            row["headers_score"] = security.get("score", "")

    # 4) 接管
    takeover = result.get("takeover") or {}
    for finding in takeover.get("findings") or []:
        host = str(finding.get("domain") or "")
        if not host:
            continue
        row = row_for(host)
        row["host"] = row["host"] or host
        row["takeover_confidence"] = finding.get("confidence", "")
        row["takeover_provider"] = finding.get("matched_provider") or ""

    # 5) 邮件审计(子域降噪结论)
    email = result.get("email_audit") or {}
    for sub in email.get("subdomains") or []:
        host = str(sub.get("domain") or "")
        if not host:
            continue
        row = row_for(host)
        row["host"] = row["host"] or host
        row["email_risk"] = sub.get("risk_level", "")
    primary = email.get("primary") or {}
    if primary.get("domain"):
        row = row_for(str(primary["domain"]))
        row["host"] = row["host"] or primary["domain"]
        row["email_risk"] = primary.get("risk_level", "")

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for key in sorted(rows):
        writer.writerow(rows[key])
    # BOM:Excel 在 Windows 上按系统代码页打开无 BOM 的 UTF-8 会乱码
    return "\ufeff" + buf.getvalue()


# ==================== Markdown ====================


def render_markdown(payload: Dict[str, Any]) -> str:
    """人读报告。刻意限制明细条数:报告是给人"扫一眼"的,完整数据在 json/csv 里。"""
    result: Dict[str, Any] = payload.get("result") or {}
    info = payload.get("info") or {}
    domain = payload.get("domain") or info.get("domain") or "unknown"
    plan = payload.get("plan") or info.get("plan") or "?"
    lines: List[str] = []

    lines.append(f"# ReconifyX 扫描报告 — `{domain}`")
    lines.append("")
    lines.append(f"- **计划**: {plan}")
    lines.append(f"- **任务**: `{payload.get('job_id', '-')}`")
    lines.append(f"- **创建时间**: {payload.get('created_at', '-')}")
    lines.append(f"- **完成时间**: {payload.get('finished_at', '-')}")
    if payload.get("from_cache"):
        lines.append("- **数据来源**: 缓存命中(非本次新算)")
    if payload.get("degraded"):
        lines.append("- **⚠️ 数据完整性**: 骨干数据源降级,结果可能不完整")
    lines.append("")

    # ---- 概览 ----
    lines.append("## 概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    lines.append(f"| 子域名 | {result.get('total_found', 0)} |")
    lines.append(f"| IP 资产 | {result.get('total_assets', 0)} |")
    if "total_live" in result:
        lines.append(f"| 存活主机 | {result.get('total_live', 0)} |")
    takeover = result.get("takeover") or {}
    if takeover:
        lines.append(f"| 可接管子域(高危) | {takeover.get('vulnerable_count', 0)} |")
    email = result.get("email_audit") or {}
    if email:
        lines.append(f"| 可伪造邮件子域 | {email.get('spoofable_subdomains', 0)} |")
    risk = result.get("risk") or {}
    if risk:
        lines.append(f"| 风险分 | {risk.get('risk_score', 0)}/100 ({risk.get('grade', '-')}) |")
    lines.append("")

    # ---- 风险清单 ----
    items = risk.get("items") or []
    if items:
        lines.append("## 风险清单")
        lines.append("")
        lines.append("| 严重度 | 代码 | 命中数 | 示例主体 |")
        lines.append("|---|---|---|---|")
        for item in _limit(items, 20):
            lines.append(
                f"| {_md_cell(item.get('severity'))} | `{_md_cell(item.get('code'))}` "
                f"| {item.get('count', 0)} | {_md_cell(item.get('subject')) or '-'} |"
            )
        lines.append("")

    # ---- DNS ----
    dns = result.get("dns") or {}
    if dns:
        lines.append("## DNS 记录")
        lines.append("")
        lines.append("| 类型 | 值 |")
        lines.append("|---|---|")
        for rtype, key in (
            ("A", "a"),
            ("AAAA", "aaaa"),
            ("NS", "ns"),
            ("MX", "mx"),
            ("CAA", "caa"),
        ):
            for value in dns.get(key) or []:
                lines.append(f"| {rtype} | `{_md_cell(value)}` |")
        if dns.get("soa"):
            lines.append(f"| SOA | `{_md_cell(dns['soa'])}` |")
        for value in _limit(list(dns.get("txt") or []), 10):
            lines.append(f"| TXT | `{_md_cell(value)}` |"
                         )
        lines.append("")

    # ---- 接管 ----
    findings = takeover.get("findings") or []
    if findings:
        lines.append("## 子域名接管")
        lines.append("")
        lines.append(f"检测 {takeover.get('total_checked', 0)} 个子域,"
                     f"有信号 {len(findings)} 个。")
        lines.append("")
        lines.append("| 子域 | 置信度 | 托管商 | 可接管 | 状态码 |")
        lines.append("|---|---|---|---|---|")
        for f in _limit(findings, 30):
            lines.append(
                f"| `{_md_cell(f.get('domain'))}` | {_md_cell(f.get('confidence'))} "
                f"| {_md_cell(f.get('matched_provider')) or '-'} "
                f"| {'✅ 是' if f.get('is_vulnerable') else '待复核'} "
                f"| {f.get('status_code', '-') if f.get('status_code') is not None else '-'} |"
            )
        lines.append("")

    # ---- 存活资产 ----
    live = result.get("live_assets") or []
    if live:
        lines.append("## 存活资产")
        lines.append("")
        lines.append("| URL | 状态 | 标题 | Server | 证书 | 安全头 |")
        lines.append("|---|---|---|---|---|---|")
        for asset in _limit(live, 50):
            tls = asset.get("tls") or {}
            if tls.get("expired"):
                tls_txt = "已过期"
            elif tls.get("verified"):
                tls_txt = f"有效({tls.get('days_left', '?')}d)"
            elif tls.get("verification_error"):
                tls_txt = "验证失败"
            else:
                tls_txt = "-"
            security = asset.get("security") or {}
            lines.append(
                f"| `{_md_cell(asset.get('url'))}` | {asset.get('status_code', '-')} "
                f"| {_md_cell(asset.get('title')) or '-'} "
                f"| {_md_cell(asset.get('server')) or '-'} "
                f"| {tls_txt} | {security.get('grade', '-')} |"
            )
        if len(live) > 50:
            lines.append("")
            lines.append(f"*(其余 {len(live) - 50} 条见 CSV / JSON 导出)*")
        lines.append("")

    # ---- 邮件 ----
    if email:
        lines.append("## 邮件伪造风险")
        lines.append("")
        p = email.get("primary") or {}
        lines.append(
            f"- 主域 `{p.get('domain', domain)}`: **{p.get('risk_level', '-')}** "
            f"(可伪造: {'是' if p.get('is_spoofable') else '否'})"
        )
        lines.append(f"- DMARC 子域策略: {email.get('subdomain_policy') or '无'}")
        lines.append(
            f"- 子域审计: {email.get('total_subdomains_audited', 0)} 个,"
            f"其中可伪造 {email.get('spoofable_subdomains', 0)} 个"
        )
        lines.append("")
        risky = [
            s
            for s in (email.get("subdomains") or [])
            if s.get("risk_level") in ("Critical", "Warning")
        ]
        if risky:
            lines.append("| 子域 | 等级 | 自有 SPF | 自有 MX |")
            lines.append("|---|---|---|---|")
            for sub in _limit(risky, 30):
                lines.append(
                    f"| `{_md_cell(sub.get('domain'))}` | {_md_cell(sub.get('risk_level'))} "
                    f"| {'是' if sub.get('has_own_spf') else '否'} "
                    f"| {'是' if sub.get('has_own_mx') else '否'} |"
                )
            lines.append("")

    # ---- 数据源 ----
    sources = payload.get("sources") or []
    if sources:
        lines.append("## 数据源健康")
        lines.append("")
        lines.append("| 源 | 状态 | 条数 | 备注 |")
        lines.append("|---|---|---|---|")
        for src in sources:
            lines.append(
                f"| {_md_cell(src.get('name'))} | {'ok' if src.get('ok') else '失败'} "
                f"| {src.get('count', 0)} | {_md_cell(src.get('detail')) or '-'} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "由 [ReconifyX](https://github.com/Cat-liko/ReconifyX-V2) 生成。"
        "请仅对已授权的目标使用本工具。"
    )
    lines.append("")
    return "\n".join(lines)


# ==================== 分发 ====================


def render(fmt: str, payload: Dict[str, Any]) -> tuple[str, str, str]:
    """按格式渲染,返回 (内容, MIME, 扩展名)。未知格式由调用方提前拦掉。"""
    if fmt == "csv":
        return render_csv(payload), *EXPORT_FORMATS["csv"]
    if fmt == "md":
        return render_markdown(payload), *EXPORT_FORMATS["md"]
    return render_json(payload), *EXPORT_FORMATS["json"]


def suggested_filename(payload: Dict[str, Any], fmt: str) -> str:
    """``example.com_Ultra_20260101_120000.json`` 这种稳定、可排序的名字。"""
    domain = str(payload.get("domain") or "result")
    plan = str(payload.get("plan") or "")
    stamp: Optional[str] = None
    finished = payload.get("finished_at") or payload.get("created_at")
    if isinstance(finished, str) and len(finished) >= 19:
        stamp = (
            finished[:19]
            .replace("-", "")
            .replace(":", "")
            .replace("T", "_")
        )
    if not stamp:
        stamp = "result"
    ext = EXPORT_FORMATS.get(fmt, EXPORT_FORMATS["json"])[1]
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in domain)
    # 去掉首尾的 "." 与 "_":既避免生成隐藏文件(. 开头),也避免 ".." 这种名字
    safe = "_".join(part for part in safe.strip("._").split("_") if part)[:80] or "result"
    return f"{safe}_{plan or 'scan'}_{stamp}.{ext}"
