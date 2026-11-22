"""风险总账 —— 把散落在各章节的发现汇成一个可排序的分值。

为什么需要它
------------
一次 Ultra 扫描可能产出:邮件审计的 3 条 finding、200 个子域的降噪结论、17 条接管
finding、几十个站点的安全头缺失、若干张过期证书。人会淹没在里面,而"先看哪个"
恰恰是 ASM 最要紧的事。

这个模块只做两件纯 CPU 的事:
  1) 用一套**显式、可解释**的加权模型算 0-100 分(越高越危险);
  2) 把同一 code 的多处命中聚合成一条(带 ``count``),避免"300 条 HSTS_MISSING"
     把真正的 Critical 挤出视野。

刻意不做的事
------------
- 不引入 CVSS。CVSS 需要一个具体漏洞和它的可利用条件,而这里全是"配置面"信号,
  硬套一套漏洞评分公式只会让人误以为分值是精确的。
- 不猜"如果攻击者可以..."。每一分的来源都在 ``items`` 里能找到对应 code。
"""

from typing import Any, Dict, List, Tuple

from app.schemas.scan import (
    SEVERITY_ORDER,
    RiskItem,
    RiskSummary,
    SeverityCounts,
)

SEV_CRITICAL = "Critical"
SEV_WARNING = "Warning"
SEV_INFO = "Info"

#: 聚合项最多返回多少条(按严重度 + 命中数排序后的头部)
_MAX_ITEMS = 20


def _grade(score: int) -> str:
    if score <= 10:
        return "A"
    if score <= 25:
        return "B"
    if score <= 45:
        return "C"
    if score <= 65:
        return "D"
    return "F"


class _Acc:
    """聚合器:按 (code, severity) 累计 count,并保留一个示例主体。"""

    __slots__ = ("items", "counts")

    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], RiskItem] = {}
        self.counts = SeverityCounts()

    def add(self, code: str, severity: str, subject: str, message: str) -> None:
        if severity == SEV_CRITICAL:
            self.counts.critical += 1
        elif severity == SEV_WARNING:
            self.counts.warning += 1
        else:
            self.counts.info += 1
            severity = SEV_INFO

        key = (code, severity)
        existing = self.items.get(key)
        if existing is None:
            self.items[key] = RiskItem(
                code=code,
                severity=severity,
                subject=subject,
                message=message,
                count=1,
            )
        else:
            existing.count += 1
            # 保留第一个主体作为示例;跨主体聚合时 subject 只用于定位
            if not existing.subject:
                existing.subject = subject

    def sorted_items(self) -> List[RiskItem]:
        return sorted(
            self.items.values(),
            key=lambda i: (SEVERITY_ORDER.get(i.severity, 9), -i.count, i.code),
        )[:_MAX_ITEMS]


def assess(data: Any) -> RiskSummary:
    """对一次扫描结果做风险汇总。``data`` 是 ScanData / ProScanData / UltraScanData。"""
    acc = _Acc()

    # ---------- 1) 邮件伪造:主域 ----------
    email = getattr(data, "email_audit", None)
    primary = getattr(email, "primary", None) if email is not None else None
    if primary is not None:
        for finding in getattr(primary, "findings", []) or []:
            if finding.severity == SEV_INFO:
                continue  # 主域的 Info 多是"你做对了"的确认(如 SPF_HARDFAIL),不进风险账
            acc.add(finding.code, finding.severity, primary.domain, finding.message)

    # ---------- 2) 邮件伪造:子域(只收 Critical/Warning)----------
    sub_critical = 0
    sub_warning = 0
    if email is not None:
        for sub in getattr(email, "subdomains", []) or []:
            level = getattr(sub, "risk_level", "")
            if level == "Critical":
                sub_critical += 1
            elif level == "Warning":
                sub_warning += 1
            else:
                continue
            findings = getattr(sub, "findings", []) or []
            code = findings[0].code if findings else "SUBDOMAIN_EMAIL_RISK"
            message = (
                findings[0].message
                if findings
                else "Subdomain mail identity is not protected against spoofing."
            )
            acc.add(code, level, sub.domain, message)

    # ---------- 3) 子域接管 ----------
    takeover = getattr(data, "takeover", None)
    takeover_high = 0
    takeover_low = 0
    if takeover is not None:
        for f in getattr(takeover, "findings", []) or []:
            if getattr(f, "is_vulnerable", False):
                takeover_high += 1
                acc.add(
                    "TAKEOVER_VULNERABLE",
                    SEV_CRITICAL,
                    f.domain,
                    f.evidence,
                )
            elif getattr(f, "confidence", "") == "Low":
                takeover_low += 1
                acc.add(
                    "TAKEOVER_REVIEW",
                    SEV_WARNING,
                    f.domain,
                    f.evidence,
                )

    # ---------- 4) 存活资产的 TLS / 响应头 ----------
    tls_expired = tls_unverified = tls_expiring = 0
    header_warnings = 0
    for asset in getattr(data, "live_assets", []) or []:
        tls = getattr(asset, "tls", None)
        if tls is not None:
            if getattr(tls, "expired", False):
                tls_expired += 1
                acc.add(
                    "TLS_EXPIRED",
                    SEV_CRITICAL,
                    asset.url,
                    f"Certificate is expired ({tls.not_after or 'unknown'}). Browsers "
                    "hard-fail on this endpoint.",
                )
            elif getattr(tls, "verification_error", None):
                tls_unverified += 1
                acc.add(
                    "TLS_UNVERIFIED",
                    SEV_WARNING,
                    asset.url,
                    f"Certificate cannot be validated: {tls.verification_error}.",
                )
            elif getattr(tls, "expiring_soon", False):
                tls_expiring += 1
                acc.add(
                    "TLS_EXPIRING",
                    SEV_WARNING,
                    asset.url,
                    f"Certificate expires in {tls.days_left} day(s) "
                    f"({tls.not_after or 'unknown'}).",
                )
            if getattr(tls, "self_signed", False):
                acc.add(
                    "TLS_SELF_SIGNED",
                    SEV_INFO,
                    asset.url,
                    "Certificate is self-signed.",
                )

        security = getattr(asset, "security", None)
        if security is not None:
            for finding in getattr(security, "findings", []) or []:
                if finding.severity == SEV_INFO:
                    continue
                header_warnings += 1
                acc.add(finding.code, finding.severity, asset.url, finding.message)

    # ---------- 评分 ----------
    score = 0
    if primary is not None:
        if getattr(primary, "risk_level", "") == "Critical":
            score += 30
        elif getattr(primary, "risk_level", "") == "Warning":
            score += 10
    score += min(20, 5 * sub_critical)
    score += min(6, sub_warning)
    score += min(30, 30 * takeover_high)
    score += min(9, 3 * takeover_low)
    score += min(16, 8 * tls_expired)
    score += min(9, 3 * tls_unverified)
    score += min(6, 2 * tls_expiring)
    score += min(15, header_warnings)
    score = max(0, min(100, score))

    return RiskSummary(
        risk_score=score,
        grade=_grade(score),
        counts=acc.counts,
        items=acc.sorted_items(),
    )
