"""邮件伪造风险审计 —— SPF / DMARC 红队视角(Pro 计划)。

不是简单字符串匹配,而是按"能不能真的伪造这个域发信"来判定风险。核心问题:
一封声称来自 user@target.com 的邮件,收件方凭 SPF/DMARC 能不能拦下伪造者?

判定分三档(is_spoofable + risk_level):

  Critical(高危,is_spoofable=True):
    - 完全没有 SPF 记录        → 任何人都能冒充该域发信,收件方无从校验
    - 存在多条 SPF 记录        → RFC 7208 §3.2 规定 permerror,SPF 整体失效
    - 含 +all 机制             → 显式声明"任何 IP 都可代发",等于自废武功

  Warning(中危,is_spoofable=True):
    - 用 ~all(SoftFail)且 DMARC 未配 p=reject/quarantine
      → SoftFail 只是"软失败",伪造邮件通常仍进收件箱;没有 DMARC 兜底 = 可伪造
    - SPF 含过大的 ip4 CIDR(如 /8 /16)
      → 授权网段过宽,网段内任一主机(含他人租户)都能合法代发

  Secure(安全,is_spoofable=False):
    - 用 -all(HardFail)          → 明确拒绝未授权 IP,伪造被硬性拦下
    - 或 ~all + 强 DMARC(p=reject/quarantine) → SoftFail 由 DMARC 兜底

设计要点:
  - 全程 dns.asyncresolver 异步解析,绝不用同步 dns.resolver 阻塞事件循环。
  - SPF/DMARC 两条 TXT 查询并发(asyncio.gather)。
  - DNS 失败(NXDOMAIN/超时)按"记录缺失"处理,不抛异常污染上层。
"""

import asyncio
import random
import re
from typing import List, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.config import Settings
from app.schemas.scan import (
    AuditFinding,
    EmailAuditResult,
    EmailSecurityReport,
    SubdomainEmailAudit,
)

# 风险等级常量
RISK_CRITICAL = "Critical"
RISK_WARNING = "Warning"
RISK_SECURE = "Secure"
# Info:子域降噪专用 —— 低风险、如实提示、不计入 spoofable(非邮件身份且父域未兜底)
RISK_INFO = "Info"

# 单条 finding 的 severity(独立于整体 risk_level)
SEV_CRITICAL = "Critical"
SEV_WARNING = "Warning"
SEV_INFO = "Info"

# 提取 SPF 里的 all 机制:-all / ~all / +all / ?all,以及**裸 all**。
# RFC 7208 §5.1:裸 `all` 等价 `+all`(任何 IP 都通过)。旧正则要求必须带限定符,
# 于是 "v=spf1 all" 被当作"没有 all 机制"判成 Secure —— 漏报了最严重的一类配置。
# 用 token 边界(行首/空白 + 空白/行尾)锚定,避免把 "include:all"、"allow" 之类误命中。
_ALL_MECHANISM_RE = re.compile(r"(?:^|\s)([-~+?]?)all(?=\s|$)", re.IGNORECASE)
# 提取 ip4:x.x.x.x/nn 的 CIDR 前缀
_IP4_CIDR_RE = re.compile(r"ip4:[^/\s]+/(\d{1,2})", re.IGNORECASE)
# SPF 中会触发额外 DNS 查询的机制(RFC 7208 §4.6.4,上限 10 次)
_DNS_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})


def _build_resolver(s: Settings) -> "dns.asyncresolver.Resolver":
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = s.DNS_TIMEOUT_SECONDS
    resolver.lifetime = s.DNS_TIMEOUT_SECONDS
    return resolver


def _build_subdomain_resolver(s: Settings) -> "dns.asyncresolver.Resolver":
    """子域扇出专用解析器:单条 DNS 超时比主域审计更短(SUBDOMAIN_DNS_TIMEOUT_SECONDS)。
    扇出量大,单条慢查询不能拖垮整体预算 —— 少数超时的坏子域快速放弃,把预算留给能完成的多数。"""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = s.SUBDOMAIN_DNS_TIMEOUT_SECONDS
    resolver.lifetime = s.SUBDOMAIN_DNS_TIMEOUT_SECONDS
    return resolver


async def _query_txt(resolver, name: str) -> List[str]:
    """查一条 TXT 记录,返回拼接后的字符串列表(每条记录一个元素)。
    NXDOMAIN / NoAnswer / 超时 一律视为"无记录",返回空列表,不抛异常。"""
    try:
        answer = await resolver.resolve(name, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return []
    records: List[str] = []
    for rdata in answer:
        # TXT 记录可能被切成多段(每段 <=255 字节),strings 是 bytes 列表,拼回整条
        parts = getattr(rdata, "strings", None)
        if parts:
            joined = b"".join(parts).decode("utf-8", errors="replace")
        else:
            joined = str(rdata).strip('"')
        records.append(joined)
    return records


def _extract_spf(txt_records: List[str]) -> List[str]:
    """从一堆 TXT 记录里挑出 SPF 记录(以 v=spf1 开头)。可能有多条(即为风险)。"""
    return [r for r in txt_records if r.lower().startswith("v=spf1")]


def _extract_dmarc(txt_records: List[str]) -> Optional[str]:
    """从 _dmarc TXT 记录里挑出 DMARC 记录(以 v=DMARC1 开头)。"""
    for r in txt_records:
        if r.lower().startswith("v=dmarc1"):
            return r
    return None


def _all_mechanism(spf: str) -> Optional[tuple[str, str]]:
    """找出 SPF 里的 all 机制,返回 (限定符, 原始 token);没有则 None。

    裸 `all` 的限定符按 RFC 7208 视为 "+"(默认限定符),调用方据此判 Critical。
    """
    m = _ALL_MECHANISM_RE.search(spf)
    if not m:
        return None
    return (m.group(1) or "+", m.group(0).strip())


def _count_dns_mechanisms(spf: str) -> int:
    """估算一条 SPF 记录会触发多少次额外 DNS 查询(RFC 7208 §4.6.4)。

    按空白切 token 逐个判定,而不是用正则扫 `include:` / `a:` ——
    裸 `a` / `mx` / `ptr` 机制(如 "v=spf1 a mx -all")不带冒号,
    带冒号的正则版本会把它们漏计,从而低估 permerror(SPF 静默失效)的风险。
    """
    count = 0
    for token in spf.split():
        t = token.lower()
        if t and t[0] in "-~+?":
            t = t[1:]
        # include:foo / redirect=_spf / a/24 / mx:bar → 取机制名
        name = re.split(r"[:=]", t, maxsplit=1)[0].split("/", 1)[0]
        if name in _DNS_MECHANISMS:
            count += 1
    return count


def _parse_dmarc_policy(dmarc_record: Optional[str]) -> Optional[str]:
    """提取 DMARC 的 p= 策略值:none / quarantine / reject。无则 None。"""
    if not dmarc_record:
        return None
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", dmarc_record, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _parse_dmarc_sp(dmarc_record: Optional[str]) -> Optional[str]:
    """提取 DMARC 的 sp= 子域策略值:none / quarantine / reject。无 sp 标签则 None。"""
    if not dmarc_record:
        return None
    m = re.search(r"\bsp\s*=\s*(none|quarantine|reject)\b", dmarc_record, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _effective_sub_policy(dmarc_record: Optional[str]) -> Optional[str]:
    """子域生效策略:RFC 7489 规定 sp 缺省继承 p。有 sp 用 sp,否则回退到 p。

    这是子域降噪的核心依据 —— 主域一句 sp=reject 就能兜底保护所有未单独配置的子域,
    此时子域缺 SPF 不该判高危。"""
    sp = _parse_dmarc_sp(dmarc_record)
    if sp is not None:
        return sp
    return _parse_dmarc_policy(dmarc_record)


async def _query_mx(resolver, name: str) -> bool:
    """查子域是否有自己的 MX 记录(是否为真实邮件身份)。
    NXDOMAIN / NoAnswer / 超时 一律视为"无 MX",返回 False,不抛异常(镜像 _query_txt)。"""
    try:
        answer = await resolver.resolve(name, "MX")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return False
    # 有应答且非空即视为有 MX
    return len(answer) > 0


def _analyze(
    domain: str,
    spf_records: List[str],
    dmarc_record: Optional[str],
    s: Settings,
) -> EmailAuditResult:
    """核心判定:把 SPF/DMARC 记录翻译成 is_spoofable + risk_level + findings。"""
    findings: List[AuditFinding] = []
    dmarc_policy = _parse_dmarc_policy(dmarc_record)
    strong_dmarc = dmarc_policy in ("reject", "quarantine")

    # ---------- Critical 判定 ----------
    # 1) 完全没有 SPF —— 但要纳入 DMARC p= 的兜底(与子域降噪逻辑对齐,消除主域/子域双标)。
    #    缺 SPF 时,遵守 DMARC 的接收方对未对齐邮件的处置取决于 p=:
    #      p=reject/quarantine → 伪造邮件被拒收/隔离,现实可利用性大幅下降 → 降为 Warning
    #                            (仍 is_spoofable=True:应补 SPF 做纵深防御,且非 DMARC 接收方仍有风险)
    #      p=none / 无 DMARC  → 无任何兜底,真正裸奔 → 保留 Critical
    if not spf_records:
        if strong_dmarc:
            findings.append(AuditFinding(
                code="SPF_MISSING_DMARC_ENFORCED",
                severity=SEV_WARNING,
                message=(
                    f"No SPF record found, but DMARC p={dmarc_policy} rejects/quarantines "
                    "unaligned mail, so DMARC-honoring receivers block forgery. Add an SPF "
                    "record for defense in depth and for receivers that skip DMARC."
                ),
            ))
            return EmailAuditResult(
                domain=domain,
                is_spoofable=True,
                risk_level=RISK_WARNING,
                spf_record=None,
                dmarc_record=dmarc_record,
                dmarc_policy=dmarc_policy,
                findings=findings,
            )
        findings.append(AuditFinding(
            code="SPF_MISSING",
            severity=SEV_CRITICAL,
            message=(
                "No SPF record found and no strong DMARC policy (p=reject/quarantine). "
                "Anyone can spoof mail from this domain; receivers have no way to "
                "validate the sending source."
            ),
        ))
        return EmailAuditResult(
            domain=domain,
            is_spoofable=True,
            risk_level=RISK_CRITICAL,
            spf_record=None,
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            findings=findings,
        )

    # 2) 多条 SPF → RFC 7208 permerror,SPF 整体失效
    if len(spf_records) > 1:
        findings.append(AuditFinding(
            code="SPF_MULTIPLE_RECORDS",
            severity=SEV_CRITICAL,
            message=(
                f"Found {len(spf_records)} SPF records. RFC 7208 mandates a permerror "
                "when more than one exists, so SPF silently fails altogether."
            ),
        ))
        return EmailAuditResult(
            domain=domain,
            is_spoofable=True,
            risk_level=RISK_CRITICAL,
            spf_record=" || ".join(spf_records),
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            findings=findings,
        )

    spf = spf_records[0]
    all_mech = _all_mechanism(spf)
    all_qualifier = all_mech[0] if all_mech else None

    # 3) +all(含等价的裸 all)→ 显式放行任何 IP
    if all_qualifier == "+":
        bare = all_mech is not None and all_mech[1].lower() == "all"
        mechanism = (
            "a bare 'all' mechanism (which RFC 7208 defines as equivalent to +all),"
            if bare
            else "+all,"
        )
        findings.append(AuditFinding(
            code="SPF_PLUS_ALL",
            severity=SEV_CRITICAL,
            message=(
                f"SPF uses {mechanism} explicitly authorizing any IP to send on behalf of "
                "this domain. This fully opens the domain to spoofing."
            ),
        ))
        return EmailAuditResult(
            domain=domain,
            is_spoofable=True,
            risk_level=RISK_CRITICAL,
            spf_record=spf,
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            findings=findings,
        )

    # ---------- Warning 判定 ----------
    warning = False

    # SPF 触发 DNS 查询数超限 → permerror,SPF 静默失效(高危偏中,归 Warning)
    dns_lookups = _count_dns_mechanisms(spf)
    if dns_lookups > s.SPF_MAX_DNS_LOOKUPS:
        findings.append(AuditFinding(
            code="SPF_TOO_MANY_DNS_LOOKUPS",
            severity=SEV_WARNING,
            message=(
                f"SPF triggers about {dns_lookups} DNS lookups, exceeding the RFC 7208 "
                f"limit of {s.SPF_MAX_DNS_LOOKUPS}, which causes a permerror that can "
                "make SPF fail altogether."
            ),
        ))
        warning = True

    # 过大的 ip4 CIDR:授权网段过宽
    for prefix_str in _IP4_CIDR_RE.findall(spf):
        prefix = int(prefix_str)
        if prefix <= s.SPF_LARGE_CIDR_PREFIX:
            findings.append(AuditFinding(
                code="SPF_OVERSIZED_CIDR",
                severity=SEV_WARNING,
                message=(
                    f"SPF authorizes an oversized network /{prefix}. The range is too "
                    "broad; any host in it (including other tenants) can legitimately "
                    "send as this domain."
                ),
            ))
            warning = True

    # ~all(SoftFail)且无强 DMARC 兜底
    if all_qualifier == "~" and not strong_dmarc:
        findings.append(AuditFinding(
            code="SPF_SOFTFAIL_NO_DMARC",
            severity=SEV_WARNING,
            message=(
                "SPF uses ~all (SoftFail) and DMARC is not set to p=reject/quarantine. "
                "Spoofed mail is usually still delivered, with no hard rejection."
            ),
        ))
        warning = True

    # ?all(Neutral)本质等同无策略,当 SoftFail 从严处理;有强 DMARC 兜底时只记 Info
    if all_qualifier == "?":
        if not strong_dmarc:
            findings.append(AuditFinding(
                code="SPF_NEUTRAL",
                severity=SEV_WARNING,
                message=(
                    "SPF uses ?all (Neutral), which takes no stance and provides almost "
                    "no protection against spoofing."
                ),
            ))
            warning = True

    # 完全没有 all 机制 = 隐式 ?all(RFC 7208 §4.6.1):未授权发信方拿到 neutral,
    # 与显式 ?all 同等无效。旧实现把它判成 Secure,既漏报又与同文件对 ?all 的
    # "从严处理"自相矛盾 —— 这里统一按 Neutral 处理。
    if all_qualifier is None and not strong_dmarc:
        findings.append(AuditFinding(
            code="SPF_NO_ALL_MECHANISM",
            severity=SEV_WARNING,
            message=(
                "SPF has no 'all' mechanism, so it behaves as an implicit ?all (Neutral): "
                "unauthorized senders are neither rejected nor marked as failures. "
                "End the record with -all (or ~all plus a strong DMARC policy)."
            ),
        ))
        warning = True

    if warning:
        return EmailAuditResult(
            domain=domain,
            is_spoofable=True,
            risk_level=RISK_WARNING,
            spf_record=spf,
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            findings=findings,
        )

    # ---------- Secure 判定 ----------
    # 能走到这里说明:要么 -all,要么(非 -all 且)有强 DMARC 兜底。
    if all_qualifier == "-":
        findings.append(AuditFinding(
            code="SPF_HARDFAIL",
            severity=SEV_INFO,
            message=(
                "SPF uses -all (HardFail), explicitly rejecting unauthorized IPs. "
                "Spoofing is hard-blocked."
            ),
        ))
    else:
        findings.append(AuditFinding(
            code="SPF_SOFTFAIL_STRONG_DMARC",
            severity=SEV_INFO,
            message=(
                f"SPF does not end in -all, but DMARC p={dmarc_policy} enforces a strong "
                "policy, so spoofed mail is rejected/quarantined."
            ),
        ))

    return EmailAuditResult(
        domain=domain,
        is_spoofable=False,
        risk_level=RISK_SECURE,
        spf_record=spf,
        dmarc_record=dmarc_record,
        dmarc_policy=dmarc_policy,
        findings=findings,
    )


async def audit_email_security(domain: str, s: Settings) -> EmailAuditResult:
    """入口:并发拉取 SPF(根域 TXT) 与 DMARC(_dmarc TXT),给出伪造风险审计结论。"""
    resolver = _build_resolver(s)
    root_txt, dmarc_txt = await asyncio.gather(
        _query_txt(resolver, domain),
        _query_txt(resolver, f"_dmarc.{domain}"),
    )
    spf_records = _extract_spf(root_txt)
    dmarc_record = _extract_dmarc(dmarc_txt)
    return _analyze(domain, spf_records, dmarc_record, s)


# ==================== 全子域降噪分级审计(Pro 核心卖点)====================

# 子域专属 finding code
_SUB_UNPROTECTED_LOW_RISK = "SUBDOMAIN_UNPROTECTED_LOW_RISK"


def _analyze_subdomain(
    subdomain: str,
    own_spf_records: List[str],
    has_mx: bool,
    parent_strong: bool,
    s: Settings,
) -> SubdomainEmailAudit:
    """子域降噪分级判定。核心:不给"缺 SPF"一刀切判高危,而是结合
    子域是否有真实邮件身份(自己的 SPF/MX)+ 父域 sp 是否兜底。

    parent_strong = 父域生效子域策略(sp 或回退 p)为 reject/quarantine。

    分级:
      有自己的 SPF → 复用主域 all 限定符逻辑:
        +all / 多条 → Critical;-all → Secure;~all/?all → 无强父域则 Warning,否则 Secure。
      无 SPF 但有 MX(真实收发信身份却缺 SPF)→ 父域兜底则 Warning(应自设),否则 Critical。
      无 SPF 且无 MX(非邮件身份)→ 父域兜底则 Secure,否则 Info(如实提示低风险,不计伪造)。
    """
    has_own_spf = len(own_spf_records) > 0
    findings: List[AuditFinding] = []

    # ---------- 分支 1:子域有自己独立的 SPF ----------
    if has_own_spf:
        # 多条 SPF → RFC 7208 permerror,SPF 整体失效
        if len(own_spf_records) > 1:
            findings.append(AuditFinding(
                code="SPF_MULTIPLE_RECORDS",
                severity=SEV_CRITICAL,
                message=(
                    f"Found {len(own_spf_records)} SPF records on this subdomain. "
                    "RFC 7208 mandates a permerror when more than one exists, so SPF "
                    "silently fails altogether."
                ),
            ))
            return SubdomainEmailAudit(
                domain=subdomain, has_own_spf=True, has_own_mx=has_mx,
                is_spoofable=True, risk_level=RISK_CRITICAL,
                spf_record=" || ".join(own_spf_records), findings=findings,
            )

        spf = own_spf_records[0]
        # 裸 all 等价 +all(RFC 7208 §5.1),与主域判定保持同一套解析
        all_mech = _all_mechanism(spf)
        all_qualifier = all_mech[0] if all_mech else None

        # +all(含裸 all)→ 显式放行任何 IP
        if all_qualifier == "+":
            findings.append(AuditFinding(
                code="SPF_PLUS_ALL",
                severity=SEV_CRITICAL,
                message=(
                    "SPF uses +all (or a bare 'all' mechanism), explicitly authorizing any "
                    "IP to send on behalf of this subdomain. This fully opens it to spoofing."
                ),
            ))
            return SubdomainEmailAudit(
                domain=subdomain, has_own_spf=True, has_own_mx=has_mx,
                is_spoofable=True, risk_level=RISK_CRITICAL,
                spf_record=spf, findings=findings,
            )

        # -all → HardFail,安全
        if all_qualifier == "-":
            findings.append(AuditFinding(
                code="SPF_HARDFAIL",
                severity=SEV_INFO,
                message=(
                    "SPF uses -all (HardFail), explicitly rejecting unauthorized IPs. "
                    "Spoofing is hard-blocked."
                ),
            ))
            return SubdomainEmailAudit(
                domain=subdomain, has_own_spf=True, has_own_mx=has_mx,
                is_spoofable=False, risk_level=RISK_SECURE,
                spf_record=spf, findings=findings,
            )

        # ~all / ?all / 无 all 机制 —— 有强父域兜底则安全,否则 Warning
        if parent_strong:
            findings.append(AuditFinding(
                code="SPF_SOFTFAIL_STRONG_DMARC",
                severity=SEV_INFO,
                message=(
                    "SPF does not end in -all (or has no 'all' mechanism), but the parent "
                    "domain enforces a strong DMARC subdomain policy (sp=reject/quarantine). "
                    "Spoofed mail is contained."
                ),
            ))
            return SubdomainEmailAudit(
                domain=subdomain, has_own_spf=True, has_own_mx=has_mx,
                is_spoofable=False, risk_level=RISK_SECURE,
                spf_record=spf, findings=findings,
            )
        findings.append(AuditFinding(
            code="SPF_SOFTFAIL_NO_DMARC",
            severity=SEV_WARNING,
            message=(
                "SPF does not end in -all (or has no 'all' mechanism) and no strong parent "
                "DMARC subdomain policy backs it up. Spoofed mail is usually still delivered."
            ),
        ))
        return SubdomainEmailAudit(
            domain=subdomain, has_own_spf=True, has_own_mx=has_mx,
            is_spoofable=True, risk_level=RISK_WARNING,
            spf_record=spf, findings=findings,
        )

    # ---------- 分支 2:无自己的 SPF,但有 MX(真实邮件身份缺 SPF)----------
    if has_mx:
        if parent_strong:
            findings.append(AuditFinding(
                code="SPF_MISSING",
                severity=SEV_WARNING,
                message=(
                    "This subdomain has MX (a real mail identity) but no SPF record. "
                    "The parent DMARC subdomain policy (sp=reject/quarantine) contains "
                    "abuse, but this subdomain should still set its own SPF."
                ),
            ))
            return SubdomainEmailAudit(
                domain=subdomain, has_own_spf=False, has_own_mx=True,
                is_spoofable=True, risk_level=RISK_WARNING,
                spf_record=None, findings=findings,
            )
        findings.append(AuditFinding(
            code="SPF_MISSING",
            severity=SEV_CRITICAL,
            message=(
                "This subdomain has MX (a real mail identity) but no SPF record and no "
                "strong parent DMARC subdomain policy. Anyone can spoof mail from it."
            ),
        ))
        return SubdomainEmailAudit(
            domain=subdomain, has_own_spf=False, has_own_mx=True,
            is_spoofable=True, risk_level=RISK_CRITICAL,
            spf_record=None, findings=findings,
        )

    # ---------- 分支 3:无 SPF 且无 MX(非邮件身份)----------
    if parent_strong:
        findings.append(AuditFinding(
            code="SPF_SOFTFAIL_STRONG_DMARC",
            severity=SEV_INFO,
            message=(
                "No SPF and no MX, but the parent DMARC subdomain policy "
                "(sp=reject/quarantine) covers this subdomain. Spoofing is contained."
            ),
        ))
        return SubdomainEmailAudit(
            domain=subdomain, has_own_spf=False, has_own_mx=False,
            is_spoofable=False, risk_level=RISK_SECURE,
            spf_record=None, findings=findings,
        )
    # 无 MX = 无发信意图,伪造该子域的收益有限;但父域也未兜底 → 如实提示低风险,
    # 不判 Secure(MX 只是启发式,非严格判据),也不计入 spoofable 计数。
    findings.append(AuditFinding(
        code=_SUB_UNPROTECTED_LOW_RISK,
        severity=SEV_INFO,
        message=(
            "No SPF, no MX, and no strong parent DMARC subdomain policy. This subdomain "
            "is not a mail identity, so spoofing value is low, but it is technically "
            "unprotected. Add an SPF -all record if it never sends mail."
        ),
    ))
    return SubdomainEmailAudit(
        domain=subdomain, has_own_spf=False, has_own_mx=False,
        is_spoofable=False, risk_level=RISK_INFO,
        spf_record=None, findings=findings,
    )


async def _audit_one_subdomain(
    subdomain: str,
    resolver,
    sem: asyncio.Semaphore,
    parent_strong: bool,
    s: Settings,
) -> Optional[SubdomainEmailAudit]:
    """审计单个子域:并发查它自己的 SPF(TXT)+ MX,再降噪分级。
    单目标异常隔离,不外溢(gather return_exceptions 会兜住,这里再吞一层保险)。"""
    async with sem:
        # 单目标域速率收敛:发出前小随机抖动,打散整批扇出的突发特征
        await asyncio.sleep(random.uniform(0, s.PER_TARGET_JITTER_SECONDS))
        try:
            own_txt, has_mx = await asyncio.gather(
                _query_txt(resolver, subdomain),
                _query_mx(resolver, subdomain),
            )
        except Exception:  # noqa: BLE001 - 单目标异常不影响其他子域
            return None
        own_spf = _extract_spf(own_txt)
        return _analyze_subdomain(subdomain, own_spf, has_mx, parent_strong, s)


async def audit_email_security_full(
    main_domain: str, subdomains: List[str], s: Settings
) -> EmailSecurityReport:
    """Pro 入口:主域完整审计 + 全子域降噪分级并发审计。

    并发数动态收敛为 min(子域数, AUDIT_CONCURRENCY_CAP);超大域截断到
    PRO_MAX_AUDIT_TARGETS。父域 DMARC sp(缺省回退 p)为 reject/quarantine 时,
    未单独配置的子域被兜底,不判高危 —— 这是避免误报洪水的关键。
    """
    # 1) 主域完整审计(复用现有逻辑;它内部会自建解析器),并算出对子域的生效兜底策略
    primary = await audit_email_security(main_domain, s)
    sub_policy = _effective_sub_policy(primary.dmarc_record)
    parent_strong = sub_policy in ("reject", "quarantine")

    # 2) 目标子域 = 发现的子域去掉主域自身,去重后。total_discovered 记录截断前的真实发现数
    seen: set[str] = set()
    discovered: List[str] = []
    for d in subdomains:
        if d == main_domain or d in seen:
            continue
        seen.add(d)
        discovered.append(d)
    total_discovered = len(discovered)
    # 超大域截断:只审计前 N 个。截断本身就让 audit_complete=False(如实透明)
    targets = discovered[: s.PRO_MAX_AUDIT_TARGETS]
    truncated = len(targets) < total_discovered

    sub_results: List[SubdomainEmailAudit] = []
    if targets:
        # 3) 动态收敛并发:子域少就少开,绝不超上限。扇出用短超时的专用解析器
        sub_resolver = _build_subdomain_resolver(s)
        concurrency = min(len(targets), s.AUDIT_CONCURRENCY_CAP)
        sem = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(
                _audit_one_subdomain(d, sub_resolver, sem, parent_strong, s)
            )
            for d in targets
        ]
        # 4) 等全部子域审计跑完(单条 DNS 超时由 SUBDOMAIN_DNS_TIMEOUT_SECONDS 约束,
        #    本地自部署不再设整体墙钟截止)。
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                continue
            if isinstance(res, SubdomainEmailAudit):
                sub_results.append(res)

    sub_results.sort(key=lambda a: a.domain)

    # 5) spoofable 计数只算 Critical/Warning,Info 级(低风险如实提示)不计入
    spoofable = sum(
        1 for r in sub_results if r.risk_level in (RISK_CRITICAL, RISK_WARNING)
    )

    # 审计完整性:被截断(超大域只审计前 N 个)即为不完整
    audit_complete = not truncated

    # 完整性说明:截断(子域数 > 上限)时显式标出 cap 与跳过数;完整时也标出 cap,
    # 让「审计上限」在结果里稳定可见,而非只在截断时才出现。
    cap = s.PRO_MAX_AUDIT_TARGETS
    if audit_complete:
        audit_note = f"Full coverage: audited all {total_discovered} subdomains (cap {cap})."
    else:
        audited = len(sub_results)
        audit_note = (
            f"Partial coverage: cap {cap} subdomains — audited {audited} of "
            f"{total_discovered} ({total_discovered - cap} skipped). "
            "Raise the cap or re-query for full coverage."
        )

    return EmailSecurityReport(
        primary=primary,
        subdomain_policy=sub_policy,
        total_discovered=total_discovered,
        total_subdomains_audited=len(sub_results),
        spoofable_subdomains=spoofable,
        audit_complete=audit_complete,
        audit_note=audit_note,
        subdomains=sub_results,
    )
