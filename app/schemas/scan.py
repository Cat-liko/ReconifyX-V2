"""对外响应模型 —— 全部 pydantic v2,既做序列化也做校验。

分层约定(不要打乱,``ScanJobStatus.result`` 的 Union 依赖它):
    ScanData       发现层:子域名 + 资产 + DNS 情报
    ProScanData    在 ScanData 之上叠加:探活 + 邮件审计 + TLS/响应头情报
    UltraScanData  在 ProScanData 之上叠加:接管检测

所有模型都开 ``extra="forbid"``:Union 校验时,类型不匹配必须**报错**而不是静默丢掉
多出来的字段 —— 一个 Pro 结果被误判成 ScanData 时,丢掉的正是 live_assets / email_audit
这类核心字段,那是最难查的一类数据丢失。
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.domain import normalize_domain

# 所有"结果类"模型的公共配置:禁止额外字段
_STRICT = ConfigDict(extra="forbid")


# ==================== 计划常量 ====================

PLAN_BASIC_NAME = "Basic"
PLAN_PRO_NAME = "Pro"
PLAN_ULTRA_NAME = "Ultra"

#: 三个计划由弱到强的顺序,用于「至少覆盖到某计划」的判断
PLAN_ORDER = (PLAN_BASIC_NAME, PLAN_PRO_NAME, PLAN_ULTRA_NAME)

#: 风险等级与 finding 严重度的固定排序(报告/评分都用它排序)
SEVERITY_ORDER = {"Critical": 0, "Warning": 1, "Info": 2}


# ==================== 基础资产模型 ====================


class AssetRecord(BaseModel):
    """单个测绘资产:一个真实暴露在公网、被网络测绘引擎(Shodan/FOFA 等)扫描过的主机。"""

    ip: str = Field(..., description="资产 IP 地址")
    hostnames: List[str] = Field(default_factory=list, description="该 IP 关联的主机名(FQDN)")
    ports: List[int] = Field(default_factory=list, description="开放端口")
    domains: List[str] = Field(default_factory=list, description="测绘引擎归类的域名")
    org: Optional[str] = Field(None, description="所属组织 / ISP")
    os: Optional[str] = Field(None, description="操作系统指纹")
    country: Optional[str] = Field(None, description="国家")
    isp: Optional[str] = Field(None, description="ISP")
    products: List[str] = Field(default_factory=list, description="识别到的组件 / 产品指纹")
    ssl_subjects: List[str] = Field(default_factory=list, description="TLS 证书 CN / SAN 中出现的域名")


class SourceHealth(BaseModel):
    """单个数据源本次调用的健康状态,用于向调用方透明化数据完整性。"""

    name: str = Field(..., description="数据源名称")
    ok: bool = Field(..., description="是否成功返回数据")
    count: int = Field(0, description="该源贡献的原始主机名条数")
    detail: str = Field("", description="失败原因 / 备注(如 timeout、rate-limited)")


class ScanInfo(BaseModel):
    domain: str
    plan: str
    timestamp: str
    cached: bool = False
    source: str = "passive-dns+ct"
    # 数据完整性信号:骨干源全挂即为 True,提示结果可能不完整
    degraded: bool = False
    # 新鲜度信号:True 表示返回的是已过 fresh 窗口的旧快照(后台正在刷新或上游现拉失败兜底)
    stale: bool = False
    sources: List[SourceHealth] = Field(
        default_factory=list, description="各数据源本次调用的健康明细"
    )
    version: str = Field("", description="生成该结果的 ReconifyX 版本")
    elapsed_ms: Optional[int] = Field(
        None, description="本次请求的实际耗时(毫秒);缓存命中会非常小"
    )


# ==================== DNS 情报 ====================


class DnsIntel(BaseModel):
    """主域的结构化 DNS 情报(A/AAAA/NS/MX/TXT/CAA/SOA)。

    为什么它和子域名列表一起给:子域名回答"有哪些名字",DNS 记录回答"这些名字归谁管、
    邮件往哪投、谁能签发证书"。CAA 缺失 + NS 指向陌生服务商,往往比多一条子域更值得
    跟进。
    """

    domain: str
    a: List[str] = Field(default_factory=list, description="A 记录(IPv4)")
    aaaa: List[str] = Field(default_factory=list, description="AAAA 记录(IPv6)")
    ns: List[str] = Field(default_factory=list, description="权威 NS")
    mx: List[str] = Field(default_factory=list, description='MX 记录,格式 "优先级 主机"')
    txt: List[str] = Field(default_factory=list, description="TXT 记录(截断后)")
    caa: List[str] = Field(default_factory=list, description='CAA 记录,格式 "flags tag value"')
    soa: Optional[str] = Field(None, description="SOA 记录摘要")
    has_spf: bool = Field(False, description="TXT 中是否存在 SPF 记录")
    has_dmarc: bool = Field(False, description="_dmarc 是否存在 DMARC 记录")
    null_mx: bool = Field(
        False, description="是否存在 RFC 7505 null MX(`0 .`):该域声明不接收邮件"
    )
    resolved: bool = Field(False, description="A/AAAA 是否有任一解析结果")
    error: Optional[str] = Field(None, description="整体查询失败原因(单类记录失败不算)")


# ==================== TLS 证书情报 ====================


class TlsInfo(BaseModel):
    """一个 https 端点的证书与握手情报。

    判定口径:``verified`` 表示**系统信任库验证通过**(域名匹配 + 未过期 + 链路可信)。
    验证失败时我们并不放弃:``verification_error`` 会带出具体原因(过期 / 自签 /
    域名不匹配 / 中间证书缺失),这些恰恰是 ASM 最该暴露的问题。
    """

    host: str
    port: int = 443
    verified: bool = False
    subject: Optional[str] = Field(None, description="证书主体 CN")
    issuer: Optional[str] = Field(None, description="签发者(CA)名称")
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = Field(None, description="距到期天数(负数=已过期)")
    expired: bool = False
    expiring_soon: bool = Field(False, description="剩余天数低于 TLS_EXPIRY_WARN_DAYS")
    self_signed: bool = Field(False, description="主体与签发者相同(自签启发式)")
    san_count: int = Field(0, description="SAN 中的 DNS 名数量")
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    error: Optional[str] = Field(None, description="握手失败原因(连不上/超时/非 TLS)")
    verification_error: Optional[str] = Field(None, description="证书验证失败的具体原因")


# ==================== HTTP 安全响应头 ====================


class HeaderFinding(BaseModel):
    code: str = Field(..., description="机器可读代码,如 HSTS_MISSING")
    severity: str = Field(..., description="Critical / Warning / Info")
    message: str = Field(..., description="Human-readable explanation in English")


class SecurityHeaders(BaseModel):
    """一个站点缺失/配置错误的安全响应头评估。纯 CPU,零额外网络成本。"""

    score: int = Field(100, description="0-100,越高越好")
    grade: str = Field("A", description="A / B / C / D / F")
    findings: List[HeaderFinding] = Field(default_factory=list)
    present: Dict[str, str] = Field(
        default_factory=dict, description="本次实际看到的安全相关响应头(截断值)"
    )


# ==================== 风险评分 ====================


class SeverityCounts(BaseModel):
    critical: int = 0
    warning: int = 0
    info: int = 0


class RiskItem(BaseModel):
    """聚合后的一条风险项:同一 code 的多个主体合并成一条,``count`` 记录命中数。"""

    code: str
    severity: str
    subject: str = Field("", description="命中的主体(域名 / URL / IP);跨主体聚合时给示例")
    message: str
    count: int = Field(1, description="该 code 命中的主体数量")


class RiskSummary(BaseModel):
    """整次扫描的风险总账。

    ``risk_score`` 是 0-100 的**加权累计分**,越高越危险(与安全响应头的 score 方向相反,
    后者越高越好)。它只用于横向排序与一眼定级,不能替代具体 finding —— 每条 finding
    都带 code 与英文说明,才是可执行的部分。
    """

    risk_score: int = Field(0, description="0-100,越高越危险")
    grade: str = Field("A", description="A / B / C / D / F")
    counts: SeverityCounts = Field(default_factory=SeverityCounts)
    items: List[RiskItem] = Field(
        default_factory=list, description="按严重度排序的聚合风险项(最多 20 条)"
    )


# ==================== 发现层(Basic) ====================


class ScanData(BaseModel):
    model_config = _STRICT

    total_found: int = Field(..., description="去重后子域名(FQDN)总数")
    subdomains: List[str] = Field(default_factory=list, description="字母升序、严格去重的 FQDN 列表")
    total_assets: int = Field(..., description="测绘到的真实暴露资产数量")
    assets: List[AssetRecord] = Field(default_factory=list, description="IP+端口+指纹的富资产清单")
    dns: Optional[DnsIntel] = Field(None, description="主域 DNS 情报(A/NS/MX/TXT/CAA/SOA)")
    risk: Optional[RiskSummary] = Field(None, description="整次扫描的风险总账")


class ScanResponse(BaseModel):
    status: str = "success"
    info: ScanInfo
    data: ScanData


class PlanNotAvailableResponse(BaseModel):
    status: str = "unavailable"
    # 默认说明必须与"当前版本支持哪些计划"一致,否则会给调用方错误的指引。
    message: str = "Unsupported plan. Available plans: Basic / Pro / Ultra."
    requested_plan: str


# ==================== Pro 计划 ====================


class LiveAsset(BaseModel):
    """一个探活命中的存活资产。区别于 Basic 的 AssetRecord(测绘元数据),
    这里是 Pro 真实发起 HTTP 请求确认"活着"的结果,带指纹、跳转链路与证书/响应头情报。"""

    url: str = Field(..., description="探活的完整 URL(含协议)")
    host: str = Field("", description="主机名(与 url 对应,便于和其它章节 join)")
    status_code: int = Field(..., description="HTTP 状态码")
    title: Optional[str] = Field(None, description="页面 <title>(截断)")
    server: Optional[str] = Field(None, description="Server 响应头指纹")
    content_length: Optional[int] = Field(None, description="响应体字节数")
    content_type: Optional[str] = Field(None, description="Content-Type 响应头")
    # follow_redirects=False,手动记录 301/302 的 Location,暴露跳转链路
    redirect_to: Optional[str] = Field(None, description="3xx 时的 Location 跳转目标")
    tls: Optional[TlsInfo] = Field(None, description="该端点的 TLS 证书情报(仅 https)")
    security: Optional[SecurityHeaders] = Field(
        None, description="安全响应头评估(缺什么 / 配错了什么)"
    )


class AuditFinding(BaseModel):
    """单条结构化审计发现。机器可读的 code + 分级 severity + 英文人读说明。

    结构化(而非裸字符串)让用户能按 code 编程处理;message 保持英文以面向全球用户;
    severity 独立于整体 risk_level,标识该条发现自身的严重度。"""

    code: str = Field(..., description="Machine-readable finding code, e.g. SPF_MISSING")
    severity: str = Field(..., description="Finding severity: Critical / Warning / Info")
    message: str = Field(..., description="Human-readable explanation in English")


class EmailAuditResult(BaseModel):
    """邮件伪造风险审计结论(SPF + DMARC 红队视角)。

    is_spoofable=True 表示存在可被伪造发信的现实风险;risk_level 为
    Critical / Warning / Secure 三档。findings 列出具体命中的风险点。"""

    domain: str = Field(..., description="被审计的主域名")
    is_spoofable: bool = Field(
        ...,
        description=(
            "Whether an improvable forgery surface exists (includes cases mitigated by a "
            "strong DMARC policy). This flags room for hardening, NOT necessarily a "
            "practically exploitable hole. For real-world severity, read risk_level: e.g. "
            "a domain with no SPF but DMARC p=reject is is_spoofable=true yet risk_level=Warning."
        ),
    )
    risk_level: str = Field(..., description="风险等级:Critical / Warning / Secure")
    spf_record: Optional[str] = Field(None, description="解析到的 SPF 记录原文(无则 None)")
    dmarc_record: Optional[str] = Field(None, description="解析到的 DMARC 记录原文(无则 None)")
    dmarc_policy: Optional[str] = Field(None, description="DMARC p= 策略:none/quarantine/reject")
    findings: List[AuditFinding] = Field(
        default_factory=list, description="Structured findings (code + severity + English message)"
    )


class SubdomainEmailAudit(BaseModel):
    """单个子域的邮件伪造风险审计(降噪分级版)。

    区别于主域的 EmailAuditResult:子域缺 SPF 极常见(api./cdn./static. 本就不发信),
    直接判高危会误报洪水。这里结合"子域是否有自己的 MX/SPF(真实邮件身份)"+ 父域
    DMARC sp= 子域策略做智能分级。risk_level 含 Info 档:如实提示"低风险、不计伪造"。

    专业性说明:MX 是"收信"标识,伪造针对 From(发信)域。MX 只是"是否值得告警"的降噪
    启发式,不是"能否被伪造"的严格判据 —— 故无 MX 子域在父域无 sp 兜底时不判"安全",
    降级为 Info 如实提示,且不计入 spoofable 计数。"""

    domain: str = Field(..., description="被审计的子域名")
    has_own_spf: bool = Field(..., description="该子域是否有自己独立的 SPF 记录")
    has_own_mx: bool = Field(..., description="该子域是否有自己的 MX 记录(真实邮件身份)")
    is_spoofable: bool = Field(
        ...,
        description=(
            "Whether an improvable forgery surface exists on this subdomain (includes cases "
            "mitigated by the parent domain's DMARC sub-policy). Flags room for hardening, "
            "NOT necessarily practically exploitable. For real-world severity read risk_level; "
            "Info-level findings are low-risk and are NOT counted in spoofable_subdomains."
        ),
    )
    risk_level: str = Field(..., description="风险等级:Critical / Warning / Secure / Info")
    spf_record: Optional[str] = Field(None, description="子域自己的 SPF 记录原文(无则 None)")
    findings: List[AuditFinding] = Field(
        default_factory=list, description="Structured findings (code + severity + English message)"
    )


class EmailSecurityReport(BaseModel):
    """全域邮件安全报告:主域完整审计 + 全子域降噪分级审计。

    primary 为主域按红队视角的完整结论;subdomains 是发现的每个子域的降噪分级结果。
    spoofable_subdomains 只计 Critical/Warning,Info 级(低风险如实提示)不计入,
    避免夸大风险数。"""

    primary: EmailAuditResult = Field(..., description="主域完整邮件伪造审计结论")
    subdomain_policy: Optional[str] = Field(
        None, description="主域生效的子域策略(DMARC sp=,缺省回退 p=):none/quarantine/reject"
    )
    total_discovered: int = Field(
        0, description="发现的子域总数(去主域后),可能大于实际审计数(截断/超时时)"
    )
    total_subdomains_audited: int = Field(..., description="实际审计的子域数量")
    spoofable_subdomains: int = Field(
        ...,
        description=(
            "Count of subdomains with a Critical or Warning risk_level. Info-level (low-risk, "
            "e.g. non-mail subdomains with no SPF and no parent sub-policy) are excluded, so "
            "this may be lower than the number of subdomains whose is_spoofable is true."
        ),
    )
    audit_complete: bool = Field(
        True,
        description="审计是否完整覆盖所有发现的子域。False=子域数超过 PRO_MAX_AUDIT_TARGETS 上限被截断,只覆盖了前 N 个",
    )
    audit_note: Optional[str] = Field(
        None,
        description="覆盖情况人读说明(英文,含审计上限 cap 与实际覆盖数);完整/截断均给出",
    )
    subdomains: List[SubdomainEmailAudit] = Field(
        default_factory=list, description="每个子域的降噪分级审计结果(按 domain 升序)"
    )


class ProScanData(ScanData):
    """Pro 计划完整产出:发现层 + 探活存活清单 + 全域邮件安全审计。"""

    total_live: int = Field(..., description="探活命中的存活资产数量")
    live_assets: List[LiveAsset] = Field(default_factory=list, description="HTTP 探活确认存活的资产")
    probe_complete: bool = Field(
        True,
        description="探活是否完整覆盖所有目标。False=目标数超过 PRO_MAX_PROBE_TARGETS 上限被截断,只覆盖了前 N 个",
    )
    probe_note: Optional[str] = Field(
        None,
        description="覆盖情况人读说明(英文,含探活上限 cap 与实际覆盖数);完整/截断均给出",
    )
    email_audit: EmailSecurityReport = Field(..., description="全域邮件伪造风险审计报告")


class ProScanResponse(BaseModel):
    status: str = "success"
    info: ScanInfo
    data: ProScanData


# ==================== Ultra 计划:子域名接管检测 ====================


class TakeoverFinding(BaseModel):
    """单个子域的接管风险检测结论。

    两条信号并行判定:
      - CNAME 链:子域 CNAME 是否指向已知第三方托管服务(S3/GitHub Pages/Heroku/Fastly…)。
      - HTTP 正文指纹:已探活抓取的正文里是否命中"未认领/悬空"页面指纹。
    confidence 分级(降噪核心):
      - High = CNAME 命中托管商 且 正文命中该商悬空指纹 —— 双信号交叉,可判可接管。
      - Low  = 仅单信号命中 —— 不下可接管结论,标记人工复核,不计入 vulnerable_count。
    只有 is_vulnerable=True(High)才计入报告的 vulnerable_count,严控误报。"""

    domain: str = Field(..., description="被检测的子域名")
    cname_chain: List[str] = Field(
        default_factory=list, description="解析到的 CNAME 跳转链(空=无 CNAME / 解析失败)"
    )
    matched_provider: Optional[str] = Field(
        None, description="命中的第三方托管服务名(如 AWS S3 / GitHub Pages),无则 None"
    )
    matched_fingerprint: Optional[str] = Field(
        None, description="命中的悬空正文指纹标签(无则 None)"
    )
    is_vulnerable: bool = Field(
        ...,
        description=(
            "True only for High-confidence takeover (CNAME points to a known provider AND the "
            "page body matches that provider's dangling fingerprint). Low-confidence single-signal "
            "hits are is_vulnerable=false and flagged for manual review."
        ),
    )
    confidence: str = Field(..., description="Detection confidence: High / Low")
    status_code: Optional[int] = Field(
        None, description="探活拿到的 HTTP 状态码(无正文信号时为 None)"
    )
    evidence: str = Field(
        ..., description="Human-readable evidence (English) explaining the verdict"
    )


class TakeoverReport(BaseModel):
    """全子域接管检测报告。vulnerable_count 只计 High-confidence 命中。"""

    total_discovered: int = Field(
        0, description="发现的子域总数(去主域后),可能大于实际检测数(截断/超时时)"
    )
    total_checked: int = Field(..., description="实际做接管检测的子域数量")
    vulnerable_count: int = Field(
        ...,
        description=(
            "Count of High-confidence takeover findings (is_vulnerable=true). Low-confidence "
            "single-signal findings are excluded from this count."
        ),
    )
    takeover_complete: bool = Field(
        True,
        description="接管检测是否完整覆盖所有发现的子域。False=子域数超过 ULTRA_MAX_TAKEOVER_TARGETS 上限被截断,只覆盖了前 N 个",
    )
    takeover_note: Optional[str] = Field(
        None,
        description="覆盖情况人读说明(英文,含检测上限 cap 与实际覆盖数);完整/截断均给出",
    )
    findings: List[TakeoverFinding] = Field(
        default_factory=list,
        description="每个被检测子域的接管结论(按 domain 升序)。含 Low 级供人工复核",
    )


class UltraScanData(ProScanData):
    """Ultra 计划完整产出:Pro 全量能力 + 子域名接管检测报告。"""

    takeover: TakeoverReport = Field(..., description="全子域接管风险检测报告")


class UltraScanResponse(BaseModel):
    status: str = "success"
    info: ScanInfo
    data: UltraScanData


# ==================== 扫描差异对比 ====================


class ScanDiff(BaseModel):
    """本次扫描与同域名上一次扫描的差异。

    baseline=True 表示没有可比的历史(该域名第一次扫,或历史被关闭/清空),此时所有
    ``new_*`` 为空 —— 不会把"第一次看到的全部"伪装成"新增",那是最容易误导人的一种
    展示方式。
    """

    domain: str
    baseline: bool = Field(True, description="True=无历史基线,new_* 字段不可视为新增")
    compared_to_job_id: Optional[str] = None
    compared_at: Optional[str] = None
    new_subdomains: List[str] = Field(default_factory=list, description="本次新增的子域名")
    removed_subdomains: List[str] = Field(default_factory=list, description="本次消失的子域名")
    new_live_urls: List[str] = Field(default_factory=list, description="本次新上线的 URL")
    removed_live_urls: List[str] = Field(default_factory=list, description="本次不再存活的 URL")
    new_takeover_domains: List[str] = Field(
        default_factory=list, description="本次新出现接管信号的子域名"
    )
    new_ip_assets: List[str] = Field(default_factory=list, description="本次新增的 IP 资产")


class HistoryEntry(BaseModel):
    job_id: str
    plan: str
    finished_at: str
    risk_score: int = 0
    degraded: bool = False
    total_found: int = 0
    total_live: int = 0


# ==================== 异步任务(job) ====================


def utcnow_iso() -> str:
    """UTC 时间戳(带 Z 后缀)。

    用 now(timezone.utc) 而不是 utcnow():后者在 3.12+ 已废弃,且返回 naive datetime。
    去掉 tzinfo 后再 isoformat,是为了保持与旧接口完全一致的字符串格式
    (naive + "Z"),不破坏已对接的调用方。
    """
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"


class ScanJobCreate(BaseModel):
    """POST /scan 请求体:提交一次异步扫描。

    domain 在进入业务逻辑前就被归一化 + 校验(至少两个标签的合法 FQDN):
    它随后会进入缓存键和结果文件名,未校验的值会造成缓存键串用与路径穿越。
    """

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=3, description="待测绘的主域名,如 example.com")
    plan: str = Field("Basic", description="订阅计划:Basic / Pro / Ultra")

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class BatchScanCreate(BaseModel):
    """POST /scan/batch 请求体:一次提交多个域名(同一个计划)。"""

    model_config = ConfigDict(extra="forbid")

    domains: List[str] = Field(..., min_length=1, description="待测绘域名列表")
    plan: str = Field("Basic", description="订阅计划:Basic / Pro / Ultra")

    @field_validator("domains")
    @classmethod
    def _validate_domains(cls, values: List[str]) -> List[str]:
        # 归一化 + 去重(保持输入顺序),单个非法值直接让整批 422 —— 静默跳过会让
        # 调用方以为自己提交的域名都在扫,实际少了一部分。
        out: List[str] = []
        seen: set[str] = set()
        for raw in values:
            norm = normalize_domain(raw)
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        return out


class BatchScanAccepted(BaseModel):
    status: str = "accepted"
    plan: str
    jobs: List["ScanJobAccepted"] = Field(
        default_factory=list, description="每个域名对应的 job(顺序与请求一致)"
    )


class ScanJobAccepted(BaseModel):
    """POST /scan 响应:立即返回 job_id(毫秒级),客户端据 status 决定是否轮询。

    status="queued" 表示后台任务已启动,需轮询 GET /scan/{job_id};
    status="completed" 表示缓存 FRESH 命中秒回,可直接 GET 一次拿结果。"""

    job_id: str
    status: str          # queued / completed
    domain: str = ""
    plan: str = ""


class ScanJobStatus(BaseModel):
    """GET /scan/{job_id} 响应:任务当前状态 + (完成时)结果。

    result 用 Union[ScanData, ProScanData, UltraScanData]:对象在运行时已有具体类型,
    序列化按实例类型选 schema,无歧义。status 状态机:queued → running → completed | failed。"""

    job_id: str
    domain: str
    plan: str
    status: str          # queued / running / completed / failed
    created_at: str
    finished_at: Optional[str] = None
    from_cache: bool = Field(False, description="结果是否来自缓存 FRESH 命中(非本次新算)")
    degraded: Optional[bool] = Field(None, description="骨干源是否全挂(数据可能残缺)")
    sources: List[SourceHealth] = Field(default_factory=list, description="各数据源本次调用健康明细")
    error: Optional[str] = Field(None, description="失败原因(status=failed 时)")
    saved_path: Optional[str] = Field(None, description="结果已落盘的文件路径(实际扫描完成后)")
    elapsed_ms: Optional[int] = Field(None, description="任务实际执行耗时(毫秒)")
    result: Optional[Union[ScanData, ProScanData, UltraScanData]] = Field(
        None, description="扫描结果(status=completed 时)"
    )


# ==================== 元信息(给 WebUI / CLI 用) ====================


class PlanCapability(BaseModel):
    name: str
    title: str
    description: str
    features: List[str] = Field(default_factory=list)


class ApiMeta(BaseModel):
    name: str
    version: str
    plans: List[PlanCapability] = Field(default_factory=list)
    auth_required: bool = False
    rate_limit_per_minute: int = 0
    history_enabled: bool = False
    tls_enabled: bool = False
    limits: Dict[str, Any] = Field(default_factory=dict)


# 前向引用收尾(BatchScanAccepted 里的 "ScanJobAccepted")
BatchScanAccepted.model_rebuild()
