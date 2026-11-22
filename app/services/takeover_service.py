"""子域名接管风险检测 —— Ultra 计划差异化卖点。

子域名接管(Subdomain Takeover):子域 CNAME 指向某第三方托管服务(S3 桶 / GitHub Pages /
Heroku app / Fastly service),但该服务侧的资源已被释放/删除,而 DNS 上的 CNAME 还挂着。
攻击者只要去对应平台把这个"空名字"注册回来,就能在你的子域上托管任意内容 —— 钓鱼、
盗 Cookie、发凭据。这是红队/ASM 里的高价值命中。

两条信号并行,交叉判定(降噪核心):
  1) CNAME 链解析:子域 CNAME 是否指向已知第三方托管服务的特征后缀(如 .s3.amazonaws.com、
     .github.io、herokudns.com、.fastly.net)。
  2) HTTP 正文指纹:对已探活抓取的正文(含 404/500,恰恰是最强信号)做"未认领/悬空"指纹匹配
     (NoSuchBucket、"There isn't a GitHub Pages site here"、"No such app"、
     "Fastly error: unknown domain")。

confidence 分级:
  - High(is_vulnerable=True):CNAME 命中托管商 且 正文命中该商悬空指纹 —— 双信号交叉,可判可接管。
  - Low (is_vulnerable=False):仅单信号命中 —— 不下结论,标记人工复核,不计入 vulnerable_count。
    例:CNAME 指向 S3 但正文非 NoSuchBucket(桶可能仍在用);或正文疑似悬空但无对应 CNAME。

设计要点(与 audit_service.py 同构):
  - 全程 dns.asyncresolver 异步解析,CNAME 查询失败(NXDOMAIN/超时)按"无 CNAME"处理,不抛异常。
  - 扇出并发 asyncio.Semaphore 动态收敛 min(子域数, TAKEOVER_CONCURRENCY_CAP)。
  - 单条 DNS 超时由 TAKEOVER_DNS_TIMEOUT_SECONDS 约束;本地自部署不再设整体墙钟截止。
  - 指纹库为纯数据常量(_PROVIDERS),判定逻辑与数据分离 —— 先窄后宽,便于扩充且不动逻辑。
  - 检测逻辑做成纯函数(_analyze_takeover),不依赖"同步返回"语境,为 Phase 2 异步作业模型预留。
"""

import asyncio
import random
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.config import Settings
from app.schemas.scan import TakeoverFinding, TakeoverReport

# confidence 常量
CONF_HIGH = "High"
CONF_LOW = "Low"


@dataclass
class ProviderSignature:
    """一个第三方托管服务的接管指纹。纯数据,判定逻辑不写在这里。

    - name: 人读服务名(进 matched_provider)。
    - cname_suffixes: 该服务 CNAME 目标的特征**后缀**(小写),命中任一即视为"指向该托管商"。
    - cname_patterns: 需要"中间匹配"的 CNAME 形态(如 S3 的区域端点
      bucket.s3.us-west-2.amazonaws.com)。用锚定正则表达,而不是 `suffix in target`
      这种子串判断 —— 子串会把 evil.s3.amazonaws.com.attacker.net 误判成指向 S3。
    - fingerprints: 悬空/未认领页面的正文特征串(小写子串匹配),命中任一即视为"资源已释放"。
    - fingerprint_label: 命中正文指纹时写入 matched_fingerprint 的简短标签。
    - is_vulnerable: 该服务悬空后是否真的能被第三方认领接管。多数托管商可接管(True);
      少数(如 Zendesk)悬空但平台不允许认领,或仅特定条件可接管(Edge case),如实标 False。
      双信号命中时 confidence 仍是 High(确认悬空事实),is_vulnerable 据此区分
      "可接管"与"悬空但不可利用",严控误报。
    """

    name: str
    cname_suffixes: Tuple[str, ...]
    fingerprints: Tuple[str, ...]
    fingerprint_label: str
    is_vulnerable: bool = True
    cname_patterns: Tuple["re.Pattern[str]", ...] = ()


# 指纹库:先窄后宽。第一批 4 个高确定性托管商端到端验证通过后,扩量到 17 个,
# 覆盖 Azure / Shopify / Netlify / Ghost / Readthedocs / Zendesk / Surge / Bitbucket /
# Tumblr / WordPress / Pantheon / SmartJobBoard / Feedpress 等(参考 can-i-take-over-xyz)。
# 所有匹配串均为小写,匹配时对 CNAME 目标与正文统一 lower() 后比对。
# 注意:Azure 的悬空信号本质是 NXDOMAIN(资源删除后 CNAME 目标直接解析失败),当前两信号
# 模型(正文指纹)只能覆盖其 404 正文型变体,NXDOMAIN 型是已知盲区,见交付说明。
_PROVIDERS: Tuple[ProviderSignature, ...] = (
    ProviderSignature(
        name="AWS S3",
        cname_suffixes=(
            ".s3.amazonaws.com",
        ),
        # 区域端点/静态站点端点形如:
        #   bucket.s3.us-west-2.amazonaws.com
        #   bucket.s3-website-us-east-1.amazonaws.com
        #   bucket.s3.dualstack.ap-south-1.amazonaws.com
        # 这类目标既不以 ".s3.amazonaws.com" 结尾,也没有固定后缀,只能用锚定正则覆盖。
        cname_patterns=(
            # bucket.s3.us-west-2.amazonaws.com / bucket.s3.dualstack.ap-south-1...
            re.compile(r"\.s3[.-][a-z0-9-]+(?:\.[a-z0-9-]+)*\.amazonaws\.com$"),
            # bucket.s3-website-us-east-1.amazonaws.com / bucket.s3-website.eu-west-1...
            re.compile(r"\.s3-website[-.][a-z0-9-]+\.amazonaws\.com$"),
        ),
        fingerprints=(
            "the specified bucket does not exist",
            "nosuchbucket",
        ),
        fingerprint_label="S3 NoSuchBucket",
    ),
    ProviderSignature(
        name="GitHub Pages",
        cname_suffixes=(
            ".github.io",
        ),
        fingerprints=(
            "there isn't a github pages site here",
            "for root urls (like http://example.com/) you must provide an index.html file",
        ),
        fingerprint_label="GitHub Pages 404",
    ),
    ProviderSignature(
        name="Heroku",
        cname_suffixes=(
            ".herokudns.com",
            ".herokuapp.com",
            ".herokussl.com",
        ),
        fingerprints=(
            "no such app",
            "there's nothing here, yet",
        ),
        fingerprint_label="Heroku No such app",
    ),
    ProviderSignature(
        name="Fastly",
        cname_suffixes=(
            ".fastly.net",
            ".fastlylb.net",
        ),
        fingerprints=(
            "fastly error: unknown domain",
            "please check that this domain has been added to a service",
        ),
        fingerprint_label="Fastly unknown domain",
    ),
    ProviderSignature(
        name="Microsoft Azure",
        cname_suffixes=(
            ".azurewebsites.net",
            ".cloudapp.net",
            ".azure-api.net",
            ".trafficmanager.net",
        ),
        fingerprints=(
            "404 web site not found",
            "404 - web app not found",
        ),
        fingerprint_label="Azure dangling app",
    ),
    ProviderSignature(
        name="Ghost",
        cname_suffixes=(".ghost.io",),
        fingerprints=(
            "site unavailable",
            "failed to resolve dns path for this host",
        ),
        fingerprint_label="Ghost unavailable",
    ),
    ProviderSignature(
        name="Readthedocs",
        cname_suffixes=(".readthedocs.io",),
        fingerprints=(
            "the link you have followed or the url that you entered does not exist",
        ),
        fingerprint_label="Readthedocs missing project",
    ),
    ProviderSignature(
        name="Surge",
        cname_suffixes=(".surge.sh",),
        fingerprints=(
            "project not found",
            "this site is not being served by surge",
        ),
        fingerprint_label="Surge project not found",
    ),
    ProviderSignature(
        name="Bitbucket",
        cname_suffixes=(".bitbucket.io",),
        fingerprints=(
            "repository not found",
            "the page you are trying to reach does not exist",
        ),
        fingerprint_label="Bitbucket repo not found",
    ),
    ProviderSignature(
        name="Tumblr",
        cname_suffixes=(".tumblr.com",),
        fingerprints=(
            "whatever you were looking for doesn't currently exist at this address",
        ),
        fingerprint_label="Tumblr not found",
    ),
    ProviderSignature(
        name="WordPress.com",
        cname_suffixes=(".wpcomstaging.com",),
        fingerprints=(
            "do you want to register",
            "this site is no longer available",
        ),
        fingerprint_label="WordPress unclaimed",
    ),
    ProviderSignature(
        name="Pantheon",
        cname_suffixes=(".pantheon.io",),
        fingerprints=(
            "404 error unknown site",
            "the gods are wise, but do not know of the site which you seek",
        ),
        fingerprint_label="Pantheon unknown site",
    ),
    ProviderSignature(
        name="SmartJobBoard",
        cname_suffixes=(".smartjobboard.com",),
        fingerprints=(
            "this job board website is either expired or its domain name is invalid",
        ),
        fingerprint_label="SmartJobBoard expired",
    ),
    ProviderSignature(
        name="Feedpress",
        cname_suffixes=(".feedpress.me",),
        fingerprints=(
            "it looks like this domain is not configured",
        ),
        fingerprint_label="Feedpress unconfigured",
    ),
    # ---- 悬空但不可直接接管(如实标注 is_vulnerable=False,严控误报) ----
    ProviderSignature(
        name="Shopify",
        cname_suffixes=(".myshopify.com",),
        fingerprints=(
            "sorry, this shop is currently unavailable",
        ),
        fingerprint_label="Shopify unavailable",
        is_vulnerable=False,
    ),
    ProviderSignature(
        name="Netlify",
        cname_suffixes=(".netlify.app",),
        fingerprints=(
            "not found - request id",
        ),
        fingerprint_label="Netlify not found",
        is_vulnerable=False,
    ),
    ProviderSignature(
        name="Zendesk",
        cname_suffixes=(".zendesk.com",),
        fingerprints=(
            "help center closed",
        ),
        fingerprint_label="Zendesk closed",
        is_vulnerable=False,
    ),
)


def _build_takeover_resolver(s: Settings) -> "dns.asyncresolver.Resolver":
    """接管检测专用解析器:单条 CNAME 查询短超时(TAKEOVER_DNS_TIMEOUT_SECONDS)。
    扇出量大,单条慢查询不能拖垮整体预算(镜像 audit_service._build_subdomain_resolver)。"""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = s.TAKEOVER_DNS_TIMEOUT_SECONDS
    resolver.lifetime = s.TAKEOVER_DNS_TIMEOUT_SECONDS
    return resolver


async def _query_cname_chain(resolver, name: str, s: Settings) -> List[str]:
    """跟随 CNAME 链,返回跳转目标列表(不含起始 name 本身)。

    最多跟随 TAKEOVER_MAX_CNAME_HOPS 跳,防御 CNAME 环 / 超长链把单目标预算吃光。
    每一跳 NXDOMAIN / NoAnswer / 超时 一律视为"链到此为止",返回已收集的部分,不抛异常
    (镜像 audit_service._query_txt 的异常吞咽模式)。返回的每个目标都已去尾点、转小写。"""
    chain: List[str] = []
    current = name
    seen: set[str] = set()
    for _ in range(s.TAKEOVER_MAX_CNAME_HOPS):
        try:
            answer = await resolver.resolve(current, "CNAME")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            break
        # CNAME 应答通常只有一条 target;取第一条即可
        target = None
        for rdata in answer:
            target = str(getattr(rdata, "target", rdata)).rstrip(".").lower()
            break
        if not target:
            break
        chain.append(target)
        # 防环:目标已见过,停止跟随
        if target in seen:
            break
        seen.add(target)
        current = target
    return chain


def _cname_matches(provider: ProviderSignature, target: str) -> bool:
    """判断一个 CNAME 目标是否指向该托管商。

    只做**后缀**(或整名相等)匹配,绝不做子串匹配:
    子串判断会把 `evil.s3.amazonaws.com.attacker.net` 当成指向 AWS S3。
    叠加正文里的 "NoSuchBucket" 指纹后,就会产出"高置信、可接管"的假阳性
    —— 而这类假阳性在这个工具里恰恰是最贵的错误(会让人去改根本不存在的配置)。
    """
    for suffix in provider.cname_suffixes:
        bare = suffix.lstrip(".")
        if target == bare or target.endswith(suffix):
            return True
    return any(pattern.search(target) for pattern in provider.cname_patterns)


def _match_provider_by_cname(cname_chain: List[str]) -> Optional[ProviderSignature]:
    """CNAME 链是否指向某已知托管商:任一跳的目标以某商特征后缀结尾即命中。"""
    for target in cname_chain:
        for provider in _PROVIDERS:
            if _cname_matches(provider, target):
                return provider
    return None


def _match_fingerprint_in_body(
    body: Optional[str], provider: Optional[ProviderSignature]
) -> Optional[ProviderSignature]:
    """正文是否命中悬空指纹。

    - provider 已知(CNAME 命中):只匹配该商自己的指纹 —— 交叉验证,严控误报。
    - provider 未知(无 CNAME 命中):对全指纹库扫一遍,任一商指纹命中即返回该商 ——
      用于"正文疑似悬空但 CNAME 未命中"的 Low 置信度旁证。
    """
    if not body:
        return None
    low = body.lower()
    candidates = (provider,) if provider is not None else _PROVIDERS
    for prov in candidates:
        if prov is None:
            continue
        for fp in prov.fingerprints:
            if fp in low:
                return prov
    return None


def _analyze_takeover(
    domain: str,
    cname_chain: List[str],
    status_code: Optional[int],
    body: Optional[str],
) -> Optional[TakeoverFinding]:
    """纯函数接管判定:CNAME 信号 × 正文指纹信号,交叉分级。

    不做任何 IO,不依赖"同步返回"语境 —— Phase 2 异步作业模型可原样复用。

    判定矩阵:
      CNAME 命中商 且 正文命中该商指纹 → High(is_vulnerable=True):可判可接管。
      仅 CNAME 命中商(正文未命中)       → Low:指向第三方但资源可能仍在用,人工复核。
      仅正文命中某商指纹(无 CNAME 命中) → Low:疑似悬空但缺 CNAME 佐证,人工复核。
      两者都不命中                       → 返回 None,不生成 finding(降噪)。
    """
    cname_provider = _match_provider_by_cname(cname_chain)
    # 正文匹配:CNAME 命中则只验该商指纹(交叉);未命中则全库扫一遍找旁证
    body_provider = _match_fingerprint_in_body(body, cname_provider)

    # ---------- High:双信号交叉命中 ----------
    if cname_provider is not None and body_provider is not None:
        # 双信号交叉确认"悬空事实",confidence=High;但"是否可接管"取决于该 provider
        # 是否允许认领(is_vulnerable 标志)。如 Zendesk 悬空但不可注册 → High 确认悬空、
        # is_vulnerable=False 如实标注不可利用,且不进 vulnerable_count。
        if cname_provider.is_vulnerable:
            verdict = (
                "This provider allows claiming the dangling resource, so it is likely "
                "takeoverable. Verify and reclaim/remove the dangling DNS record."
            )
        else:
            verdict = (
                "This provider does NOT allow claiming the dangling resource (edge case "
                "or closed platform), so it is a confirmed dangling record but not "
                "directly takeoverable. Manual review recommended."
            )
        return TakeoverFinding(
            domain=domain,
            cname_chain=cname_chain,
            matched_provider=cname_provider.name,
            matched_fingerprint=body_provider.fingerprint_label,
            is_vulnerable=cname_provider.is_vulnerable,
            confidence=CONF_HIGH,
            status_code=status_code,
            evidence=(
                f"CNAME points to {cname_provider.name} "
                f"({' -> '.join(cname_chain)}) and the page body matches its dangling "
                f"fingerprint ('{body_provider.fingerprint_label}'), confirming the "
                f"backing resource is unclaimed. {verdict}"
            ),
        )

    # ---------- Low:仅 CNAME 指向托管商,正文未确认悬空 ----------
    if cname_provider is not None:
        return TakeoverFinding(
            domain=domain,
            cname_chain=cname_chain,
            matched_provider=cname_provider.name,
            matched_fingerprint=None,
            is_vulnerable=False,
            confidence=CONF_LOW,
            status_code=status_code,
            evidence=(
                f"CNAME points to {cname_provider.name} "
                f"({' -> '.join(cname_chain)}), but the page body shows no dangling "
                "fingerprint, so the backing resource may still be in use. Manual review "
                "recommended: confirm the resource is actively owned."
            ),
        )

    # ---------- Low:仅正文疑似悬空,无 CNAME 佐证 ----------
    if body_provider is not None:
        return TakeoverFinding(
            domain=domain,
            cname_chain=cname_chain,
            matched_provider=None,
            matched_fingerprint=body_provider.fingerprint_label,
            is_vulnerable=False,
            confidence=CONF_LOW,
            status_code=status_code,
            evidence=(
                f"The page body matches a dangling fingerprint "
                f"('{body_provider.fingerprint_label}'), but no CNAME to a known provider "
                "was found. Manual review recommended: this may be a takeover or a benign "
                "error page."
            ),
        )

    # ---------- 非接管:两信号皆无 → 不生成 finding(降噪) ----------
    # findings 只应列出"有接管信号"的子域(High 双命中,或 Low 单信号供人工复核)。
    # 完全无信号的子域若也生成一条 confidence=Low 的 finding,超大域会吐出数百条
    # "No takeover signal" 垃圾,淹没真正的接管命中。故无信号直接返回 None,上层过滤。
    return None


async def _resolve_one_cname(
    subdomain: str,
    resolver,
    sem: asyncio.Semaphore,
    s: Settings,
) -> Tuple[str, List[str]]:
    """仅解析单个子域的 CNAME 链(不做判定),返回 (subdomain, cname_chain)。

    把"慢的 DNS IO(CNAME 扇出)"与"快的正文指纹判定(纯 CPU)"解耦:
    CNAME 扇出只依赖子域列表,可与探活(HTTP)/审计(DNS)三支线 asyncio.gather 并发;
    判定留到探活正文就绪后再串行跑(纯 CPU,墙钟可忽略)。单目标异常隔离,不外溢
    (gather return_exceptions 兜底,这里再吞一层保险)。"""
    async with sem:
        # 单目标域速率收敛:发出前小随机抖动,打散整批扇出的突发特征
        await asyncio.sleep(random.uniform(0, s.PER_TARGET_JITTER_SECONDS))
        try:
            cname_chain = await _query_cname_chain(resolver, subdomain, s)
        except Exception:  # noqa: BLE001 - 单目标 DNS 异常不影响其他子域
            cname_chain = []
        return subdomain, cname_chain


@dataclass
class CnameFanout:
    """CNAME 扇出阶段的中间产出:每个目标子域的 CNAME 链映射 + 统计信息。

    与最终 TakeoverReport 分离,是因为扇出(慢 DNS IO)必须与探活(HTTP)/审计(DNS)
    三支线 asyncio.gather 并发,而最终聚合(正文指纹匹配,纯 CPU)要等探活正文
    就绪后才能做。这个 dataclass 承载两者之间的交接,也天然契合 Phase 2 异步
    作业模型(扇出在后台 job 里跑,聚合在轮询/回调里跑)。

    chains 含"每个成功解析的目标子域 → CNAME 链(可能为空)";解析失败(超时被
    取消)的目标不进 chains,由 checked 如实反映实际覆盖数。
    """

    chains: Dict[str, List[str]]
    total_discovered: int
    checked: int
    truncated: bool


async def fanout_cname(
    main_domain: str,
    subdomains: List[str],
    s: Settings,
) -> CnameFanout:
    """Ultra 扇出阶段(异步):对全子域并发解析 CNAME 链,不做判定。

    与 audit_service.audit_email_security_full 同构的并发/隔离骨架。
    只依赖子域列表,可与 probe_liveness_with_bodies(HTTP)与审计(DNS)三支线
    asyncio.gather 并发 —— 接管真正新增的成本只有这段 DNS 扇出。
    """
    # 目标子域 = 发现的子域去掉主域自身,去重后。total_discovered 记录截断前真实发现数
    seen: set[str] = set()
    discovered: List[str] = []
    for d in subdomains:
        if d == main_domain or d in seen:
            continue
        seen.add(d)
        discovered.append(d)
    total_discovered = len(discovered)
    # 超大域截断:只检测前 N 个。截断本身就让 takeover_complete=False(如实透明)
    targets = discovered[: s.ULTRA_MAX_TAKEOVER_TARGETS]
    truncated = len(targets) < total_discovered

    chains: Dict[str, List[str]] = {}
    if targets:
        resolver = _build_takeover_resolver(s)
        # 动态收敛并发:子域少就少开,绝不超上限
        concurrency = min(len(targets), s.TAKEOVER_CONCURRENCY_CAP)
        sem = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(_resolve_one_cname(d, resolver, sem, s))
            for d in targets
        ]
        # 等全部 CNAME 扇出跑完(单条 DNS 超时由 TAKEOVER_DNS_TIMEOUT_SECONDS 约束,
        # 本地自部署不再设整体墙钟截止)。
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                continue
            d, chain = res
            chains[d] = chain

    return CnameFanout(
        chains=chains,
        total_discovered=total_discovered,
        checked=len(chains),
        truncated=truncated,
    )


def assemble_takeover(
    fanout: CnameFanout,
    probe_bodies: Dict[str, Tuple[Optional[int], Optional[str]]],
    s: Settings,
) -> TakeoverReport:
    """Ultra 聚合阶段(纯 CPU,零 IO):CNAME 扇出结果 × 探活正文交叉判定,产出报告。

    必须等 probe_liveness_with_bodies 拿到正文后才能调(依赖 probe_bodies),但本身
    只做字符串/正则匹配,墙钟可忽略 —— 故放在三支线 gather 之后串行执行,不影响整体
    耗时(仍为 discover + max(probe, audit, cname_fanout))。

    无信号的子域不生成 finding(降噪);findings 只含有接管信号(High 双命中 +
    Low 单信号供人工复核)。vulnerable_count 只算 is_vulnerable=True(High)。
    """
    findings: List[TakeoverFinding] = []
    # 按 domain 升序遍历(升序要求见 schema),对每个成功解析的子域做交叉判定
    for d in sorted(fanout.chains):
        status_code, body = probe_bodies.get(d, (None, None))
        finding = _analyze_takeover(d, fanout.chains[d], status_code, body)
        if finding is not None:
            findings.append(finding)

    # vulnerable_count 只算 High-confidence(is_vulnerable=True),Low 级单信号不计入
    vulnerable_count = sum(1 for f in findings if f.is_vulnerable)

    # 完整性:被截断(超大域只检测前 N 个)即为不完整
    takeover_complete = not fanout.truncated

    # 完整性说明:截断(子域数 > 上限)时显式标出 cap 与跳过数;完整时也标出 cap,
    # 让「接管检测上限」在结果里稳定可见,而非只在截断时才出现。
    cap = s.ULTRA_MAX_TAKEOVER_TARGETS
    if takeover_complete:
        takeover_note = f"Full coverage: checked all {fanout.total_discovered} subdomains (cap {cap})."
    else:
        takeover_note = (
            f"Partial coverage: cap {cap} subdomains — checked {fanout.checked} of "
            f"{fanout.total_discovered} ({fanout.total_discovered - cap} skipped). "
            "Raise the cap or re-query for full coverage."
        )

    return TakeoverReport(
        total_discovered=fanout.total_discovered,
        total_checked=fanout.checked,
        vulnerable_count=vulnerable_count,
        takeover_complete=takeover_complete,
        takeover_note=takeover_note,
        findings=findings,
    )
