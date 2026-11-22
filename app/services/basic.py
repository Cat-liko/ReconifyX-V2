"""Basic 探测逻辑 —— 免费被动子域名发现引擎(零成本、可无限查、带完整性信号)。

不依赖任何付费额度。并发聚合多个免费被动数据源,并把"每个源本次是否健康"
如实上报给调用方,避免"某些源被限流 → 返回 0 子域名却 HTTP 200"这种对
付费用户致命的静默失败。

数据源分层(按稳定性 / 价值):
  骨干(证书透明度,子域名覆盖最全,互为热备):
    1. crt.sh       —— 带指数退避重试(后端偶发 502/超时)
    2. CertSpotter  —— 与 crt.sh 同类,crt.sh 挂时顶上;匿名可用,配 key 限额更高
  增强(第三方中转,唯一带出 IP+端口+指纹,补齐 assets):
    3. FOFA         —— 私人中转站,挂了不影响 degraded 判定,只是 assets 退化为空

设计要点:
  - 全异步 httpx.AsyncClient,多源并发拉取(asyncio.gather)。
  - 每个源独立超时 / 失败隔离,并返回 SourceHealth(ok/count/detail)。
  - 结果统一清洗:小写、去尾点、剥通配符、归属校验、FQDN 合法性、set 去重、升序。
  - degraded 语义:任一"骨干"源失败即视为结果可能不完整。
"""

import asyncio
import json
import re
from typing import Dict, List, Set, Tuple

import httpx

from app.core.config import Settings
from app.core.domain import FQDN_RE
from app.core.publicsuffix import embedded_registrable_domain
from app.schemas.scan import AssetRecord, SourceHealth

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# 哪些源属于"骨干":骨干失败才算 degraded(增强源限流是常态,不影响完整性判断)
_BACKBONE_SOURCES = {"crt.sh", "certspotter"}


def _is_fofa_noise(h: str, domain: str, max_depth: int) -> bool:
    """FOFA 噪声判定:子域段里嵌了别人的注册域,或层级过深 → 判为拼接垃圾。

    FOFA 的 ``domain=`` 是模糊命中,会混入别人拿本域当反代/DNS 后缀拼出的脏记录
    (如 ``ai.webproxy.jd.com.example.com``)。

    判定必须"按后缀"而不是"按单个标签":
    早期实现只要任一标签命中 TLD 表就丢弃,结果把 ``cn.example.com`` /
    ``me.example.com`` / ``co.example.com`` 这类**完全合法**的子域全部误杀
    —— 单标签恰好与某 TLD 同名是极常见的命名习惯。
    现在交给 publicsuffix.embedded_registrable_domain 判:
    只有"子域段以 ``<名字>.<公共后缀>`` 结尾"才算嵌了别人的注册域,并且认识
    ``com.cn`` / ``co.uk`` 这类两标签后缀。
    """
    if not h.endswith("." + domain):
        return False  # 恰等于 domain 或非归属,交给 _is_valid_fqdn 统一裁决
    sub = h[: -(len(domain) + 1)]
    labels = sub.split(".")
    if len(labels) > max_depth:
        return True
    return bool(embedded_registrable_domain(labels))


def _clean_host(s: str) -> str:
    s = (s or "").strip().lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    return s


def _is_valid_fqdn(h: str, domain: str) -> bool:
    if not h or "*" in h:
        return False
    if not (h == domain or h.endswith("." + domain)):
        return False
    return FQDN_RE.fullmatch(h) is not None


class _SourceResult:
    """单源产出:主机名集合 + IP 映射 + 健康状态。"""

    __slots__ = ("fqdns", "ip_by_fqdn", "ip_meta", "health")

    def __init__(self, name: str):
        self.fqdns: Set[str] = set()
        self.ip_by_fqdn: Dict[str, Set[str]] = {}
        # IP → {"ports": set[int], "products": set[str]}:富资产元数据(目前仅 FOFA 提供)
        self.ip_meta: Dict[str, Dict[str, Set]] = {}
        self.health = SourceHealth(name=name, ok=False, count=0, detail="")

    def finalize(self, ok: bool, detail: str = "") -> "_SourceResult":
        self.health.ok = ok
        self.health.count = len(self.fqdns)
        self.health.detail = detail
        return self


# ---------------- 各数据源 ----------------

async def _fetch_crtsh(client: httpx.AsyncClient, domain: str, s: Settings) -> _SourceResult:
    r = _SourceResult("crt.sh")
    last_err = ""
    # crt.sh 后端偶发 502/超时,做指数退避重试
    for attempt in range(s.CRTSH_RETRIES + 1):
        try:
            resp = await client.get(
                s.CRTSH_URL,
                # deduplicate=Y:crt.sh 对同一证书会在多张日志里重复返回,
                # 让服务端先去重,显著减少传输量与下面的解析开销。
                params={"q": f"%.{domain}", "output": "json", "deduplicate": "Y"},
                timeout=s.SOURCE_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            # 超大响应(大域名动辄数十 MB)不是瞬时故障,重试也不会变小:
            # 直接判该源失败并如实上报,避免把畸形/超大 JSON 读进解析器。
            if len(resp.content) > s.SOURCE_MAX_BYTES:
                return r.finalize(
                    ok=False,
                    detail=(
                        f"response too large ({len(resp.content)} > "
                        f"{s.SOURCE_MAX_BYTES} bytes)"
                    ),
                )
            text = resp.text.strip()
            try:
                rows = resp.json()
            except json.JSONDecodeError:
                # crt.sh 偶尔返回逐行 JSON 对象
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            for row in rows:
                name_value = row.get("name_value", "") or ""
                common = row.get("common_name", "") or ""
                for raw in name_value.split("\n") + [common]:
                    h = _clean_host(raw)
                    if h:
                        r.fqdns.add(h)
            return r.finalize(ok=True)
        except Exception as exc:  # noqa: BLE001
            last_err = type(exc).__name__
            if attempt < s.CRTSH_RETRIES:
                await asyncio.sleep(s.CRTSH_RETRY_BACKOFF * (2 ** attempt))
    return r.finalize(ok=False, detail=f"failed after retries: {last_err}")


async def _fetch_certspotter(client: httpx.AsyncClient, domain: str, s: Settings) -> _SourceResult:
    r = _SourceResult("certspotter")
    try:
        headers = {}
        if s.CERTSPOTTER_TOKEN:
            headers["Authorization"] = f"Bearer {s.CERTSPOTTER_TOKEN}"
        resp = await client.get(
            s.CERTSPOTTER_URL.format(domain=domain),
            headers=headers or None,
            timeout=s.SOURCE_TIMEOUT_SECONDS,
        )
        # 429 = 匿名限额用尽,如实标记而非静默吞掉
        if resp.status_code == 429:
            return r.finalize(ok=False, detail="rate-limited (429)")
        resp.raise_for_status()
        for issuance in resp.json() or []:
            for raw in issuance.get("dns_names", []) or []:
                h = _clean_host(raw)
                if h:
                    r.fqdns.add(h)
        return r.finalize(ok=True)
    except Exception as exc:  # noqa: BLE001
        return r.finalize(ok=False, detail=type(exc).__name__)


async def _fetch_fofa(client: httpx.AsyncClient, domain: str, s: Settings) -> _SourceResult:
    """FOFA 第三方中转站:唯一能带出 IP+端口+指纹的源,用于补齐 assets。

    两步鉴权(全自动,无需手抄 cookie):
      1) 用密码 POST 解锁页,Set-Cookie 返回 mk_encrypt(有效期约 1h);
      2) 复用该 cookie POST function.php 查询,返回 extended 模式 JSON。
    结果行 7 字段:[host, ip, title, port, city, product, protocol]。
    未配置 FOFA_PASSWORD 时直接跳过(标记 skipped,不算失败)。
    """
    r = _SourceResult("fofa")
    if not s.FOFA_PASSWORD:
        return r.finalize(ok=False, detail="disabled (no password)")
    # 只对"连接层"瞬时错误退避重试(TCP 连不上/超时);中转站是三方 VPS,密集访问偶发。
    # 业务层失败(error=true / bad json)不在这里重试 —— 那是稳定故障,重试纯属浪费预算。
    last_err = ""
    for attempt in range(s.FOFA_RETRIES + 1):
        try:
            # 1) 密码换 mk_encrypt cookie(写入 client 自身的 cookie jar)
            await client.post(
                s.FOFA_UNLOCK_URL,
                data={s.FOFA_PWD_FIELD: s.FOFA_PASSWORD},
                timeout=s.SOURCE_TIMEOUT_SECONDS,
            )
            # 2) 查询:domain="example.com" 语法命中该域全部关联资产
            resp = await client.post(
                s.FOFA_QUERY_URL,
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
                data={
                    "action": "fofa_cx",
                    "fofa_yf": f'domain="{domain}"',
                    "fofa_ts": str(s.FOFA_RESULT_SIZE),
                },
                timeout=s.SOURCE_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            payload = resp.json()
            break  # 请求链路走通,跳出重试(业务层解析在循环外做)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            # 连接层瞬时错误:退避重试
            last_err = type(exc).__name__
            if attempt < s.FOFA_RETRIES:
                await asyncio.sleep(s.FOFA_RETRY_BACKOFF * (2 ** attempt))
                continue
            return r.finalize(ok=False, detail=f"connect failed after retries: {last_err}")
        except Exception as exc:  # noqa: BLE001 - 非连接层异常(如 HTTP 4xx/5xx),不重试
            return r.finalize(ok=False, detail=type(exc).__name__)
    try:
        # 中转站错误(cookie 失效/额度问题)会置 error=true,如实标记而非静默吞
        if not isinstance(payload, dict) or payload.get("error"):
            detail = "unlocked failed" if isinstance(payload, dict) else "bad json"
            return r.finalize(ok=False, detail=detail)
        for row in payload.get("results", []) or []:
            if not isinstance(row, list) or len(row) < 2:
                continue
            host_field = row[0] or ""
            ip = (row[1] or "").strip()
            port = str(row[3]).strip() if len(row) > 3 and row[3] else ""
            product = (row[5] or "").strip() if len(row) > 5 else ""
            # host 字段可能是 "sub.example.com:2053" 或带协议,剥掉端口再清洗
            host = host_field.split("//")[-1].split("/")[0].split(":")[0]
            h = _clean_host(host)
            # 去噪:模糊命中的拼接垃圾(嵌别人 TLD / 层级过深)不进 fqdn,
            # 但其 IP+端口+指纹仍有价值,照常收进 ip_meta。
            if h and not _is_fofa_noise(h, domain, s.FOFA_MAX_SUB_DEPTH):
                r.fqdns.add(h)
                if _IPV4_RE.match(ip):
                    r.ip_by_fqdn.setdefault(h, set()).add(ip)
            # 端口/指纹挂到 IP 上,补齐 assets(存到 ip_meta,discover 汇总时消费)
            if _IPV4_RE.match(ip):
                meta = r.ip_meta.setdefault(ip, {"ports": set(), "products": set()})
                if port.isdigit():
                    meta["ports"].add(int(port))
                if product:
                    meta["products"].add(product)
        return r.finalize(ok=True)
    except Exception as exc:  # noqa: BLE001
        return r.finalize(ok=False, detail=type(exc).__name__)


def _merge_ip_maps(target: Dict[str, Set[str]], src: Dict[str, Set[str]]) -> None:
    for fqdn, ips in src.items():
        target.setdefault(fqdn, set()).update(ips)


async def discover(
    domain: str, settings: Settings
) -> Tuple[List[str], List[AssetRecord], bool, List[SourceHealth]]:
    """异步入口:并发聚合免费被动源。

    核心目标:用户传入域名后,尽可能收全结果。

    所有源同时开跑、并发等待各自跑完;每个源受 SOURCE_TIMEOUT_SECONDS 单条超时约束。
    本地自部署无网关限制,不再设整体墙钟截止,慢的增强源也自然跑完。

    返回 (去重升序 FQDN 列表, 轻量资产清单, degraded, 各源健康明细)。
    degraded=True 表示所有"骨干"证书透明度源均失败,结果可能不完整。
    """
    domain = _clean_host(domain)

    headers = {"User-Agent": "ReconifyX/0.1 (+asm-discovery)"}
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        # 所有源立即并发开跑,等各自跑完(单条超时由 SOURCE_TIMEOUT_SECONDS 约束)。
        # gather(return_exceptions=True) 让单源异常不拖垮整体,结果里的 Exception 由下游兜底。
        tasks = [
            asyncio.create_task(_fetch_crtsh(client, domain, settings)),
            asyncio.create_task(_fetch_certspotter(client, domain, settings)),
            asyncio.create_task(_fetch_fofa(client, domain, settings)),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # 主干 fqdn(证书透明度 + 被动DNS,数据干净)与 FOFA fqdn 分开收集:
    # 正常路径子域名列表只用干净源;FOFA 的子域名仅在主干全空时兜底顶上,
    # 保证"绝不返回空"的同时,不让 FOFA 的模糊命中污染正常结果。
    primary_fqdns: Set[str] = set()
    fofa_fqdns: Set[str] = set()
    ip_by_fqdn: Dict[str, Set[str]] = {}
    ip_meta: Dict[str, Dict[str, Set]] = {}  # IP → {ports, products},目前仅 FOFA 填充
    health: List[SourceHealth] = []
    backbone_ok = False

    for res in results:
        if isinstance(res, Exception):
            # 兜底防止未知源崩溃
            health.append(SourceHealth(name="unknown", ok=False, detail=type(res).__name__))
            continue
        if res.health.name == "fofa":
            fofa_fqdns.update(res.fqdns)
        else:
            primary_fqdns.update(res.fqdns)
        _merge_ip_maps(ip_by_fqdn, res.ip_by_fqdn)
        for ip, meta in res.ip_meta.items():
            tgt = ip_meta.setdefault(ip, {"ports": set(), "products": set()})
            tgt["ports"].update(meta.get("ports", set()))
            tgt["products"].update(meta.get("products", set()))
        health.append(res.health)
        if res.health.name in _BACKBONE_SOURCES and res.health.ok:
            backbone_ok = True

    # 骨干源全挂 → 结果不可信,标记 degraded
    degraded = not backbone_ok

    # 归属校验 + FQDN 合法性 + 去重 + 升序(先只用干净的主干源)
    clean_fqdns = sorted({f for f in primary_fqdns if _is_valid_fqdn(f, domain)})
    # 兜底:主干一个子域都没拿到(crt.sh/CertSpotter 突发全挂)时,才把 FOFA 的
    # 子域名放进来顶上 —— 核心诉求"调用后绝不返回空"。此时结果已标 degraded。
    if not clean_fqdns:
        clean_fqdns = sorted({f for f in fofa_fqdns if _is_valid_fqdn(f, domain)})

    # 资产聚合:免费源带出的 IP → 主机名,并叠加 FOFA 的端口 / 指纹(若有)
    # 先按 IP 归并成 set,最后一次性排序:旧实现每插一条就 sorted(set(...) | {...}),
    # 在"一个 IP 挂上万个子域"的 CDN 场景下是 O(n² log n),纯 CPU 白烧。
    hostnames_by_ip: Dict[str, Set[str]] = {}
    for fqdn, ips in ip_by_fqdn.items():
        if not _is_valid_fqdn(fqdn, domain):
            continue
        for ip in ips:
            hostnames_by_ip.setdefault(ip, set()).add(fqdn)

    assets_by_ip: Dict[str, AssetRecord] = {
        ip: AssetRecord(ip=ip, hostnames=sorted(hosts))
        for ip, hosts in hostnames_by_ip.items()
    }

    # 把 FOFA 收集到的端口 / 产品指纹挂到对应 IP 资产上。
    # ip_meta 里可能有 ip_by_fqdn 未覆盖的 IP(FOFA 命中但无合法归属 FQDN),
    # 这类裸 IP 也建资产,避免丢弃有价值的端口/指纹。
    for ip, meta in ip_meta.items():
        rec = assets_by_ip.get(ip)
        if rec is None:
            rec = assets_by_ip[ip] = AssetRecord(ip=ip)
        if meta.get("ports"):
            rec.ports = sorted(set(rec.ports) | meta["ports"])
        if meta.get("products"):
            rec.products = sorted(set(rec.products) | meta["products"])

    assets = sorted(assets_by_ip.values(), key=lambda r: r.ip)
    return clean_fqdns, assets, degraded, health
