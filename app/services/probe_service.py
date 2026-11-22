"""高并发资产探活 —— Pro 计划核心之一。

Basic 只做被动发现(子域名/资产存在过),但"存在过"不等于"现在活着"。
Pro 对发现的每个子域名真实发起 HTTP 请求,确认哪些当下可访问,并抓取指纹。

设计要点:
  - 全 asyncio 协程,单个 httpx.AsyncClient 复用连接池。
  - 并发用 asyncio.Semaphore 限流。并发数动态收敛:实际 = min(目标数, 上限 120),
    小域名不空转开满信号量,大域名也绝不超 120,避免打爆本机 fd / 上游 WAF。
  - follow_redirects=False:手动记录 301/302 的 Location,把跳转链路暴露给红队
    (跳转常泄露内网域名 / 真实后端 / 登录入口),而非被 httpx 静默吞掉。
  - 状态码白名单过滤:只有白名单内(默认含 200/301/302 + 401/403)才进 live_assets。
    401/403 = "有服务但需授权",在 ASM/红队里是高价值打点,刻意保留。
  - 每目标同时探 https 与 http:https 优先,失败再退 http。抓 status/title/server/len。
  - 单目标失败(超时/连不上/TLS 错)完全隔离,不影响其他目标,不抛到上层。
"""

import asyncio
import random
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import httpx

from app.core.config import Settings
from app.schemas.scan import LiveAsset
from app.services import headers_service, tls_service

# 从 HTML 里抠 <title>,尽量宽松(跨行、大小写、属性)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
# title 最大保留长度,防止畸形页面塞爆响应
_TITLE_MAX_LEN = 200

# 探活 UA 池:随机挑选主流真实浏览器 UA,而非暴露自研工具标识。
# 原因:自定义 UA(如 ReconifyX/asm-probe)极易被目标 WAF 识别并封禁本机 IP,
# 影响后续所有用户的探活。用真实浏览器 UA 降低被拦概率、贴近真实访问流量。
_USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome / Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]


def _random_ua() -> str:
    """从真实浏览器 UA 池随机取一个。每个目标独立随机,进一步分散指纹。"""
    return random.choice(_USER_AGENTS)


def _extract_title(body: str) -> Optional[str]:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    if not title:
        return None
    return title[:_TITLE_MAX_LEN]


def _header_int(headers, name: str) -> Optional[int]:
    """取一个整数型响应头(Content-Length);缺失或非数字返回 None。"""
    raw = headers.get(name)
    if raw and raw.strip().isdigit():
        return int(raw)
    return None


@dataclass
class ProbeOutcome:
    """单主机探活的完整产出。

    Pro 只关心 live_asset(命中白名单才非 None);Ultra 额外需要 body 做接管指纹匹配,
    且接管指纹的最强信号恰恰在 404/500 等非白名单状态码上(NoSuchBucket / "No such app"),
    故当 collect_body=True 时,即便状态码不在白名单,也把 (status_code, body) 抓回来。

    - live_asset: 命中 PROBE_LIVE_STATUS_CODES 才有;否则 None(不进 Pro 的 live_assets)。
    - host / status_code / body: 只要拿到任一 scheme 的 HTTP 响应就填充(collect_body=True 时),
      供 Ultra 侧按 host 取正文做指纹匹配。全 scheme 都连不上时 status_code=None、body=None。
    """

    host: str
    live_asset: Optional[LiveAsset] = None
    status_code: Optional[int] = None
    body: Optional[str] = None


async def _fetch_capped(
    client: httpx.AsyncClient,
    url: str,
    headers: Dict[str, str],
    s: Settings,
) -> Tuple[int, "httpx.Headers", str, int]:
    """发一次 GET,但**最多只读 PROBE_READ_MAX_BYTES 字节**就断开。

    为什么必须流式读:
      旧实现用 `client.get()` 把整个响应体收进内存后才 `resp.text[:8192]` 切片。
      一个 20 MiB 的畸形/恶意页面会被完整下载(实测单目标 20 MiB ≈ 8000ms),
      1000 个目标就是 GB 级流量与内存峰值,而真正用到的只有开头几 KB。
      这里读到上限立即停止迭代并关闭连接,把"单目标成本"钉死在一个常量。

    返回 (状态码, 响应头, 解码后的正文, 实际读取字节数)。
    """
    max_bytes = s.PROBE_READ_MAX_BYTES
    async with client.stream(
        "GET", url, headers=headers, timeout=s.PROBE_TIMEOUT_SECONDS
    ) as resp:
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            buf.extend(chunk)
            if len(buf) >= max_bytes:
                del buf[max_bytes:]
                break
        # 编码优先用响应头里的 charset,缺失则按 utf-8 宽松解码(errors=replace
        # 保证畸形字节不会把整条探活炸掉)。标签名/接管指纹都是 ASCII,够用。
        encoding = getattr(resp, "charset_encoding", None) or "utf-8"
        try:
            text = bytes(buf).decode(encoding, errors="replace")
        except LookupError:  # 未知 charset 名
            text = bytes(buf).decode("utf-8", errors="replace")
        return resp.status_code, resp.headers, text, len(buf)


async def _probe_one(
    client: httpx.AsyncClient,
    host: str,
    sem: asyncio.Semaphore,
    s: Settings,
    collect_body: bool = False,
) -> ProbeOutcome:
    """探活单个主机:https 优先,失败退 http。命中白名单状态码填充 live_asset。

    collect_body=True(Ultra)时额外抓正文:即便状态码不在白名单也保留 (status_code, body),
    截断到 s.TAKEOVER_BODY_MAX_CHARS,供接管指纹匹配。Pro 默认 False,行为与改造前一致。
    """
    async with sem:
        # 每个目标独立随机 UA:同一批探活里不同主机呈现不同浏览器指纹,
        # 避免整批请求同一 UA 被上游按特征批量识别。
        req_headers = {"User-Agent": _random_ua()}
        # 单目标域速率收敛:发出前小随机抖动,打散整批探活的突发特征,
        # 降低上游 WAF 因瞬时爆量限速 / 封禁本机 IP 的概率。
        await asyncio.sleep(random.uniform(0, s.PER_TARGET_JITTER_SECONDS))
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                # 外层总闸:httpx 的 timeout 是"单次读"超时,持续滴水的服务端
                # 能让一个目标长期占住并发槽位,这里再按整体墙钟兜一刀。
                status, resp_headers, text, read_bytes = await asyncio.wait_for(
                    _fetch_capped(client, url, req_headers, s),
                    timeout=s.PROBE_OVERALL_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                continue  # 该 scheme 超时,换下一个
            except (httpx.HTTPError, OSError):
                # 该 scheme 连不上/协议错/TLS 错,换下一个 scheme
                continue
            except Exception:  # noqa: BLE001 - 兜底,单目标异常不外溢
                continue

            # 拿到任一响应即抓正文(仅 Ultra),已在上限处截断。
            # 无论状态码是否白名单都抓 —— 接管指纹的最强信号常在 404/500 上。
            body: Optional[str] = text[: s.TAKEOVER_BODY_MAX_CHARS] if collect_body else None

            if status not in s.PROBE_LIVE_STATUS_CODES:
                # 有响应但不在白名单(如 404/500):算探到了,不再试另一个 scheme,直接判死。
                # 但正文已抓(collect_body 时),连同状态码带回供接管指纹匹配。
                return ProbeOutcome(
                    host=host, live_asset=None, status_code=status, body=body
                )

            # 命中白名单:抓指纹
            title = None
            # 3xx 通常无 body,只有 2xx/4xx 才值得解析 title
            if status == 200 or status in (401, 403):
                title = _extract_title(text)
            redirect_to = resp_headers.get("location") if status in (301, 302) else None

            # 字节数优先用 Content-Length 头;缺失时仅在"确实读到了完整响应"的情况下
            # 用实读字节数兜底 —— 被上限截断时上报截断值会误导调用方。
            content_length = _header_int(resp_headers, "content-length")
            if content_length is None and read_bytes < s.PROBE_READ_MAX_BYTES:
                content_length = read_bytes

            # 安全响应头评估:纯 CPU,复用已经拿到的响应头,零额外网络成本
            security = None
            if s.SECURITY_HEADERS_ENABLED:
                try:
                    cookies = resp_headers.get_list("set-cookie")
                except Exception:  # noqa: BLE001 - 非 httpx.Headers 实现时降级
                    cookies = ()
                security = headers_service.analyze(url, resp_headers, s, cookies)

            live_asset = LiveAsset(
                url=url,
                host=host,
                status_code=status,
                title=title,
                server=resp_headers.get("server"),
                content_length=content_length,
                content_type=resp_headers.get("content-type"),
                redirect_to=redirect_to,
                security=security,
            )
            return ProbeOutcome(
                host=host,
                live_asset=live_asset,
                status_code=status,
                body=body,
            )
        # https、http 都没连上
        return ProbeOutcome(host=host, live_asset=None, status_code=None, body=None)


async def _probe_batch(
    hosts: List[str], s: Settings, collect_body: bool
) -> Tuple[List[LiveAsset], Dict[str, Tuple[Optional[int], Optional[str]]], bool]:
    """共享探活内核:并发探活一批主机。

    返回 (存活资产按 url 升序, 正文映射 {host: (status_code, body)}, probe_complete)。
    正文映射仅在 collect_body=True 时填充(Ultra 用),且只收有 HTTP 响应的主机。

    并发数动态收敛为 min(目标数, PROBE_CONCURRENCY_CAP);超大域名截断到
    PRO_MAX_PROBE_TARGETS,兜底防止单请求被拖垮,截断发生时 probe_complete=False。
    单条探活超时由 PROBE_TIMEOUT_SECONDS 约束,本地自部署不再设整体墙钟截止。

    存活资产在返回前还会被补上两样"顺手的"情报(都是零额外 HTTP 成本或强收敛后的):
      - security:安全响应头评估,纯 CPU,直接用已经拿到的响应头;
      - tls:TLS 证书情报,对 https 存活资产额外握一次手(受上限截断)。
    """
    if not hosts:
        return [], {}, True

    # 兜底:超大域名只探前 N 个(已去重升序,子域名列表本身有序)
    targets = hosts[: s.PRO_MAX_PROBE_TARGETS]
    truncated = len(targets) < len(hosts)

    # 动态收敛并发:目标少就少开,绝不超上限
    concurrency = min(len(targets), s.PROBE_CONCURRENCY_CAP)
    sem = asyncio.Semaphore(concurrency)

    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=concurrency,
    )
    live: List[LiveAsset] = []
    bodies: Dict[str, Tuple[Optional[int], Optional[str]]] = {}
    # 不再设 client 级固定 UA:UA 改为每个请求在 _probe_one 里独立随机注入,
    # 分散指纹,避免整批探活用同一标识被 WAF 批量封禁。
    # follow_redirects=False:手动记录跳转,暴露 3xx 链路
    async with httpx.AsyncClient(
        follow_redirects=False,
        limits=limits,
        verify=False,  # ASM 探活面对大量自签/过期证书,不能因 TLS 校验失败漏报存活
    ) as client:
        tasks = [
            asyncio.create_task(_probe_one(client, host, sem, s, collect_body))
            for host in targets
        ]
        # 等全部探活跑完(单条超时由 PROBE_TIMEOUT_SECONDS 约束,不再设整体墙钟截止)。
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                continue
            if not isinstance(res, ProbeOutcome):
                continue
            if res.live_asset is not None:
                live.append(res.live_asset)
            # 只有拿到 HTTP 响应(status_code 非 None)才收正文,供接管指纹匹配。
            # 全 scheme 连不上的主机不入映射,接管侧无正文信号可用。
            if collect_body and res.status_code is not None:
                bodies[res.host] = (res.status_code, res.body)

    live.sort(key=lambda a: a.url)
    # TLS 证书情报:只对 https 存活资产补一次握手(受 PROBE_TLS_MAX_TARGETS 截断)。
    # 必须放在 gather 之后:它依赖"哪些目标真的活着",而且是对存活资产的二次收敛
    # —— 通常只有几十个,成本远小于对全部目标盲握手。
    await tls_service.enrich(live, s)
    probe_complete = not truncated
    return live, bodies, probe_complete


async def probe_liveness(hosts: List[str], s: Settings) -> Tuple[List[LiveAsset], bool]:
    """Pro 入口:对一批主机名并发探活,返回 (存活资产按 url 升序, probe_complete)。

    行为与改造前完全一致 —— 只收白名单命中的 live_assets,不抓非白名单正文。
    """
    live, _bodies, probe_complete = await _probe_batch(hosts, s, collect_body=False)
    return live, probe_complete


async def probe_liveness_with_bodies(
    hosts: List[str], s: Settings
) -> Tuple[List[LiveAsset], Dict[str, Tuple[Optional[int], Optional[str]]], bool]:
    """Ultra 入口:探活并额外收集所有拿到响应的主机正文(含 404/500),供接管指纹匹配。

    返回 (存活资产按 url 升序, {host: (status_code, body)}, probe_complete)。
    live_assets 语义与 Pro 完全一致;bodies 是 Pro 丢弃、Ultra 复用的增量信号。
    """
    return await _probe_batch(hosts, s, collect_body=True)
