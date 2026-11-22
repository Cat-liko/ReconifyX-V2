"""DNS 情报 —— 主域的结构化记录(A/AAAA/NS/MX/TXT/CAA/SOA)。

为什么值得单独一层
------------------
子域名列表只回答"有哪些名字";DNS 记录回答的是**结构性问题**:

  - NS 指向谁 → 域名托管在哪个服务商手里(Cloudflare / Route53 / 某虚拟主机),
    换供应商时最容易漏掉的迁移残留就在这里;
  - CAA 缺失 → 任何公共 CA 都能给这个域签证书,配合子域接管就是现成的攻击链;
  - MX + SPF/DMARC 存在性 → 邮件身份是否成立(邮件审计拿它做交叉验证);
  - SOA → 序列号与主 NS,判断区域变更频率的第一手线索。

设计要点(与 audit_service 同构):
  - 全程 ``dns.asyncresolver`` 异步解析,绝不阻塞事件循环;
  - 单类记录失败(NXDOMAIN / NoAnswer / 超时)一律当"该类型无记录",不抛异常;
  - 所有类型并发查询,主域情报的墙钟 ≈ 一次 DNS 往返,而不是 7 次;
  - 每条记录都截断,防畸形域返回上千条 TXT 把响应体撑大。
"""

import asyncio
from typing import List, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.config import Settings
from app.schemas.scan import DnsIntel

# 单类记录查询失败时统一吞掉的异常集合(镜像 audit_service 的做法)
_DNS_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
    dns.exception.DNSException,
)


def _build_resolver(s: Settings) -> "dns.asyncresolver.Resolver":
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = s.DNS_TIMEOUT_SECONDS
    resolver.lifetime = s.DNS_TIMEOUT_SECONDS
    return resolver


def _truncate(value: str, s: Settings) -> str:
    limit = s.DNS_MAX_RECORD_CHARS
    return value if len(value) <= limit else value[: limit - 1] + "…"


async def _query(resolver, name: str, rtype: str, s: Settings) -> List[str]:
    """查一类记录并格式化成字符串列表;任何异常都返回空列表。"""
    try:
        answer = await resolver.resolve(name, rtype)
    except _DNS_ERRORS:
        return []
    except Exception:  # noqa: BLE001 - 兜底:解析器自身异常也不能污染整次扫描
        return []

    out: List[str] = []
    for rdata in answer:
        try:
            out.append(_truncate(_format(rdata, rtype), s))
        except Exception:  # noqa: BLE001 - 单条 rdata 畸形不影响其它条
            continue
        if len(out) >= s.DNS_MAX_RECORDS:
            break
    return out


def _format(rdata, rtype: str) -> str:
    """把 dnspython 的 rdata 变成人能读、也能机器再解析的一行字符串。"""
    if rtype == "NS":
        return str(getattr(rdata, "target", rdata)).rstrip(".")
    if rtype == "MX":
        pref = getattr(rdata, "preference", 0)
        exch = str(getattr(rdata, "exchange", "")).rstrip(".")
        return f"{pref} {exch}".strip()
    if rtype == "TXT":
        parts = getattr(rdata, "strings", None)
        if parts:
            return b"".join(parts).decode("utf-8", errors="replace")
        return str(rdata).strip('"')
    if rtype == "CAA":
        flags = getattr(rdata, "flags", 0)
        tag = getattr(rdata, "tag", b"")
        if isinstance(tag, bytes):
            tag = tag.decode("ascii", errors="replace")
        value = getattr(rdata, "value", b"")
        if isinstance(value, bytes):
            value = value.decode("ascii", errors="replace")
        return f"{flags} {tag} {value}".strip()
    if rtype == "SOA":
        return (
            f"{str(getattr(rdata, 'mname', '')).rstrip('.')} "
            f"{str(getattr(rdata, 'rname', '')).rstrip('.')} "
            f"serial={getattr(rdata, 'serial', '')} "
            f"refresh={getattr(rdata, 'refresh', '')} "
            f"retry={getattr(rdata, 'retry', '')} "
            f"expire={getattr(rdata, 'expire', '')} "
            f"minimum={getattr(rdata, 'minimum', '')}"
        ).strip()
    return str(rdata)


async def collect(domain: str, s: Settings) -> Optional[DnsIntel]:
    """并发拉取主域的全部记录,组装成 DnsIntel。

    任何单类记录失败都不算整体失败;只有"连解析器都起不来"才返回 error。
    返回 None 表示该功能被配置关闭。
    """
    if not s.DNS_INTEL_ENABLED:
        return None

    try:
        resolver = _build_resolver(s)
    except Exception as exc:  # noqa: BLE001 - 一个坏的 resolv.conf 不该让扫描 500
        return DnsIntel(domain=domain, error=f"resolver init failed: {type(exc).__name__}")

    # 7 类记录 + DMARC 子域 TXT,全部并发:总墙钟 ≈ 一次 DNS 往返
    a, aaaa, ns, mx, txt, caa, soa, dmarc_txt = await asyncio.gather(
        _query(resolver, domain, "A", s),
        _query(resolver, domain, "AAAA", s),
        _query(resolver, domain, "NS", s),
        _query(resolver, domain, "MX", s),
        _query(resolver, domain, "TXT", s),
        _query(resolver, domain, "CAA", s),
        _query(resolver, domain, "SOA", s),
        _query(resolver, f"_dmarc.{domain}", "TXT", s),
    )

    has_spf = any(r.lower().startswith("v=spf1") for r in txt)
    has_dmarc = any(r.lower().startswith("v=dmarc1") for r in dmarc_txt)

    # SOA 只会有一条;取第一条即可
    return DnsIntel(
        domain=domain,
        a=a,
        aaaa=aaaa,
        ns=ns,
        mx=mx,
        txt=txt,
        caa=caa,
        soa=soa[0] if soa else None,
        has_spf=has_spf,
        has_dmarc=has_dmarc,
        resolved=bool(a or aaaa),
    )
