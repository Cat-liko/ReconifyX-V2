"""TLS 证书情报 —— 对存活 https 端点做握手,取证书与协商参数。

为什么值得做
------------
ASM 里最容易演变成"真实事故"的往往是证书问题,而不是漏洞:

  - 证书过期 → 用户浏览器全量告警,业务侧却常常最后才知道;
  - 自签 / 私发证书 → 内部服务被误暴露到公网,或中间人代理留下的痕迹;
  - 域名不匹配 → 证书是给别的域签的,通常是配置复制粘贴;
  - 剩余天数很少 → 续期链路(ACME 自动签发 / certbot 定时任务)已经坏了。

这些都能"握手即可得",却完全无法从 HTTP 响应头看出来 —— 所以必须真的握一次手。

两次握手,一次为"能不能被浏览器接受",一次为"那到底是一张什么证书"
--------------------------------------------------------------------
1. 先按**正常浏览器的规则**验证(域名匹配 + 有效期 + 信任链)。
   成功 → ``getpeercert()`` 给出完整证书字典,字段齐全。
2. 只有验证**失败**时才做第二次不验证身份的握手,只为把证书的 DER 取出来解析。
   为什么必须这样:CPython 在 ``verify_mode=CERT_NONE`` 下 ``getpeercert()`` 返回空
   字典 —— 恰恰是"证书有问题"这种最需要看细节的场景,拿不到任何字段。
   第二次握手的成本只在异常路径上付(正常站点仍是单次握手)。

   解析 DER 用两条路,都失败就如实只报错误原因:
     a) 装了 ``cryptography`` 就用它(可选依赖,装了更准);
     b) 否则用 CPython 内置的 ``ssl._ssl._test_decode_cert``(私有但存在多年,
        官方测试自己也在用;必须用 PEM,所以先 ``DER_cert_to_PEM_cert``)。

信任库的选择
------------
``ssl.create_default_context()`` 在部分 Linux 容器里拿不到任何根证书(镜像没装
ca-certificates),表现为"所有站点都验证失败"。所以优先用 ``certifi`` 的 CA 包
(它本来就是 httpx 的传递依赖),再退回系统信任库;用户也可以用 ``TLS_CA_BUNDLE``
指定企业代理的根证书。
"""

import asyncio
import os
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from app.core.config import Settings
from app.schemas.scan import LiveAsset, TlsInfo

# certifi 路径缓存:None=还没解析过,False=解析过但没有
_CERTIFI_PATH: Any = None


def _certifi_bundle() -> Optional[str]:
    """返回 certifi 的 CA 包路径(不可用则 None)。只解析一次。"""
    global _CERTIFI_PATH
    if _CERTIFI_PATH is None:
        try:
            import certifi  # 本地导入:它只是可选优化,不是硬依赖

            path = certifi.where()
            _CERTIFI_PATH = path if (path and os.path.isfile(path)) else False
        except Exception:  # noqa: BLE001 - 没装 certifi 就退回系统信任库
            _CERTIFI_PATH = False
    return _CERTIFI_PATH or None


def _context(s: Settings, verify: bool) -> ssl.SSLContext:
    """构造握手用的 SSLContext。

    verify=True  → 按浏览器规则验证,CA 依次尝试 TLS_CA_BUNDLE → certifi → 系统库;
    verify=False → 不验证(只用于异常路径上取证书原文)。
    """
    cafile = s.TLS_CA_BUNDLE or _certifi_bundle()
    if verify:
        try:
            ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        except (OSError, ssl.SSLError):
            # 指定的 CA 包读不了(路径写错 / 文件损坏):退回系统信任库而不是直接失败
            ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _verification_reason(exc: ssl.SSLCertVerificationError) -> str:
    """从验证异常里取一句人能读的原因(CPython 3.8+ 提供 verify_message)。"""
    msg = getattr(exc, "verify_message", "") or ""
    if not msg:
        msg = str(exc)
    return msg or "certificate verification failed"


async def _open(host: str, port: int, ctx: ssl.SSLContext, s: Settings):
    """建立 TLS 连接并返回 SSLObject(调用方负责关闭 writer)。"""
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        timeout=s.TLS_TIMEOUT_SECONDS,
    )
    sslobj = writer.get_extra_info("ssl_object")
    return sslobj, writer


async def _close(writer) -> None:
    writer.close()
    try:
        # 只做握手不等数据,读到 EOF 会白等一个 RTT;wait_closed 兜底收尾
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - 对端已断开时会抛,忽略
        pass


def _decode_der(der: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """把证书 DER 解析成 getpeercert() 那种字典;两条路都失败则 None。"""
    if not der:
        return None

    # 路线 a:可选依赖 cryptography(装了更可靠)
    try:
        from cryptography import x509  # type: ignore

        cert = x509.load_der_x509_certificate(der)
        common = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = [
                ("DNS", str(name)) for name in san_ext.value.get_values_for_type(x509.DNSName)
            ]
        except Exception:  # noqa: BLE001 - 没有 SAN 扩展是合法的
            san_names = []

        # cryptography >= 42 才有 *_utc;旧版是 naive,自己补 UTC
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:  # pragma: no cover - 只影响老版本
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        def _openssl_time(value: datetime) -> str:
            # 必须与 OpenSSL 的 "Jun  1 22:56:35 2026 GMT" 格式一致:
            # ssl.cert_time_to_seconds 就是按这个格式解析的(注意日期是空格补齐)
            return f"{value:%b} {value.day:2d} {value:%H:%M:%S %Y} GMT"

        issuer_pairs = []
        if issuer_attrs:
            issuer_pairs.append(("commonName", issuer_attrs[0].value))
        if org:
            issuer_pairs.append(("organizationName", org[0].value))

        return {
            "subject": ((("commonName", common[0].value),),) if common else (),
            "issuer": tuple((pair,) for pair in issuer_pairs),
            "notBefore": _openssl_time(not_before),
            "notAfter": _openssl_time(not_after),
            "subjectAltName": tuple(san_names),
        }
    except Exception:  # noqa: BLE001 - 没装 / 版本不匹配 / 解析失败都走路线 b
        pass

    # 路线 b:CPython 内置解码器(私有 API,失败就放弃)
    path = ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _name_field(rdns, key: str) -> Optional[str]:
    """从 ``((('commonName','x'),), ...)`` 这种结构里取第一个匹配的字段。"""
    if not rdns:
        return None
    for group in rdns:
        for pair in group:
            if isinstance(pair, tuple) and len(pair) == 2 and pair[0] == key:
                return pair[1]
    return None


def _cert_time_iso(raw) -> Optional[str]:
    if not raw:
        return None
    try:
        epoch = ssl.cert_time_to_seconds(raw)
    except (ValueError, TypeError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_left(not_after: Optional[str]) -> Optional[int]:
    """剩余天数。用 UTC 当天零点做差,避免"白天/夜里扫同一张证书得到不同天数"。"""
    if not not_after:
        return None
    try:
        epoch = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError):
        return None
    now = datetime.now(timezone.utc).timestamp()
    return int((epoch - now) // 86400)


def _build(
    host: str,
    port: int,
    cert: Optional[Dict[str, Any]],
    sslobj,
    s: Settings,
    *,
    verified: bool,
    error: Optional[str] = None,
    verification_error: Optional[str] = None,
) -> TlsInfo:
    """把证书字典 + 协商参数组装成 TlsInfo。"""
    tls_version = None
    cipher = None
    try:
        if sslobj is not None:
            tls_version = sslobj.version()
            got = sslobj.cipher()
            cipher = got[0] if got else None
    except Exception:  # noqa: BLE001
        pass

    if not cert:
        return TlsInfo(
            host=host,
            port=port,
            verified=verified,
            tls_version=tls_version,
            cipher=cipher,
            error=error or ("no peer certificate exposed" if verified else None),
            verification_error=verification_error,
        )

    subject = _name_field(cert.get("subject"), "commonName")
    issuer = _name_field(cert.get("issuer"), "commonName") or _name_field(
        cert.get("issuer"), "organizationName"
    )
    not_after = cert.get("notAfter")
    days_left = _days_left(not_after)
    expired = days_left is not None and days_left < 0

    san_count = 0
    for entry in cert.get("subjectAltName", ()) or ():
        if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS":
            san_count += 1

    return TlsInfo(
        host=host,
        port=port,
        verified=verified,
        subject=subject,
        issuer=issuer,
        not_before=_cert_time_iso(cert.get("notBefore")),
        not_after=_cert_time_iso(not_after),
        days_left=days_left,
        expired=expired,
        expiring_soon=(
            days_left is not None and not expired and days_left <= s.TLS_EXPIRY_WARN_DAYS
        ),
        self_signed=bool(subject and issuer and subject == issuer),
        san_count=san_count,
        tls_version=tls_version,
        cipher=cipher,
        error=error,
        verification_error=verification_error,
    )


async def _inspect(host: str, s: Settings, port: int = 443) -> TlsInfo:
    """一次完整探测:先按浏览器规则验证,失败再取证书原文。任何情况都返回 TlsInfo。"""
    # ---------- 1) 正常验证 ----------
    try:
        sslobj, writer = await _open(host, port, _context(s, verify=True), s)
    except asyncio.TimeoutError:
        return TlsInfo(host=host, port=port, error="timeout")
    except ssl.SSLCertVerificationError as exc:
        reason = _verification_reason(exc)
        # 落到下面的"再握一次取证书"路径
        cert = await _grab_certificate(host, port, s)
        return _build(
            host,
            port,
            cert,
            None,
            s,
            verified=False,
            error=f"certificate not trusted: {reason}",
            verification_error=reason,
        )
    except ssl.SSLError as exc:
        return TlsInfo(host=host, port=port, error=f"tls error: {type(exc).__name__}")
    except (OSError, asyncio.CancelledError):
        return TlsInfo(host=host, port=port, error="connection failed")
    except Exception:  # noqa: BLE001 - 单目标异常绝不外溢
        return TlsInfo(host=host, port=port, error="handshake failed")

    try:
        cert = sslobj.getpeercert() if sslobj is not None else None
        return _build(host, port, cert, sslobj, s, verified=True)
    finally:
        await _close(writer)


async def _grab_certificate(host: str, port: int, s: Settings) -> Optional[Dict[str, Any]]:
    """不验证身份再握一次,只为把证书 DER 拿出来解析。失败返回 None。"""
    try:
        sslobj, writer = await _open(host, port, _context(s, verify=False), s)
    except Exception:  # noqa: BLE001 - 连不上就没有证书可看
        return None
    try:
        der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None
    except Exception:  # noqa: BLE001
        der = None
    finally:
        await _close(writer)
    # 解析放到线程里:它是纯 CPU 的 ASN.1 遍历,畸形证书上可能耗时几十毫秒
    return await asyncio.to_thread(_decode_der, der)


async def inspect(host: str, s: Settings) -> TlsInfo:
    """单主机证书情报入口(带总超时兜底:握手本身已限时,这里再防解析器卡住)。"""
    try:
        # 最坏情况 = 验证握手超时 + 取证书握手超时 + 解析,所以留 2 倍余量
        return await asyncio.wait_for(
            _inspect(host, s), timeout=s.TLS_TIMEOUT_SECONDS * 2 + 1.0
        )
    except asyncio.TimeoutError:
        return TlsInfo(host=host, error="timeout")
    except Exception:  # noqa: BLE001
        return TlsInfo(host=host, error="inspection failed")


async def enrich(assets: List[LiveAsset], s: Settings) -> None:
    """给一批存活资产补上 TLS 情报(**就地修改** assets 里的元素)。

    只处理 https 资产(证书只存在于 TLS 上),并按 ``PROBE_TLS_MAX_TARGETS`` 截断:
    一次握手 ≈ 一次额外 TCP+TLS,不设上限会让超大域的扫描时间翻倍。截断后剩下的
    资产 ``asset.tls`` 保持 None,前端据此显示"—"。
    """
    if not s.PROBE_TLS_ENABLED or not assets:
        return

    targets = [a for a in assets if a.url.lower().startswith("https://")]
    if not targets:
        return
    targets = targets[: s.PROBE_TLS_MAX_TARGETS]

    hosts: List[str] = []
    for asset in targets:
        hosts.append(asset.host or (urlsplit(asset.url).hostname or ""))

    concurrency = min(len(targets), 50)
    sem = asyncio.Semaphore(concurrency)

    async def _one(asset: LiveAsset, host: str) -> None:
        if not host:
            return
        async with sem:
            asset.tls = await inspect(host, s)

    await asyncio.gather(
        *(_one(a, h) for a, h in zip(targets, hosts)), return_exceptions=True
    )
