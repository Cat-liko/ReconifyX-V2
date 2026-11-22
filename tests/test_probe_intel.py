"""探活在真实(本地)服务器上补齐 host / content_type / 安全响应头,并把正文交给接管检测。

用本地 asyncio 服务器,不依赖外网。https 会先试:服务端读到 TLS ClientHello 首字节就
直接关闭,让 https 快速失败,避免为了等 TLS 超时白等好几秒。
"""

import asyncio

from app.core.config import Settings
from app.services import probe_service as ps

BODY = b"<html><head><title>Hello Probe</title></head><body>ok</body></html>"

OK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
    b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY
)

DANGLING_BODY = b"<html><body>NoSuchBucket</body></html>"
NOTFOUND_RESPONSE = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(DANGLING_BODY)).encode() + b"\r\n\r\n" + DANGLING_BODY
)


def _make_handler(response: bytes):
    async def _handler(reader, writer):
        try:
            first = await reader.read(1)
            if first != b"G":
                return  # TLS ClientHello:直接关掉,让 https 秒失败
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            writer.write(response)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    return _handler


async def _serve(response: bytes):
    srv = await asyncio.start_server(_make_handler(response), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    return srv, f"127.0.0.1:{port}"


def _settings(**over):
    base = dict(
        PROBE_TLS_ENABLED=False,
        PER_TARGET_JITTER_SECONDS=0.0,
        PROBE_TIMEOUT_SECONDS=3.0,
        PROBE_OVERALL_TIMEOUT_SECONDS=5.0,
        PROBE_READ_MAX_BYTES=64 * 1024,
    )
    base.update(over)
    return Settings(**base)


async def test_probe_fills_host_content_type_and_header_audit():
    srv, host = await _serve(OK_RESPONSE)
    try:
        live, complete = await ps.probe_liveness([host], _settings())
    finally:
        srv.close()
        await srv.wait_closed()

    assert complete is True
    assert len(live) == 1
    asset = live[0]

    assert asset.host == host
    assert asset.status_code == 200
    assert asset.title == "Hello Probe"
    assert asset.content_type is not None and asset.content_type.startswith("text/html")

    # 安全响应头是"顺手的"情报:复用同一个响应,零额外请求
    assert asset.security is not None
    codes = {f.code for f in asset.security.findings}
    assert "CSP_MISSING" in codes  # 这个响应确实没有 CSP
    assert "XCTO_MISSING" not in codes  # 但有 nosniff
    assert asset.security.score < 100

    # 本地是明文 http,不该有 TLS 情报
    assert asset.tls is None


async def test_non_whitelisted_status_still_returns_body_for_takeover():
    """接管指纹的最强信号恰恰在 404 上,所以 Ultra 必须保留正文。"""
    srv, host = await _serve(NOTFOUND_RESPONSE)
    try:
        live, bodies, complete = await ps.probe_liveness_with_bodies([host], _settings())
    finally:
        srv.close()
        await srv.wait_closed()

    assert complete is True
    assert live == []  # 404 不在存活白名单里
    assert host in bodies
    status, body = bodies[host]
    assert status == 404
    assert body is not None and "NoSuchBucket" in body


async def test_probe_tls_enrichment_skips_http_only_assets():
    srv, host = await _serve(OK_RESPONSE)
    try:
        live, _bodies, _complete = await ps.probe_liveness_with_bodies(
            [host], _settings(PROBE_TLS_ENABLED=True)
        )
    finally:
        srv.close()
        await srv.wait_closed()

    # 开了 TLS 采集,但资产是 http,不该为它去握 443
    assert all(asset.tls is None for asset in live)


async def test_unreachable_host_yields_no_asset():
    # 端口 1 上不会有服务,连接会被迅速拒绝
    live, complete = await ps.probe_liveness(["127.0.0.1:1"], _settings())
    assert live == []
    assert complete is True


async def test_empty_input_is_handled():
    live, complete = await ps.probe_liveness([], _settings())
    assert live == []
    assert complete is True
