"""探活读取上限 —— 针对"整包下载再切片"的性能回归。

旧实现用 client.get() 把整个响应体收进内存,然后只取前 8192 字符。
一个 20 MiB 的畸形页面会被完整下载(实测单目标约 8s),1000 个目标就是 GB 级
流量与内存峰值。这里用本地流式服务器量化验证:客户端实际读到的字节被钉在上限。
"""

import asyncio

import httpx
import pytest

from app.core.config import Settings
from app.services import probe_service as ps

BODY_SIZE = 16 * 1024 * 1024      # 16 MiB 的"畸形大页面"
CAP = 64 * 1024                   # 期望客户端最多读这么多
_CHUNK = b"<title>big</title>" + b"A" * (65536 - len(b"<title>big</title>"))

_state = {"written": 0}


async def _handler(reader, writer):
    """极简 HTTP 服务:先按首字节区分 TLS 握手与明文 HTTP,再持续输出大响应体。"""
    try:
        first = await reader.read(1)
        if first != b"G":
            # TLS ClientHello(0x16)之类:探活会先试 https,这里立刻关闭让它秒失败,
            # 避免测试为了等 TLS 超时白等 PROBE_TIMEOUT_SECONDS 秒。
            return
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: %d\r\n\r\n" % BODY_SIZE
        )
        written = 0
        while written < BODY_SIZE:
            writer.write(_CHUNK)
            await writer.drain()   # 客户端断开后下一次 drain 会抛异常
            written += len(_CHUNK)
            _state["written"] = written
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


@pytest.fixture
async def server():
    _state["written"] = 0
    srv = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        srv.close()
        await srv.wait_closed()


def _settings(**overrides) -> Settings:
    base = dict(
        PER_TARGET_JITTER_SECONDS=0.0,
        PROBE_TIMEOUT_SECONDS=3.0,
        PROBE_OVERALL_TIMEOUT_SECONDS=5.0,
        PROBE_READ_MAX_BYTES=CAP,
    )
    base.update(overrides)
    return Settings(**base)


async def test_probe_does_not_download_whole_body(server):
    s = _settings()
    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        outcome = await ps._probe_one(
            client, f"127.0.0.1:{server}", asyncio.Semaphore(2), s, collect_body=True
        )

    assert outcome.live_asset is not None
    assert outcome.live_asset.title == "big"
    # Content-Length 头仍然如实上报真实体积(而不是被截断后的 64 KiB)
    assert outcome.live_asset.content_length == BODY_SIZE
    # 正文只保留接管指纹需要的长度
    assert outcome.body is not None
    assert len(outcome.body) <= s.TAKEOVER_BODY_MAX_CHARS
    # 服务端远没有把 16 MiB 写完 —— 证明客户端读满上限就断开
    assert _state["written"] < BODY_SIZE // 2


async def test_fetch_capped_reads_exactly_cap(server):
    s = _settings()
    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        status, headers, text, read_bytes = await ps._fetch_capped(
            client, f"http://127.0.0.1:{server}", {}, s
        )
    assert status == 200
    assert read_bytes == CAP
    assert headers["content-length"] == str(BODY_SIZE)
    assert text.startswith("<title>big</title>")


async def test_slow_drip_is_cut_by_overall_timeout():
    """一个每 50ms 吐一个字节的服务端:httpx 的单次读超时永远不会触发,
    必须靠 PROBE_OVERALL_TIMEOUT_SECONDS 的总闸把它掐掉,否则单个目标能占住
    并发槽位数分钟。这里同时验证"取消正在流式读取的响应"不会抛异常。"""

    async def drip_handler(reader, writer):
        try:
            first = await reader.read(1)
            if first != b"G":
                return
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            await writer.drain()
            for _ in range(400):
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0.05)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    srv = await asyncio.start_server(drip_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        s = _settings(PROBE_OVERALL_TIMEOUT_SECONDS=0.5, PROBE_TIMEOUT_SECONDS=2.0)
        async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
            loop = asyncio.get_running_loop()
            started = loop.time()
            outcome = await ps._probe_one(
                client, f"127.0.0.1:{port}", asyncio.Semaphore(2), s
            )
            elapsed = loop.time() - started
    finally:
        srv.close()
        await srv.wait_closed()

    assert outcome.live_asset is None
    assert elapsed < 3.0, f"overall timeout did not cut the drip ({elapsed:.1f}s)"


async def test_small_body_is_read_fully_and_length_falls_back_to_read_bytes():
    """没有 Content-Length 头时,只有完整读完才用实读字节数兜底。"""

    async def small_handler(reader, writer):
        try:
            first = await reader.read(1)
            if first != b"G":
                return
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>ok</title>")
            await writer.drain()
        finally:
            writer.close()

    srv = await asyncio.start_server(small_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        s = _settings()
        async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
            outcome = await ps._probe_one(
                client, f"127.0.0.1:{port}", asyncio.Semaphore(2), s
            )
    finally:
        srv.close()
        await srv.wait_closed()

    assert outcome.live_asset is not None
    assert outcome.live_asset.title == "ok"
    assert outcome.live_asset.content_length == len(
        b"<title>ok</title>"
    )  # 无 CL 头 → 实读字节数
