"""端口绑定:不能有 check-then-bind 竞态,显式端口与自动退让的语义必须分开。"""

import socket

import pytest

from app.core.net import bind_or_explain, pick_socket, try_bind


def _listen(port: int = 0):
    """占住一个端口,返回 (socket, port)。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(8)
    return sock, sock.getsockname()[1]


def test_pick_socket_returns_a_listening_socket():
    sock = pick_socket("127.0.0.1", (0,))
    try:
        port = sock.getsockname()[1]
        assert port > 0
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(1.0)
            assert probe.connect_ex(("127.0.0.1", port)) == 0
        finally:
            probe.close()
    finally:
        sock.close()


def test_occupied_port_is_skipped_by_pick_socket():
    taken, port = _listen()
    try:
        assert try_bind("127.0.0.1", port) is None
        sock = pick_socket("127.0.0.1", (port, 0))
        try:
            assert sock.getsockname()[1] != port
        finally:
            sock.close()
    finally:
        taken.close()


def test_explicit_port_is_honoured():
    sock, port = _listen()
    sock.close()  # 空出来了
    got = bind_or_explain("127.0.0.1", port)
    try:
        assert got.getsockname()[1] == port
    finally:
        got.close()


def test_explicit_port_is_never_silently_replaced():
    """`--port 9000` 被占用时必须报错,不能悄悄换端口让用户对着错地址调试。"""
    taken, port = _listen()
    try:
        with pytest.raises(OSError) as excinfo:
            bind_or_explain("127.0.0.1", port)
        assert str(port) in str(excinfo.value)
        assert "in use" in str(excinfo.value)
    finally:
        taken.close()


def test_implicit_port_falls_back():
    """没指定端口时"起得来"优先,依次退让。"""
    taken, port = _listen()
    try:
        sock = bind_or_explain("127.0.0.1", None, (port, 0))
        try:
            assert sock.getsockname()[1] != port
        finally:
            sock.close()
    finally:
        taken.close()


def test_bind_or_explain_rejects_all_ports_in_use():
    socks = []
    try:
        for _ in range(2):
            socks.append(_listen()[0])
        ports = [s.getsockname()[1] for s in socks]
        with pytest.raises(OSError):
            bind_or_explain("127.0.0.1", ports[0])
    finally:
        for s in socks:
            s.close()
