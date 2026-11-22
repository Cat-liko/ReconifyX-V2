"""启动器:端口绑定不能有 check-then-bind 竞态,参数转发要正确。"""

import socket

import launcher


def test_pick_socket_returns_a_listening_port():
    sock = launcher.pick_socket()
    try:
        port = sock.getsockname()[1]
        assert port > 0
        # 真的在 listen:连得上
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(1.0)
            assert probe.connect_ex(("127.0.0.1", port)) == 0
        finally:
            probe.close()
    finally:
        sock.close()


def test_occupied_port_is_skipped():
    """首选端口被占时不能用同一个端口,必须换下一个 —— 这是旧实现崩掉的场景。"""
    first = launcher.pick_socket(ports=(0,))
    taken = first.getsockname()[1]
    try:
        second = launcher.pick_socket(ports=(taken, 0))
        try:
            assert second.getsockname()[1] != taken
        finally:
            second.close()
    finally:
        first.close()


def test_pick_socket_accepts_explicit_port():
    sock = launcher.pick_socket(ports=(0,))
    port = sock.getsockname()[1]
    sock.close()

    again = launcher.pick_socket(ports=(port,))
    try:
        assert again.getsockname()[1] == port
    finally:
        again.close()


def test_help_flag_is_forwarded_as_top_level(capsys):
    """`ReconifyX.exe --help` 必须打印顶层帮助,而不是 serve 的帮助。"""
    code = launcher.main(["--help"])
    assert code == 0
    out = capsys.readouterr().out
    assert "serve" in out and "scan" in out


def test_version_flag_is_forwarded_as_top_level(capsys):
    code = launcher.main(["--version"])
    assert code == 0
    assert "reconifyx" in capsys.readouterr().out.lower()


def test_bare_option_is_forwarded_as_serve(monkeypatch):
    """`ReconifyX.exe --port 9000` 等价于 `serve --port 9000`(不真的起服务)。"""
    captured = {}

    def fake_main(argv=None):
        captured["argv"] = list(argv or [])
        return 0

    monkeypatch.setattr("reconifyx.cli.main", fake_main)

    assert launcher.main(["--port", "9000"]) == 0
    assert captured["argv"] == ["serve", "--port", "9000"]


def test_subcommand_is_forwarded_verbatim(monkeypatch):
    captured = {}

    def fake_main(argv=None):
        captured["argv"] = list(argv or [])
        return 0

    monkeypatch.setattr("reconifyx.cli.main", fake_main)

    assert launcher.main(["scan", "example.com", "-p", "ultra"]) == 0
    assert captured["argv"] == ["scan", "example.com", "-p", "ultra"]
