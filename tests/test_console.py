"""控制台编码兜底(app/core/console.py)。

为什么值得单测
--------------
这个 shim 平时完全无感,只有在"英文 Windows + 管道"这种组合下才起作用 ——
而那恰好是 CI 和 ``| more`` 最常出现的环境。这里用假流把三种分支都钉住,
免得哪天顺手把 ``errors="replace"`` 删掉,线上就退化成 --help 崩溃。
"""

import sys

from app.core.console import ensure_safe_streams


class _FakeStream:
    """只实现 ensure_safe_streams 会碰到的两个方法。"""

    def __init__(self, tty):
        self._tty = tty
        self.calls = []

    def isatty(self):
        return self._tty

    def reconfigure(self, **kwargs):
        self.calls.append(kwargs)


class _NoReconfigure:
    """模拟被包装过、不提供 reconfigure 的流(pytest capsys、某些 IDE 控制台)。"""

    def isatty(self):
        return False

    def write(self, _text):
        return 0


class _BrokenStream:
    """reconfigure 存在但会抛:例如流已关闭。"""

    def isatty(self):
        return False

    def reconfigure(self, **_kwargs):
        raise ValueError("I/O operation on closed file")


def test_non_tty_forces_utf8(monkeypatch):
    """管道/重定向必须落成 UTF-8,否则重定向出的文件在别的工具里是乱码。"""
    out, err = _FakeStream(tty=False), _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    ensure_safe_streams()

    assert out.calls == [
        {"errors": "replace", "encoding": "utf-8", "line_buffering": True}
    ]
    assert err.calls == out.calls


def test_tty_keeps_console_encoding(monkeypatch):
    """真终端不能改成 UTF-8:Windows 控制台靠 locale 编码显示中文。"""
    out = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", _FakeStream(tty=True))

    ensure_safe_streams()

    assert out.calls == [{"errors": "replace"}]


def test_stream_without_reconfigure_is_ignored(monkeypatch):
    """没有 reconfigure 的流(测试捕获器)跳过即可,不能因此报错。"""
    monkeypatch.setattr(sys, "stdout", _NoReconfigure())
    monkeypatch.setattr(sys, "stderr", _NoReconfigure())

    ensure_safe_streams()  # 不抛异常就是通过


def test_reconfigure_failure_is_swallowed(monkeypatch):
    """流已关闭时 reconfigure 会抛 ValueError —— 显示问题是次要的,不能拖垮程序。"""
    monkeypatch.setattr(sys, "stdout", _BrokenStream())
    monkeypatch.setattr(sys, "stderr", _BrokenStream())

    ensure_safe_streams()


def test_none_streams_are_skipped(monkeypatch):
    """pythonw 下 sys.stdout 可能是 None。"""
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    ensure_safe_streams()


def test_idempotent(monkeypatch):
    out = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", _FakeStream(tty=False))

    ensure_safe_streams()
    ensure_safe_streams()

    expected = {"errors": "replace", "encoding": "utf-8", "line_buffering": True}
    assert out.calls == [expected, expected]
