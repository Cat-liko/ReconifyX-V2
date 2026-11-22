"""控制台编码兜底 —— 让中文在任何终端/管道下都印得出来。

为什么需要这个
--------------
Windows 上,当 stdout 不是终端(被重定向到文件、管道,或被 CI 捕获)时,
Python 用的是 **locale 编码**而不是 UTF-8:

    py -c "import sys; print(sys.stdout.encoding)"
    # 终端里直接跑:utf-8(_WindowsConsoleIO 走 WriteConsoleW,任何字符都能显示)
    # 管道/重定向:  gbk    (中文 Windows) / cp437 (英文 Windows)

后果有两个,第二个是真的会把程序打死:

1. 重定向出来的文件是 GBK 字节。GitHub、编辑器、其它脚本一律按 UTF-8 读,
   于是 ``reconifyx scan example.com > report.txt`` 得到一份乱码。
2. locale 编不出中文时直接抛 ``UnicodeEncodeError``。在英文 Windows 上,

       reconifyx --help | more

   会在打印 argparse 帮助的那一刻带着 traceback 崩掉 —— 而 --help 崩溃
   是最难辩解的一类 bug。

所以这里的策略是:

* **非终端**(管道/文件):强制 UTF-8 + ``errors="replace"``,输出永远是 UTF-8。
* **真终端**:保留控制台编码(Windows 下中文显示依赖它),只把错误策略换成
  ``errors="replace"`` —— 一个生僻字符最多变成 ``?``,绝不再抛异常。

被调用方吞掉所有异常:这里只是"尽量修好显示",shim 失败不该影响主流程。
"""

from __future__ import annotations

import sys
from typing import Any


def _reconfigure(stream: Any, *, encoding: str | None) -> None:
    """尽力重设一个文本流的编码/错误策略;不支持就地跳过。"""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    kwargs: dict[str, Any] = {"errors": "replace"}
    if encoding is not None:
        kwargs["encoding"] = encoding
        # 重定向到文件时 Python 默认是全缓冲:服务跑起来后 banner 还卡在缓冲区里,
        # 用户 `reconifyx serve > log.txt` 再 `type log.txt` 会看到空文件。
        # 改成行缓冲,长跑命令的每一行都能立刻落地。
        kwargs["line_buffering"] = True
    try:
        reconfigure(**kwargs)
    except (ValueError, OSError, AttributeError):
        # 流已关闭 / 被包装成不可重设的对象(pytest 的 capsys 等)
        pass


def ensure_safe_streams() -> None:
    """在打印任何中文之前调用一次。幂等,可重复调用。"""
    for stream in (sys.stdout, sys.stderr):
        if stream is None:  # pythonw / 已分离的控制台
            continue
        try:
            is_tty = bool(stream.isatty())
        except (AttributeError, ValueError):
            is_tty = False
        _reconfigure(stream, encoding=None if is_tty else "utf-8")
