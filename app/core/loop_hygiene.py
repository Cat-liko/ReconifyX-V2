"""事件循环卫生 —— 只处理一个已知的 CPython Windows 噪音,不做任何业务逻辑。

``ProactorEventLoop`` 在"对端已经 RST 掉连接"时会往 stderr 打一条
``ConnectionResetError`` 的 traceback:

    Exception in callback _ProactorBasePipeTransport._call_connection_lost(None)
    ConnectionResetError: [WinError 10054] 远程主机强迫关闭了一个现有的连接。

这条日志来自 loop 内部回调(``_call_connection_lost`` 里对已断开的 socket 调
``shutdown()``),业务代码**无法**通过 try/except 捕获 —— 它不在我们的调用栈里。
而 TLS 探测天然会制造这种连接(握手完立刻关闭,很多服务端直接 RST),于是正常扫描
会刷出成片的"异常",让真正的问题被淹没。

这是 CPython 的已知问题(gh-109214)。这里装一个**只吞这一种**异常处理器:
匹配条件同时要求 ``ConnectionResetError`` 和回调名 ``_call_connection_lost``,
其他任何异常照旧走默认处理器。
"""

import asyncio
import sys
from typing import Any

_installed = False

#: 只吞这一种回调里的这种异常;别的一律放行
_IGNORED_MESSAGE_HINTS = ("_call_connection_lost", "_call_connection_lost_impl")


def quiet_windows_reset_noise() -> bool:
    """在当前事件循环上安装过滤。返回是否真的安装了(幂等)。"""
    global _installed
    if _installed or sys.platform != "win32":
        return False

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的循环(例如同步上下文)时什么也不做 —— 不能凭空造一个
        return False

    previous = loop.get_exception_handler()

    def _handler(loop_: asyncio.AbstractEventLoop, context: dict) -> None:
        exc: Any = context.get("exception")
        message = str(context.get("message", ""))
        if isinstance(exc, ConnectionResetError) and any(
            hint in message for hint in _IGNORED_MESSAGE_HINTS
        ):
            return
        if previous is not None:
            previous(loop_, context)
        else:
            loop_.default_exception_handler(context)

    loop.set_exception_handler(_handler)
    _installed = True
    return True
