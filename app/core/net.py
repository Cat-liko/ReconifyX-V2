"""端口占用 —— 先 bind 成功再把 socket 交给 uvicorn。

为什么不能"先探再用"
-------------------
旧实现是"用 ``connect_ex`` 试一下端口空不空,空了再让 uvicorn 去 bind"。
这是典型的 check-then-bind 竞态:两次系统调用之间,另一个进程(也可能是原来那个
还没退干净的自己)完全可能把端口抢走,于是 uvicorn 抛
``OSError: address already in use``,用户看到的是闪退 / 一句看不懂的堆栈。

现在的做法是**同一个 socket 走到底**:我们自己 bind + listen 成功,
再把已经 listen 的 socket 交给 ``uvicorn.Server.run(sockets=[sock])``。
拿到手的就是同一个对象,中间没有任何窗口可以被插队。

``SO_REUSEADDR`` 刻意不设:Windows 上它允许绑定到别人正在监听的端口(端口劫持),
对一个本地安全工具来说,这个"便利"是纯粹的风险。
"""

from __future__ import annotations

import socket
from typing import Optional, Sequence

#: 默认优先尝试的端口(桌面模式双击 exe 时用)
PREFERRED_PORTS = (8000, 8001, 8002, 8003)


def try_bind(host: str, port: int) -> Optional[socket.socket]:
    """尝试占住一个 socket。成功返回已 listen 的 socket,失败返回 None。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        sock.listen(128)
        return sock
    except OSError:
        sock.close()
        return None


def pick_socket(host: str = "127.0.0.1", ports: Sequence[int] = PREFERRED_PORTS) -> socket.socket:
    """按给定端口顺序占一个 socket;全都占不到时让系统随机分配(port 0)。"""
    for port in ports:
        sock = try_bind(host, port)
        if sock is not None:
            return sock
    sock = try_bind(host, 0)
    if sock is None:
        raise RuntimeError(f"cannot bind any port on {host}; check firewall/permissions")
    return sock


def bind_or_explain(
    host: str, port: Optional[int], fallback: Sequence[int] = PREFERRED_PORTS
) -> socket.socket:
    """绑定端口。``port`` 显式给出 → 占不到就抛错;未给出 → 依次退让。

    为什么要区分:
      - 用户写了 ``--port 9000``,那 9000 被占就该明确报错,而不是偷偷换一个
        端口让他对着错误的地址调试;
      - 用户没写端口,那"起得来"比"必须是 8000"重要得多,退到 8001/8002 或
        让系统随机分配都行。
    """
    if port is not None:
        sock = try_bind(host, port)
        if sock is None:
            raise OSError(
                f"port {port} on {host} is already in use; "
                "pass a different --port or stop the other process"
            )
        return sock
    return pick_socket(host, fallback)
