"""统一入口 —— 打包后的 ``ReconifyX.exe`` 与源码运行都走这里。

行为
----
  - 不带参数(双击 exe)        → 起本地服务 + 自动打开浏览器
  - 带子命令(scan/dns/serve/version) → 交给命令行实现
  - 带选项(如 ``--port 9000``)→ 等价于 ``serve --port 9000``

为什么把端口选择改成"直接 bind"
--------------------------------
旧实现是"先用 ``connect_ex`` 探一下端口空不空,空了再让 uvicorn 去 bind"。
这是经典的 check-then-bind 竞态:两次系统调用之间,另一个进程完全可能把端口占掉,
于是 uvicorn 抛 ``OSError: address already in use``,用户看到的是闪退。

现在改成**先自己 bind 成功,再把 socket 交给 uvicorn**(``Server.run(sockets=[sock])``)。
拿到手的就是同一个 socket,中间没有任何窗口可以被抢。四个首选端口全被占用时,
退化为让操作系统分配一个空闲端口(port 0)—— 总比直接失败好。
"""

import socket
import sys
import threading
import time
import webbrowser
from typing import List, Optional, Sequence

# 端口占用的实现放在 app/core/net.py:CLI 的 `serve` 与桌面模式共用同一套
# "先 bind 成功、再把同一个 socket 交给 uvicorn" 的逻辑,避免两边行为不一致
# (一边没有 check-then-bind 竞态、另一边有,是这次修 bug 时发现的)。
from app.core.net import PREFERRED_PORTS, pick_socket

HOST = "127.0.0.1"

#: 顶层可见的子命令(其余参数一律按 ``serve`` 处理)
CLI_COMMANDS = frozenset({"scan", "dns", "serve", "version"})

#: 顶层选项:必须原样透传,不能补 ``serve`` 前缀(argparse 的子命令解析器不认识它们)
TOP_LEVEL_FLAGS = frozenset({"-h", "--help", "--version"})


def _open_browser_when_ready(port: int, timeout: float = 20.0) -> None:
    """等端口真的能连上再开浏览器,而不是睡固定时长赌它已经起来了。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.5)
            if probe.connect_ex((HOST, port)) == 0:
                webbrowser.open(f"http://{HOST}:{port}/", new=1)
                return
        finally:
            probe.close()
        time.sleep(0.15)


def serve(open_browser: bool = True, ports: Sequence[int] = PREFERRED_PORTS) -> int:
    """起服务(阻塞直到 Ctrl+C)。返回进程退出码。"""
    import uvicorn

    from app.core.config import get_settings
    from app.main import app

    settings = get_settings()
    sock = pick_socket(HOST, ports)
    port = sock.getsockname()[1]

    print()
    print(f"  {settings.PROJECT_NAME} v{settings.VERSION}")
    print(f"  本地地址: http://{HOST}:{port}/")
    print(f"  数据目录: {settings.RESULT_DIR}/")
    print("  停止服务: Ctrl+C")
    print()

    if open_browser:
        threading.Thread(
            target=_open_browser_when_ready, args=(port,), daemon=True
        ).start()

    config = uvicorn.Config(
        app, host=HOST, port=port, log_level=settings.LOG_LEVEL, access_log=False
    )
    server = uvicorn.Server(config)
    server.run(sockets=[sock])
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """入口。返回退出码。"""
    # 桌面模式的启动横幅是中文的;先修好编码,否则英文 Windows 上
    # 重定向/管道会直接抛 UnicodeEncodeError。见 app/core/console.py
    from app.core.console import ensure_safe_streams

    ensure_safe_streams()

    args = list(sys.argv[1:] if argv is None else argv)

    # --- 子命令 / 选项:交给 CLI ---
    if args and (args[0] in CLI_COMMANDS or args[0].startswith("-")):
        from reconifyx.cli import main as cli_main

        # 顶层选项(--help/--version)原样透传;裸选项(如 --port 9000)按 serve 处理
        if args[0] in CLI_COMMANDS or args[0] in TOP_LEVEL_FLAGS:
            forwarded = args
        else:
            forwarded = ["serve"] + args
        try:
            return cli_main(forwarded)
        except SystemExit as exc:  # argparse 的 --help / --version 走这条路
            return int(exc.code or 0)

    # --- 无参数:桌面模式 ---
    try:
        return serve()
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001 - 双击 exe 时错误必须留在窗口里
        print(f"startup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        try:
            input("按回车键退出…")
        except (EOFError, KeyboardInterrupt):
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
