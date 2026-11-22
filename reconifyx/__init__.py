"""ReconifyX —— 本地攻击面管理工具。

这个包只提供**命令行入口**;真正的实现都在 ``app`` 包里:

    app/main.py                 FastAPI 应用与三条扫描管线的编排
    app/services/*.py           各检测能力(发现 / DNS / 探活 / TLS / 邮件 / 接管 …)
    app/core/*.py               缓存、job 存储、历史、指标、守卫等基础设施

把 CLI 单独放一个包,是为了让 ``pip install`` 后的入口点(``reconifyx``)与
内部实现包名(``app``)解耦:``app`` 是个很通用的名字,不适合作为分发名。
"""

__all__ = ["__version__"]


def __getattr__(name: str):
    """惰性取版本号:避免 import 时就把整个 app 包拉起来。"""
    if name == "__version__":
        from app.core.config import get_settings

        return get_settings().VERSION
    raise AttributeError(name)
