"""域名归一化与合法性校验 —— 所有外部输入的域名都必须先过这一层。

为什么单独成层,而不是各调用点自己写正则:

  1. 域名会进入**缓存键**(main._plan_cache_key)。若不校验,`pro::example.com`
     这个"域名"在 Basic 计划下生成的缓存键,恰好等于 example.com 在 Pro 计划下
     的缓存键 —— 两种不同的数据结构互相覆盖,读取方会拿到错误类型。
  2. 域名会进入**结果文件名**(main._save_result)。若含 `..` / 路径分隔符,
     落盘时会穿越出 res/ 目录,写到项目之外。
  3. 域名会被拼进 **DNS 查询**与 **HTTP URL**。含空格/斜杠/通配符的值会让
     下游解析器产生无意义请求,甚至把整条 URL 拼成意外的主机。

规则(对齐 RFC 1123 的主机名语法,只接受能作为扫描目标的 FQDN):

  - 只允许 ASCII 字母、数字、连字符;标签 1-63 字符,首尾不得为连字符;
  - 至少两个标签(必须有后缀),总长 <= 253;
  - 拒绝下划线、空格、斜杠、冒号、通配符 `*` 等字符。

为了容错,允许用户粘贴带协议的完整 URL(`https://example.com/path`)或带尾点
的域名(`example.com.`):先抽取主机部分再校验。抽取后仍不合法的,一律拒绝,
不做"猜一个近似值"的静默修正 —— 猜错会扫到别人的资产。
"""

import re

# FQDN 语法:必须 >= 2 个标签,每个标签 1-63 字符,不允许首尾连字符。
# 用 fullmatch 语义(见 is_fqdn),不依赖调用方加锚点。
FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

# 带协议的输入(用户从浏览器地址栏直接粘贴):只取 authority 部分。
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def is_fqdn(value: str) -> bool:
    """判断一个已归一化的字符串是否为合法 FQDN(不抽取、不修正)。"""
    return bool(value) and FQDN_RE.fullmatch(value) is not None


def normalize_domain(raw: str) -> str:
    """归一化并校验输入域名;不合法时抛 ValueError(由上层转成 422/400)。

    归一化步骤:去空白 → 小写 → 剥协议 → 剥 userinfo/端口/路径 → 去尾点。
    任何一步之后仍不符合 FQDN 语法的,直接拒绝。
    """
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("domain is empty")

    # 允许粘贴 "https://user@host:8443/path" 这种完整 URL:只保留 host
    if _SCHEME_RE.match(value):
        value = value.split("://", 1)[1]
        value = value.split("/", 1)[0]
        value = value.rsplit("@", 1)[-1]
        if ":" in value:  # 不是 IPv6 场景,FQDN 里冒号只可能是端口
            value = value.split(":", 1)[0]

    value = value.rstrip(".")

    if not is_fqdn(value):
        raise ValueError(
            f"invalid domain {raw!r}: expected a bare FQDN like 'example.com' "
            "(letters/digits/hyphens, at least two labels)"
        )
    return value
