"""Basic 发现引擎里的纯逻辑:FOFA 噪声判定 + 归属校验。"""

import pytest

from app.services.basic import _is_fofa_noise, _is_valid_fqdn


@pytest.mark.parametrize(
    "host",
    [
        "cn.example.com",     # 单标签,恰好与 TLD 同名 —— 合法命名习惯
        "me.example.com",
        "co.example.com",
        "cc.example.com",
        "io.example.com",
        "top.example.com",
        "www.example.com",
    ],
)
def test_legit_single_label_tld_not_noise(host):
    # 旧实现是"任一标签命中 TLD 表就丢弃",把这些合法子域全误杀了
    assert _is_fofa_noise(host, "example.com", 5) is False


@pytest.mark.parametrize(
    "host",
    [
        "ai.webproxy.jd.com.example.com",     # 别人的注册域被当后缀拼出来
        "x.foo.net.example.com",
        "a.b.c.d.e.f.example.com",            # 层级过深
    ],
)
def test_embedded_registered_domain_is_noise(host):
    assert _is_fofa_noise(host, "example.com", 5) is True


def test_noise_only_applies_to_owned_hosts():
    # 不属于目标域的交给 _is_valid_fqdn 统一裁决,这里不能先判脏
    assert _is_fofa_noise("example.com", "example.com", 5) is False
    assert _is_fofa_noise("a.other.com", "example.com", 5) is False


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("example.com", True),
        ("a.example.com", True),
        ("a.b.example.com", True),
        ("badexample.com", False),           # 不是后缀归属
        ("example.com.evil.com", False),
        ("a.example.com.evil", False),
        ("*.example.com", False),
        ("", False),
        ("a_b.example.com", False),          # FQDN 不允许下划线
    ],
)
def test_ownership_and_syntax(host, ok):
    assert _is_valid_fqdn(host, "example.com") is ok
