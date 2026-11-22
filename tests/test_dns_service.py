"""DNS 情报的记录渲染(dns_service._format / has_null_mx)。

为什么要单测:这些字符串会直接进 JSON、CSV、MD 和服务端响应,
"人能读"和"机器能再解析"两个要求同时压在上面,一旦格式走样很难在
集成测试里发现(集成测试只看域名列表)。
"""

from app.services.dns_service import _format, _truncate


class _Rdata:
    """最小化的 dnspython rdata 替身(只带被测字段)。"""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_mx_keeps_preference_and_strips_trailing_dot():
    rdata = _Rdata(preference=10, exchange="mail.example.com.")
    assert _format(rdata, "MX") == "10 mail.example.com"


def test_null_mx_is_not_rendered_as_bare_zero():
    """RFC 7505:`MX 0 .` 曾被渲染成 "0",看着像"没有 MX 记录"。"""
    rdata = _Rdata(preference=0, exchange=".")
    assert _format(rdata, "MX") == "0 ."


def test_mx_preference_zero_with_real_host():
    rdata = _Rdata(preference=0, exchange="mx.example.com.")
    assert _format(rdata, "MX") == "0 mx.example.com"


def test_ns_strips_trailing_dot():
    assert _format(_Rdata(target="ns1.example.com."), "NS") == "ns1.example.com"


def test_txt_joins_character_strings():
    """长 TXT 会被拆成多个 255 字节的 character-string,必须拼回一条。"""
    rdata = _Rdata(strings=[b"v=spf1 ", b"include:_spf.example.com ~all"])
    assert _format(rdata, "TXT") == "v=spf1 include:_spf.example.com ~all"


def test_caa_decodes_bytes():
    rdata = _Rdata(flags=0, tag=b"issue", value=b"letsencrypt.org")
    assert _format(rdata, "CAA") == "0 issue letsencrypt.org"


def test_soa_summary_is_parseable():
    rdata = _Rdata(
        mname="ns1.example.com.",
        rname="hostmaster.example.com.",
        serial=2024010101,
        refresh=7200,
        retry=3600,
        expire=1209600,
        minimum=300,
    )
    out = _format(rdata, "SOA")
    assert out.startswith("ns1.example.com hostmaster.example.com ")
    for part in ("serial=2024010101", "refresh=7200", "minimum=300"):
        assert part in out


class _Settings:
    """_truncate 只读 DNS_MAX_RECORD_CHARS 这一个配置项。"""

    DNS_MAX_RECORD_CHARS = 32


def test_truncate_caps_long_values():
    assert len(_truncate("x" * 5000, _Settings())) <= 32
    assert _truncate("short", _Settings()) == "short"


def test_truncate_uses_settings_budget():
    squeezed = _truncate("y" * 500, _Settings())
    assert len(squeezed) <= 32
