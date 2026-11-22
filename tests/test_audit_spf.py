"""SPF / DMARC 判定。

重点覆盖两个曾经的漏报/误报:
  1. 裸 `all`(RFC 7208 定义其等价 +all)曾被判成 Secure —— 最危险的一类配置被漏报;
  2. 完全不含 `all` 机制的记录等价隐式 `?all`,曾被判 Secure,与显式 `?all` 的从严判定矛盾。
"""

import pytest

from app.core.config import Settings
from app.services.audit_service import (
    _all_mechanism,
    _analyze,
    _analyze_subdomain,
    _count_dns_mechanisms,
)

SETTINGS = Settings()


@pytest.mark.parametrize(
    ("record", "qualifier"),
    [
        ("v=spf1 -all", "-"),
        ("v=spf1 ~all", "~"),
        ("v=spf1 +all", "+"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 all", "+"),          # 裸 all 的默认限定符就是 +
        ("v=spf1 ip4:1.2.3.4 -all", "-"),
        ("v=spf1 include:_spf.example.com ~all", "~"),
    ],
)
def test_all_mechanism_parsing(record, qualifier):
    mech = _all_mechanism(record)
    assert mech is not None
    assert mech[0] == qualifier


def test_all_mechanism_absent():
    assert _all_mechanism("v=spf1 include:_spf.google.com") is None


@pytest.mark.parametrize("record", ["v=spf1 all", "v=spf1 +all"])
def test_bare_all_is_critical(record):
    # 裸 all 与 +all 等价:任何 IP 都能代发,必须判 Critical
    result = _analyze("example.com", [record], None, SETTINGS)
    assert result.risk_level == "Critical"
    assert result.is_spoofable is True
    assert [f.code for f in result.findings] == ["SPF_PLUS_ALL"]


def test_hardfail_is_secure():
    result = _analyze("example.com", ["v=spf1 -all"], None, SETTINGS)
    assert result.risk_level == "Secure"
    assert result.is_spoofable is False


def test_softfail_without_dmarc_is_warning():
    result = _analyze("example.com", ["v=spf1 ~all"], None, SETTINGS)
    assert result.risk_level == "Warning"
    assert "SPF_SOFTFAIL_NO_DMARC" in [f.code for f in result.findings]


def test_softfail_with_strong_dmarc_is_secure():
    result = _analyze(
        "example.com", ["v=spf1 ~all"], "v=DMARC1; p=reject; rua=mailto:a@b.c", SETTINGS
    )
    assert result.risk_level == "Secure"
    assert result.dmarc_policy == "reject"


def test_missing_all_mechanism_is_neutral_not_secure():
    # 没有 all 机制 = 隐式 ?all:未授权方拿到 neutral,与显式 ?all 同等无效
    result = _analyze("example.com", ["v=spf1 include:_spf.google.com"], None, SETTINGS)
    assert result.risk_level == "Warning"
    assert "SPF_NO_ALL_MECHANISM" in [f.code for f in result.findings]


def test_missing_all_but_strong_dmarc_is_secure():
    result = _analyze(
        "example.com",
        ["v=spf1 include:_spf.google.com"],
        "v=DMARC1; p=quarantine",
        SETTINGS,
    )
    assert result.risk_level == "Secure"


def test_no_spf_no_dmarc_is_critical():
    result = _analyze("example.com", [], None, SETTINGS)
    assert result.risk_level == "Critical"
    assert [f.code for f in result.findings] == ["SPF_MISSING"]


def test_no_spf_with_strong_dmarc_is_warning():
    result = _analyze("example.com", [], "v=DMARC1; p=reject", SETTINGS)
    assert result.risk_level == "Warning"
    assert [f.code for f in result.findings] == ["SPF_MISSING_DMARC_ENFORCED"]


def test_multiple_spf_is_critical():
    result = _analyze("example.com", ["v=spf1 -all", "v=spf1 ~all"], None, SETTINGS)
    assert result.risk_level == "Critical"
    assert "SPF_MULTIPLE_RECORDS" in [f.code for f in result.findings]


def test_oversized_cidr_is_warning():
    result = _analyze("example.com", ["v=spf1 ip4:10.0.0.0/8 -all"], None, SETTINGS)
    assert result.risk_level == "Warning"
    assert "SPF_OVERSIZED_CIDR" in [f.code for f in result.findings]


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 a mx -all", 2),                      # 裸 a / mx 也要计数
        ("v=spf1 a:example.com mx:example.com -all", 2),
        ("v=spf1 include:a.com include:b.com -all", 2),
        ("v=spf1 redirect=_spf.example.com", 1),
        ("v=spf1 ip4:1.2.3.4 -all", 0),
        ("v=spf1 a/24 -all", 1),
        ("v=spf1 v=spf1 -all", 0),
    ],
)
def test_count_dns_mechanisms(record, expected):
    assert _count_dns_mechanisms(record) == expected


def test_too_many_dns_lookups_is_warning():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(12)) + " -all"
    result = _analyze("example.com", [record], None, SETTINGS)
    assert result.risk_level == "Warning"
    assert "SPF_TOO_MANY_DNS_LOOKUPS" in [f.code for f in result.findings]


# ---------------- 子域判定 ----------------

def test_subdomain_bare_all_is_critical():
    result = _analyze_subdomain("api.example.com", ["v=spf1 all"], False, False, SETTINGS)
    assert result.risk_level == "Critical"


def test_subdomain_no_spf_no_mx_low_risk():
    result = _analyze_subdomain("cdn.example.com", [], False, False, SETTINGS)
    assert result.risk_level == "Info"
    assert result.is_spoofable is False


def test_subdomain_no_spf_with_mx_and_parent_strong():
    result = _analyze_subdomain("mail.example.com", [], True, True, SETTINGS)
    assert result.risk_level == "Warning"
    assert result.is_spoofable is True
