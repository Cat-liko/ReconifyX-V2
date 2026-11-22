"""公共后缀子集:FOFA 噪声判定依赖它,判错会误杀合法子域。"""

from app.core.publicsuffix import (
    COMMON_TLDS,
    MULTI_LABEL_SUFFIXES,
    embedded_registrable_domain,
    is_public_suffix,
)


def test_single_label_tld_is_public_suffix():
    assert is_public_suffix(["com"]) is True
    assert is_public_suffix(["io"]) is True
    assert is_public_suffix(["notatld"]) is False


def test_multi_label_suffix_is_public_suffix():
    assert is_public_suffix(["co", "uk"]) is True
    assert is_public_suffix(["com", "cn"]) is True
    # uk 单独不是可用于注册的后缀,必须整体匹配 co.uk
    assert is_public_suffix(["foo", "uk"]) is False


def test_detects_embedded_foreign_domain():
    # ai.webproxy.jd.com  → 子域段 [ai, webproxy, jd, com] 里嵌了 jd.com
    assert embedded_registrable_domain(["ai", "webproxy", "jd", "com"]) == ("jd", "com")
    # foo.some-cdn.com.cn → 嵌了 some-cdn.com.cn(两标签后缀)
    assert embedded_registrable_domain(["foo", "some-cdn", "com", "cn"]) == (
        "some-cdn",
        "com",
        "cn",
    )


def test_does_not_flag_legit_single_label_matches():
    # 这些是最容易被误杀的形态:单标签恰好与某 TLD 同名
    for labels in (["cn"], ["me"], ["co"], ["io"], ["app"], ["dev"]):
        assert embedded_registrable_domain(labels) == ()
    assert embedded_registrable_domain(["login", "accounts"]) == ()
    assert embedded_registrable_domain(["www"]) == ()


def test_suffix_tables_are_lowercase_and_dotted():
    """表里一旦写错大小写或少了点,匹配就会静默失效。"""
    assert all(tld == tld.lower() for tld in COMMON_TLDS)
    assert all("." in suffix and suffix == suffix.lower() for suffix in MULTI_LABEL_SUFFIXES)
