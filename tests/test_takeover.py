"""子域名接管判定:CNAME 匹配 + 双信号交叉分级。

核心回归点:CNAME 目标曾经的 `suffix in target` 子串判断,会把
`evil.s3.amazonaws.com.attacker.net` 当成"指向 AWS S3";叠加正文里的
NoSuchBucket 指纹后就直接产出"高置信、可接管"的假阳性。
"""

import pytest

from app.services.takeover_service import (
    CnameFanout,
    _analyze_takeover,
    _match_provider_by_cname,
    assemble_takeover,
)


@pytest.mark.parametrize(
    ("chain", "provider"),
    [
        (["mybucket.s3.amazonaws.com"], "AWS S3"),
        (["bucket.s3.us-west-2.amazonaws.com"], "AWS S3"),          # 区域端点
        (["bucket.s3-website-us-east-1.amazonaws.com"], "AWS S3"),   # 静态站点端点
        (["bucket.s3.dualstack.ap-south-1.amazonaws.com"], "AWS S3"),
        (["hello.github.io"], "GitHub Pages"),
        (["app.herokuapp.com"], "Heroku"),
        (["x.fastly.net"], "Fastly"),
        (["s3.amazonaws.com"], "AWS S3"),                            # 整名相等
    ],
)
def test_cname_matches_known_provider(chain, provider):
    matched = _match_provider_by_cname(chain)
    assert matched is not None
    assert matched.name == provider


@pytest.mark.parametrize(
    "chain",
    [
        ["evil.s3.amazonaws.com.attacker.net"],   # 子串里嵌了 S3 后缀
        ["attacker.net"],
        ["s3.amazonaws.com.evil.com"],
        ["notgithub.io"],                          # 不以 .github.io 结尾
        ["happy.herokuapp.com.evil.org"],
        [],
    ],
)
def test_cname_does_not_match_forged_targets(chain):
    assert _match_provider_by_cname(chain) is None


def test_cname_matching_is_suffix_based():
    provider = _match_provider_by_cname(["github.io.evil.com"])
    assert provider is None


def test_forged_cname_plus_body_fingerprint_is_not_high():
    # 旧行为:High + is_vulnerable=True(假阳性)。现在两个信号都不该命中。
    finding = _analyze_takeover(
        "sub.example.com",
        ["evil.s3.amazonaws.com.attacker.net"],
        404,
        "<Error><Code>NoSuchBucket</Code></Error>",
    )
    assert finding is not None
    # 只剩"正文疑似悬空"的 Low 旁证,而不是高置信可接管
    assert finding.confidence == "Low"
    assert finding.is_vulnerable is False
    assert finding.matched_provider is None


def test_double_signal_is_high_and_vulnerable():
    finding = _analyze_takeover(
        "sub.example.com",
        ["mybucket.s3.amazonaws.com"],
        404,
        "<Error><Code>NoSuchBucket</Code></Error>",
    )
    assert finding.confidence == "High"
    assert finding.is_vulnerable is True
    assert finding.matched_provider == "AWS S3"


def test_cname_only_is_low():
    finding = _analyze_takeover("sub.example.com", ["mybucket.s3.amazonaws.com"], 200, "<html>ok</html>")
    assert finding.confidence == "Low"
    assert finding.is_vulnerable is False


def test_no_signal_returns_none():
    assert _analyze_takeover("sub.example.com", [], 200, "<html>nothing here</html>") is None


def test_non_claimable_provider_is_high_but_not_vulnerable():
    # Zendesk 悬空但平台不允许认领:确认悬空(High),但不计入 vulnerable_count
    finding = _analyze_takeover(
        "support.example.com",
        ["x.zendesk.com"],
        404,
        "<html>Help Center Closed</html>",
    )
    assert finding.confidence == "High"
    assert finding.is_vulnerable is False


def test_assemble_counts_only_vulnerable():
    fanout = CnameFanout(
        chains={
            "a.example.com": ["mybucket.s3.amazonaws.com"],
            "b.example.com": ["x.zendesk.com"],
        },
        total_discovered=2,
        checked=2,
        truncated=False,
    )
    bodies = {
        "a.example.com": (404, "NoSuchBucket"),
        "b.example.com": (404, "Help Center Closed"),
    }
    from app.core.config import Settings

    report = assemble_takeover(fanout, bodies, Settings())
    assert report.vulnerable_count == 1
    assert len(report.findings) == 2
    assert report.takeover_complete is True
