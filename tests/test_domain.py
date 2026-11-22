"""域名归一化 / 校验。

这套规则是三条安全边界的共同入口:
  - 缓存键(`pro::example.com` 若被当域名接受,会污染 Pro 计划的缓存条目);
  - 结果文件名(含 `..` / 路径分隔符时可穿越出 res/);
  - DNS / HTTP 请求目标。
"""

import pytest
from pydantic import ValidationError

from app.core.domain import is_fqdn, normalize_domain
from app.schemas.scan import ScanJobCreate


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),  # 允许 FQDN 尾点
        ("https://example.com/path?q=1", "example.com"),  # 允许粘贴完整 URL
        ("http://user:pw@sub.example.com:8443/x", "sub.example.com"),
        ("a.b.c.example.co.uk", "a.b.c.example.co.uk"),
    ],
)
def test_normalize_accepts_and_canonicalizes(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",                 # 单标签,不是可扫描的 FQDN
        "pro::example.com",          # 会与 Pro 的缓存键撞名
        "..\\..\\evil",              # 路径穿越
        "../../evil.com",
        "exa mple.com",              # 空格
        "-bad.example.com",          # 标签以连字符开头
        "bad-.example.com",
        "a_b.example.com",           # 下划线
        "*.example.com",             # 通配符不是扫描目标
        "example.com/../etc/passwd",
    ],
)
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_is_fqdn_is_fullmatch_not_prefix():
    assert is_fqdn("example.com")
    # 语法层面 example.com.evil 是合法 FQDN —— "是否归属目标域"是 basic._is_valid_fqdn
    # 的职责,不该混进语法校验里
    assert is_fqdn("example.com.evil")
    assert not is_fqdn("example.com\n")  # fullmatch 不接受尾随换行
    assert not is_fqdn("")
    assert not is_fqdn("-bad.com")


def test_scan_job_create_normalizes_domain():
    job = ScanJobCreate(domain="HTTPS://Example.com/x", plan="Pro")
    assert job.domain == "example.com"


def test_scan_job_create_rejects_traversal():
    with pytest.raises(ValidationError):
        ScanJobCreate(domain="..\\..\\evil", plan="Basic")
