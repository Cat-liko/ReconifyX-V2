"""请求守卫:API Key 比较与每 IP 令牌桶。"""

from app.core.guards import TokenBucket, api_key_ok, requires_guard


def test_no_configured_key_means_no_auth():
    # 空 key = 未启用鉴权(而不是"任何 key 都能过")
    assert api_key_ok("", None) is True
    assert api_key_ok("", "anything") is True


def test_configured_key_requires_exact_match():
    assert api_key_ok("s3cret", "s3cret") is True
    assert api_key_ok("s3cret", "s3creT") is False
    assert api_key_ok("s3cret", None) is False
    assert api_key_ok("s3cret", "") is False


def test_guarded_paths():
    assert requires_guard("/scan") is True
    assert requires_guard("/scan/abc") is True
    assert requires_guard("/scan/batch") is True
    assert requires_guard("/dns") is True
    assert requires_guard("/history") is True
    assert requires_guard("/debug/scan") is True
    # 静态页与探针不该被限流(否则浏览器一刷新就耗光额度)
    assert requires_guard("/") is False
    assert requires_guard("/app.js") is False
    assert requires_guard("/healthz") is False
    assert requires_guard("/metrics") is False
    assert requires_guard("/openapi.json") is False


def test_bucket_allows_burst_then_blocks():
    bucket = TokenBucket(per_minute=60, burst=3)
    now = 1000.0
    assert bucket.allow("ip", now) is True
    assert bucket.allow("ip", now) is True
    assert bucket.allow("ip", now) is True
    # 桶空:同一时刻的第四次必须被拒
    assert bucket.allow("ip", now) is False


def test_bucket_refills_over_time():
    bucket = TokenBucket(per_minute=60, burst=1)  # 每秒补 1 个
    now = 1000.0
    assert bucket.allow("ip", now) is True
    assert bucket.allow("ip", now) is False
    assert bucket.allow("ip", now + 1.1) is True


def test_bucket_is_per_key():
    bucket = TokenBucket(per_minute=60, burst=1)
    now = 1000.0
    assert bucket.allow("a", now) is True
    assert bucket.allow("b", now) is True
    assert bucket.allow("a", now) is False


def test_retry_after_is_positive():
    bucket = TokenBucket(per_minute=60, burst=1)
    now = 1000.0
    bucket.allow("ip", now)
    bucket.allow("ip", now)
    assert bucket.retry_after_seconds("ip") >= 1
