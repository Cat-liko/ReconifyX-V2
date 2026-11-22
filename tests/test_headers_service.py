"""安全响应头审计:纯函数,覆盖每个判定的正/反两面。"""

from app.core.config import Settings
from app.services import headers_service as hs

URL = "https://app.example.com/"


def _codes(result):
    return {f.code for f in result.findings}


def _good_headers():
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }


def test_perfect_headers_score_full_marks():
    result = hs.analyze(URL, _good_headers(), Settings())
    assert result.findings == []
    assert result.score == 100
    assert result.grade == "A"


def test_bare_https_response_flags_essentials():
    result = hs.analyze(URL, {}, Settings())
    codes = _codes(result)
    assert "HSTS_MISSING" in codes
    assert "CSP_MISSING" in codes
    assert "XCTO_MISSING" in codes
    assert "FRAMING_UNPROTECTED" in codes
    assert result.score < 60
    assert result.grade in ("D", "F")


def test_http_url_does_not_demand_hsts():
    """对着 http 站点要 HSTS 是空谈,不该扣分。"""
    result = hs.analyze("http://legacy.example.com/", {}, Settings())
    assert "HSTS_MISSING" not in _codes(result)


def test_short_hsts_max_age_is_flagged():
    headers = _good_headers()
    headers["Strict-Transport-Security"] = "max-age=600; includeSubDomains"
    assert "HSTS_SHORT_MAX_AGE" in _codes(hs.analyze(URL, headers, Settings()))


def test_hsts_without_include_subdomains_is_info():
    headers = _good_headers()
    headers["Strict-Transport-Security"] = "max-age=31536000"
    result = hs.analyze(URL, headers, Settings())
    assert "HSTS_NO_SUBDOMAINS" in _codes(result)
    assert result.score >= 90  # Info 级不重罚


def test_x_frame_options_satisfies_framing_check():
    headers = _good_headers()
    del headers["Content-Security-Policy"]
    result = hs.analyze(URL, headers, Settings())
    codes = _codes(result)
    assert "FRAMING_UNPROTECTED" not in codes  # XFO=DENY 已覆盖
    assert "CSP_MISSING" in codes


def test_csp_frame_ancestors_satisfies_framing_check():
    headers = _good_headers()
    del headers["X-Frame-Options"]
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
    assert "FRAMING_UNPROTECTED" not in _codes(hs.analyze(URL, headers, Settings()))


def test_invalid_xcto_value_is_not_accepted():
    headers = _good_headers()
    headers["X-Content-Type-Options"] = "sniff"
    assert "XCTO_INVALID" in _codes(hs.analyze(URL, headers, Settings()))


def test_cookie_flags_are_checked():
    headers = _good_headers()
    cookies = [
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",   # 合规
        "weak=1; Path=/",                                     # 三个属性都缺
    ]
    result = hs.analyze(URL, headers, Settings(), cookies)
    codes = _codes(result)
    assert "COOKIE_NO_SECURE" in codes
    assert "COOKIE_NO_HTTPONLY" in codes
    assert "COOKIE_NO_SAMESITE" in codes
    # 消息里应给出命中数量,便于判断影响面
    message = next(f.message for f in result.findings if f.code == "COOKIE_NO_SECURE")
    assert "1 Set-Cookie" in message


def test_secure_cookie_only_over_https():
    """http 站点上缺失 Secure 不算问题(反正也没 TLS 可言)。"""
    headers = _good_headers()
    result = hs.analyze("http://plain.example.com/", headers, Settings(), ["a=1; Path=/"])
    assert "COOKIE_NO_SECURE" not in _codes(result)
    assert "COOKIE_NO_HTTPONLY" in _codes(result)


def test_info_checks_can_be_disabled():
    result = hs.analyze(URL, {}, Settings(SECURITY_HEADERS_INCLUDE_INFO=False))
    codes = _codes(result)
    assert "REFERRER_POLICY_MISSING" not in codes
    assert "PERMISSIONS_POLICY_MISSING" not in codes


def test_unsafe_inline_csp_is_info_only():
    headers = _good_headers()
    headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
    result = hs.analyze(URL, headers, Settings())
    assert "CSP_UNSAFE_INLINE" in _codes(result)
    assert result.grade == "A"  # Info 不降级


def test_cors_wildcard_is_flagged():
    headers = _good_headers()
    headers["Access-Control-Allow-Origin"] = "*"
    assert "CORS_WILDCARD" in _codes(hs.analyze(URL, headers, Settings()))


def test_present_only_contains_security_headers():
    headers = _good_headers()
    headers["X-Random-Tracking"] = "should-not-appear"
    present = hs.analyze(URL, headers, Settings()).present
    assert "strict-transport-security" in present
    assert "x-random-tracking" not in present


def test_header_lookup_is_case_insensitive():
    headers = {"X-CONTENT-TYPE-OPTIONS": "nosniff"}
    assert "XCTO_MISSING" not in _codes(hs.analyze(URL, headers, Settings()))
