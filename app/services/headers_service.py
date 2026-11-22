"""HTTP 安全响应头审计 —— 纯 CPU,复用探活已经拿到的响应头。

为什么值得单独一节
------------------
这些头不修不会让服务宕机,但它们是**浏览器侧最后一道防线**:

  - HSTS 缺失 → 首跳明文可被劫持,后面再好的 TLS 也白搭(SSL stripping);
  - CSP 缺失 → 任何一处 XSS 直接变成任意脚本执行;
  - X-Frame-Options / frame-ancestors 缺失 → 点击劫持;
  - X-Content-Type-Options 缺失 → 浏览器 MIME 嗅探,把上传的"图片"当 HTML 执行;
  - Set-Cookie 缺 HttpOnly/Secure → XSS 直接偷会话。

成本几乎为零:响应头在探活阶段**已经**在手里,这里只做字符串判定,不额外发一个请求。
这也正是把它放在 Pro/Ultra 而不是单独做一个接口的原因。

分级口径(刻意保守,避免"全是 Warning"导致没人看):
  Warning = 浏览器侧有明确可利用面,或者配置写错(比缺失更糟);
  Info    = 纵深防御建议 / 信息披露,不构成直接攻击面。
"""

from typing import Dict, List, Mapping, Optional, Sequence

from app.core.config import Settings
from app.schemas.scan import HeaderFinding, SecurityHeaders

SEV_WARNING = "Warning"
SEV_INFO = "Info"

# 各严重度的扣分权重(从 100 分里扣)
_WEIGHTS = {SEV_WARNING: 10, SEV_INFO: 3}

# HSTS 建议下限:6 个月(IANA / OWASP 的常见推荐值)
_HSTS_MIN_MAX_AGE = 15552000

# 只保留这些安全相关头进 present(完整响应头可能有几百字节且含无关内容)
_PRESENT_KEYS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "server",
)

_MAX_VALUE_CHARS = 300


def _clip(value: str) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= _MAX_VALUE_CHARS else value[: _MAX_VALUE_CHARS - 1] + "…"


def _parse_hsts_max_age(value: str) -> Optional[int]:
    """从 Strict-Transport-Security 里取 max-age 秒数。"""
    for part in value.split(";"):
        key, _, raw = part.strip().partition("=")
        if key.strip().lower() == "max-age":
            raw = raw.strip().strip('"')
            if raw.isdigit():
                return int(raw)
    return None


def _cookie_flags(cookie: str) -> Dict[str, bool]:
    """粗糙但够用的 Set-Cookie 解析:只关心三个布尔属性。"""
    segments = [s.strip() for s in cookie.split(";") if s.strip()]
    if not segments:
        return {"secure": False, "httponly": False, "samesite": False}
    flags = {s.split("=", 1)[0].strip().lower() for s in segments[1:]}
    return {
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": "samesite" in flags,
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def analyze(
    url: str,
    headers: Mapping[str, str],
    s: Settings,
    set_cookies: Sequence[str] = (),
) -> SecurityHeaders:
    """评估一个响应的安全头配置。纯函数:同样输入永远同样输出,便于单测。"""
    low: Dict[str, str] = {str(k).lower(): str(v) for k, v in headers.items()}
    is_https = url.lower().startswith("https://")
    findings: List[HeaderFinding] = []

    def has(name: str) -> bool:
        return bool(low.get(name, "").strip())

    # ---- HSTS(只对 https 有意义;http 站点谈 HSTS 是空谈)----
    if is_https:
        hsts = low.get("strict-transport-security", "")
        if not hsts:
            findings.append(
                HeaderFinding(
                    code="HSTS_MISSING",
                    severity=SEV_WARNING,
                    message=(
                        "No Strict-Transport-Security header. The first request can be "
                        "downgraded to plain HTTP (SSL stripping), defeating TLS entirely. "
                        "Add 'max-age=31536000; includeSubDomains'."
                    ),
                )
            )
        else:
            max_age = _parse_hsts_max_age(hsts)
            if max_age is None:
                findings.append(
                    HeaderFinding(
                        code="HSTS_NO_MAX_AGE",
                        severity=SEV_WARNING,
                        message=(
                            "Strict-Transport-Security is present but has no parsable "
                            "'max-age' directive, so browsers ignore the policy."
                        ),
                    )
                )
            elif max_age < _HSTS_MIN_MAX_AGE:
                findings.append(
                    HeaderFinding(
                        code="HSTS_SHORT_MAX_AGE",
                        severity=SEV_WARNING,
                        message=(
                            f"Strict-Transport-Security max-age is {max_age}s, below the "
                            f"recommended {_HSTS_MIN_MAX_AGE}s (6 months). Short windows "
                            "leave room for downgrade attacks."
                        ),
                    )
                )
            if "includesubdomains" not in hsts.lower():
                findings.append(
                    HeaderFinding(
                        code="HSTS_NO_SUBDOMAINS",
                        severity=SEV_INFO,
                        message=(
                            "HSTS policy does not include the 'includeSubDomains' "
                            "directive, so subdomains remain downgradable."
                        ),
                    )
                )

    # ---- CSP ----
    csp = low.get("content-security-policy", "")
    csp_ro = low.get("content-security-policy-report-only", "")
    if not csp and not csp_ro:
        findings.append(
            HeaderFinding(
                code="CSP_MISSING",
                severity=SEV_WARNING,
                message=(
                    "No Content-Security-Policy. Without it, any script injection (XSS, "
                    "malicious third-party tag) executes with full page privileges."
                ),
            )
        )
    else:
        effective = (csp or csp_ro).lower()
        if "unsafe-inline" in effective:
            findings.append(
                HeaderFinding(
                    code="CSP_UNSAFE_INLINE",
                    severity=SEV_INFO,
                    message=(
                        "Content-Security-Policy allows 'unsafe-inline', which largely "
                        "negates its XSS protection. Prefer nonces or hashes."
                    ),
                )
            )
        if "unsafe-eval" in effective:
            findings.append(
                HeaderFinding(
                    code="CSP_UNSAFE_EVAL",
                    severity=SEV_INFO,
                    message=(
                        "Content-Security-Policy allows 'unsafe-eval', enabling code "
                        "execution from strings."
                    ),
                )
            )

    # ---- MIME 嗅探 ----
    xcto = low.get("x-content-type-options", "").strip().lower()
    if xcto != "nosniff":
        findings.append(
            HeaderFinding(
                code="XCTO_MISSING" if not xcto else "XCTO_INVALID",
                severity=SEV_WARNING,
                message=(
                    "X-Content-Type-Options must be 'nosniff'. Otherwise browsers may sniff "
                    "MIME types, turning an uploaded file into executable HTML/JS."
                ),
            )
        )

    # ---- 点击劫持(XFO 或 CSP frame-ancestors 二选一即可)----
    xfo = low.get("x-frame-options", "").strip().lower()
    framing_ok = xfo in ("deny", "sameorigin") or "frame-ancestors" in (
        low.get("content-security-policy", "") or ""
    ).lower()
    if not framing_ok:
        findings.append(
            HeaderFinding(
                code="FRAMING_UNPROTECTED",
                severity=SEV_WARNING,
                message=(
                    "No clickjacking protection: set X-Frame-Options (DENY/SAMEORIGIN) or "
                    "CSP 'frame-ancestors'. The page can otherwise be framed invisibly."
                ),
            )
        )

    # ---- 会话 Cookie 属性 ----
    if set_cookies:
        insecure_secure = 0
        insecure_httponly = 0
        missing_samesite = 0
        for cookie in set_cookies:
            flags = _cookie_flags(cookie)
            if is_https and not flags["secure"]:
                insecure_secure += 1
            if not flags["httponly"]:
                insecure_httponly += 1
            if not flags["samesite"]:
                missing_samesite += 1
        if insecure_secure:
            findings.append(
                HeaderFinding(
                    code="COOKIE_NO_SECURE",
                    severity=SEV_WARNING,
                    message=(
                        f"{insecure_secure} Set-Cookie without the Secure flag over HTTPS: "
                        "the cookie can be sent over a plaintext downgrade."
                    ),
                )
            )
        if insecure_httponly:
            findings.append(
                HeaderFinding(
                    code="COOKIE_NO_HTTPONLY",
                    severity=SEV_WARNING,
                    message=(
                        f"{insecure_httponly} Set-Cookie without HttpOnly: any XSS can read "
                        "the session cookie directly."
                    ),
                )
            )
        if missing_samesite:
            findings.append(
                HeaderFinding(
                    code="COOKIE_NO_SAMESITE",
                    severity=SEV_INFO,
                    message=(
                        f"{missing_samesite} Set-Cookie without SameSite: cross-site "
                        "requests may carry the cookie (CSRF surface)."
                    ),
                )
            )

    # ---- 信息披露(纯 Info,不影响评分总量级)----
    if has("server") and s.SECURITY_HEADERS_INCLUDE_INFO:
        findings.append(
            HeaderFinding(
                code="SERVER_BANNER",
                severity=SEV_INFO,
                message=(
                    f"Server header discloses '{_clip(low['server'])}'. Consider removing "
                    "the version banner to slow down targeted exploitation."
                ),
            )
        )
    if has("x-powered-by") and s.SECURITY_HEADERS_INCLUDE_INFO:
        findings.append(
            HeaderFinding(
                code="X_POWERED_BY",
                severity=SEV_INFO,
                message=(
                    f"X-Powered-By discloses '{_clip(low['x-powered-by'])}'. Remove the "
                    "framework banner."
                ),
            )
        )

    # ---- Referrer-Policy / Permissions-Policy(可选的纵深防御)----
    if s.SECURITY_HEADERS_INCLUDE_INFO:
        if not has("referrer-policy"):
            findings.append(
                HeaderFinding(
                    code="REFERRER_POLICY_MISSING",
                    severity=SEV_INFO,
                    message=(
                        "No Referrer-Policy. URLs (which may contain tokens) can leak to "
                        "third parties via the Referer header. Prefer 'strict-origin-when-cross-origin'."
                    ),
                )
            )
        if not has("permissions-policy"):
            findings.append(
                HeaderFinding(
                    code="PERMISSIONS_POLICY_MISSING",
                    severity=SEV_INFO,
                    message=(
                        "No Permissions-Policy. Powerful browser features (camera, geolocation, "
                        "payment) stay available to embedded third-party frames."
                    ),
                )
            )

    # ---- CORS 通配 ----
    if low.get("access-control-allow-origin", "").strip() == "*":
        findings.append(
            HeaderFinding(
                code="CORS_WILDCARD",
                severity=SEV_INFO,
                message=(
                    "Access-Control-Allow-Origin is '*' — any origin can read this response. "
                    "Acceptable for public APIs, dangerous for authenticated endpoints."
                ),
            )
        )

    # ---- 评分 ----
    penalty = sum(_WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)

    present = {k: _clip(v) for k, v in low.items() if k in _PRESENT_KEYS and v}

    return SecurityHeaders(
        score=score, grade=_grade(score), findings=findings, present=present
    )
