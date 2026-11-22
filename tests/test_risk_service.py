"""风险总账:聚合、计数、评分与分级。"""

from types import SimpleNamespace as NS

from app.services import risk_service


def finding(code, severity="Critical", message="m"):
    return NS(code=code, severity=severity, message=message)


def subdomain(domain, level, findings=None):
    return NS(domain=domain, risk_level=level, findings=findings or [], is_spoofable=True)


def live(url, tls=None, security=None):
    return NS(url=url, tls=tls, security=security)


def build(primary_level="Secure", primary_findings=None, subdomains=None, takeover=None, assets=None):
    return NS(
        email_audit=NS(
            primary=NS(
                domain="example.com",
                risk_level=primary_level,
                findings=primary_findings or [],
            ),
            subdomains=subdomains or [],
        ),
        takeover=takeover,
        live_assets=assets or [],
        dns=None,
        risk=None,
    )


def test_clean_scan_scores_zero():
    summary = risk_service.assess(build())
    assert summary.risk_score == 0
    assert summary.grade == "A"
    assert summary.counts.critical == 0
    assert summary.items == []


def test_critical_primary_email_dominates_score():
    data = build(primary_level="Critical", primary_findings=[finding("SPF_MISSING")])
    summary = risk_service.assess(data)
    assert summary.risk_score >= 30
    assert summary.counts.critical == 1
    assert summary.items[0].code == "SPF_MISSING"


def test_same_code_is_aggregated_with_count():
    subs = [subdomain(f"a{i}.example.com", "Critical", [finding("SPF_MISSING")]) for i in range(3)]
    summary = risk_service.assess(build(subdomains=subs))
    codes = {item.code: item for item in summary.items}
    assert codes["SPF_MISSING"].count == 3
    assert summary.counts.critical == 3


def test_info_findings_are_dropped_from_risk_account():
    """主域的 Info 多是"你做对了"的确认(SPF_HARDFAIL),不该进风险账。"""
    data = build(primary_findings=[finding("SPF_HARDFAIL", "Info")])
    summary = risk_service.assess(data)
    assert summary.items == []
    assert summary.counts.info == 0


def test_takeover_high_is_weighted_heavily():
    takeover = NS(
        findings=[
            NS(domain="old.example.com", is_vulnerable=True, confidence="High", evidence="e"),
            NS(domain="maybe.example.com", is_vulnerable=False, confidence="Low", evidence="e"),
        ]
    )
    summary = risk_service.assess(build(takeover=takeover))
    codes = {item.code for item in summary.items}
    assert "TAKEOVER_VULNERABLE" in codes
    assert "TAKEOVER_REVIEW" in codes
    assert summary.risk_score >= 33


def test_expired_certificate_ranked_critical():
    assets = [live("https://a.example.com", tls=NS(expired=True, not_after="2020-01-01T00:00:00Z"))]
    summary = risk_service.assess(build(assets=assets))
    assert "TLS_EXPIRED" in {item.code for item in summary.items}
    assert summary.counts.critical == 1


def test_unverified_and_expiring_are_warnings():
    assets = [
        live("https://b.example.com", tls=NS(verification_error="self-signed")),
        live(
            "https://c.example.com",
            tls=NS(expiring_soon=True, days_left=5, not_after="2026-01-05T00:00:00Z"),
        ),
    ]
    summary = risk_service.assess(build(assets=assets))
    codes = {item.code for item in summary.items}
    assert "TLS_UNVERIFIED" in codes
    assert "TLS_EXPIRING" in codes
    assert summary.counts.warning == 2


def test_self_signed_alone_is_info():
    assets = [live("https://d.example.com", tls=NS(self_signed=True))]
    summary = risk_service.assess(build(assets=assets))
    assert summary.counts.info == 1
    assert summary.risk_score == 0


def test_header_warnings_count_but_do_not_explode():
    security = NS(grade="D", score=54, findings=[finding("HSTS_MISSING", "Warning"),
                                                 finding("CSP_MISSING", "Warning")])
    assets = [live(f"https://h{i}.example.com", security=security) for i in range(50)]
    summary = risk_service.assess(build(assets=assets))
    # 50 个站点 × 2 条 = 100 条 Warning,但分值必须被封顶
    assert summary.counts.warning == 100
    assert summary.risk_score <= 100
    codes = {item.code for item in summary.items}
    assert "HSTS_MISSING" in codes


def test_score_is_capped_at_100():
    """多个维度同时命中时总分必须封顶,不能算出 200 分。"""
    subs = [
        subdomain(f"s{i}.example.com", "Critical", [finding("SUB_MAIL", "Critical")])
        for i in range(500)
    ]
    takeover = NS(
        findings=[
            NS(domain=f"t{i}.example.com", is_vulnerable=True, confidence="High", evidence="e")
            for i in range(5)
        ]
    )
    assets = [
        live("https://a.example.com", tls=NS(expired=True, not_after="2020-01-01T00:00:00Z")),
        live("https://b.example.com", tls=NS(expired=True, not_after="2020-01-01T00:00:00Z")),
    ] + [
        live(
            f"https://h{i}.example.com",
            security=NS(grade="F", score=0, findings=[finding("CSP_MISSING", "Warning")]),
        )
        for i in range(30)
    ]
    data = build(
        primary_level="Critical",
        primary_findings=[finding("SPF_MISSING", "Critical")],
        subdomains=subs,
        takeover=takeover,
        assets=assets,
    )
    summary = risk_service.assess(data)
    assert summary.risk_score == 100
    assert summary.grade == "F"


def test_items_are_sorted_by_severity():
    data = build(
        primary_level="Critical",
        primary_findings=[finding("SPF_MISSING", "Critical")],
        subdomains=[subdomain("a.example.com", "Warning", [finding("SPF_SOFTFAIL_NO_DMARC", "Warning")])],
    )
    items = risk_service.assess(data).items
    assert items[0].severity == "Critical"


def test_items_are_bounded():
    subs = [
        subdomain(f"s{i}.example.com", "Critical", [finding(f"CODE_{i}", "Critical")])
        for i in range(60)
    ]
    assert len(risk_service.assess(build(subdomains=subs)).items) <= 20


def test_grade_thresholds():
    assert risk_service._grade(0) == "A"
    assert risk_service._grade(10) == "A"
    assert risk_service._grade(11) == "B"
    assert risk_service._grade(26) == "C"
    assert risk_service._grade(46) == "D"
    assert risk_service._grade(66) == "F"
