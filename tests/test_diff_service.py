"""扫描差异对比:集合运算 + "无基线"语义。"""

from types import SimpleNamespace as NS

from app.services import diff_service


def snapshot(job_id="job-1", finished=1000.0, subs=None, live=None, takeover=None, ips=None):
    return {
        "job_id": job_id,
        "finished_at": finished,
        "subdomains": subs or [],
        "live_urls": live or [],
        "takeover_domains": takeover or [],
        "ip_assets": ips or [],
    }


def test_no_previous_means_baseline_and_no_fake_additions():
    diff = diff_service.compute_diff("example.com", None, snapshot(subs=["a.example.com"]))
    assert diff.baseline is True
    assert diff.new_subdomains == []
    assert diff.removed_subdomains == []
    assert diff.compared_to_job_id is None


def test_new_and_removed_sets():
    prev = snapshot(subs=["a.x.com", "b.x.com"], live=["https://a.x.com"], ips=["1.1.1.1"])
    cur = snapshot(subs=["b.x.com", "c.x.com"], live=["https://c.x.com"], ips=["2.2.2.2"])

    diff = diff_service.compute_diff("x.com", prev, cur)

    assert diff.baseline is False
    assert diff.new_subdomains == ["c.x.com"]
    assert diff.removed_subdomains == ["a.x.com"]
    assert diff.new_live_urls == ["https://c.x.com"]
    assert diff.removed_live_urls == ["https://a.x.com"]
    assert diff.new_ip_assets == ["2.2.2.2"]
    assert diff.compared_to_job_id == "job-1"
    assert diff.compared_at and diff.compared_at.endswith("Z")


def test_new_takeover_only_reports_appearances():
    """接管信号消失不值得报警(可能只是 DNS 被清掉了)。"""
    prev = snapshot(takeover=["old.x.com", "still.x.com"])
    cur = snapshot(takeover=["still.x.com", "new.x.com"])

    diff = diff_service.compute_diff("x.com", prev, cur)

    assert diff.new_takeover_domains == ["new.x.com"]


def test_diff_is_sorted_and_deterministic():
    prev = snapshot(subs=[])
    cur = snapshot(subs=["c.x.com", "a.x.com", "b.x.com"])
    diff = diff_service.compute_diff("x.com", prev, cur)
    assert diff.new_subdomains == ["a.x.com", "b.x.com", "c.x.com"]


def test_empty_previous_snapshot_is_treated_as_usable_baseline():
    """历史里可能存着早期版本写的空快照:缺字段要当空集合,不能崩。"""
    diff = diff_service.compute_diff("x.com", {"job_id": "old", "finished_at": 1.0}, snapshot(subs=["a.x.com"]))
    assert diff.baseline is False
    assert diff.new_subdomains == ["a.x.com"]


def test_build_snapshot_extracts_the_three_key_sets():
    result = NS(
        total_found=2,
        subdomains=["a.x.com", "b.x.com"],
        total_live=1,
        total_assets=1,
        live_assets=[NS(url="https://a.x.com")],
        assets=[NS(ip="1.2.3.4")],
        takeover=NS(findings=[NS(domain="a.x.com")]),
    )
    snap = diff_service.build_snapshot(
        domain="x.com",
        plan="ultra",
        job_id="j1",
        finished_at=1234.5,
        result=result,
        risk_score=42,
        degraded=False,
    )
    assert snap["subdomains"] == ["a.x.com", "b.x.com"]
    assert snap["live_urls"] == ["https://a.x.com"]
    assert snap["ip_assets"] == ["1.2.3.4"]
    assert snap["takeover_domains"] == ["a.x.com"]
    assert snap["risk_score"] == 42


def test_build_snapshot_without_probe_or_takeover():
    """Basic 计划没有 live_assets / takeover 字段,不能让 build 崩。"""
    result = NS(total_found=0, subdomains=[], total_assets=0, assets=[])
    snap = diff_service.build_snapshot(
        domain="x.com",
        plan="basic",
        job_id="j2",
        finished_at=1.0,
        result=result,
        risk_score=0,
        degraded=True,
    )
    assert snap["live_urls"] == []
    assert snap["takeover_domains"] == []
    assert snap["degraded"] is True
