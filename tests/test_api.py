"""API 层:域名校验、计划校验、异步任务生命周期、结果落盘边界。"""

import asyncio
import time
from pathlib import Path

import httpx
import pytest

import app.main as main
import app.services.basic as basic
from app.core.jobs import Job
from app.main import _save_result, app
from app.schemas.scan import ScanData


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _fake_discover(domain, settings):
    return [domain, f"www.{domain}"], [], False, []


@pytest.mark.parametrize(
    "bad",
    ["pro::example.com", "..\\..\\evil", "localhost", "a_b.com", "exa mple.com"],
)
async def test_post_scan_rejects_invalid_domain(bad):
    async with _client() as c:
        r = await c.post("/scan", json={"domain": bad, "plan": "Basic"})
    assert r.status_code == 422
    assert "invalid domain" in r.text


async def test_post_scan_rejects_unknown_plan():
    async with _client() as c:
        r = await c.post("/scan", json={"domain": "example.com", "plan": "Enterprise"})
    assert r.status_code == 400
    body = r.json()
    assert body["status"] == "unavailable"
    assert "Basic" in body["message"]


async def test_debug_endpoint_rejects_invalid_domain():
    async with _client() as c:
        r = await c.get("/debug/scan", params={"domain": "pro::example.com"})
    assert r.status_code == 400
    assert "invalid domain" in r.text


async def test_scan_job_completes_and_normalizes_domain(monkeypatch, tmp_path):
    monkeypatch.setattr(basic, "discover", _fake_discover)
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    async with _client() as c:
        r = await c.post("/scan", json={"domain": "  Example.COM  ", "plan": "Basic"})
        assert r.status_code == 202, r.text
        job_id = r.json()["job_id"]

        job = None
        for _ in range(200):
            g = await c.get(f"/scan/{job_id}")
            assert g.status_code == 200
            job = g.json()
            if job["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.02)

    assert job is not None
    assert job["status"] == "completed", job
    assert job["domain"] == "example.com"
    assert job["result"]["total_found"] == 2
    assert job["degraded"] is False
    # 实际扫描完成会落盘,且落在配置的目录里
    assert job["saved_path"] is not None
    assert Path(job["saved_path"]).resolve().parent == tmp_path.resolve()


async def test_duplicate_post_reuses_active_job(monkeypatch, tmp_path):
    calls = {"n": 0}

    async def slow_discover(domain, settings):
        calls["n"] += 1
        await asyncio.sleep(0.2)
        return [domain], [], False, []

    monkeypatch.setattr(basic, "discover", slow_discover)
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    async with _client() as c:
        first = await c.post("/scan", json={"domain": "dup.example.com", "plan": "Basic"})
        second = await c.post("/scan", json={"domain": "dup.example.com", "plan": "Basic"})
        assert first.json()["job_id"] == second.json()["job_id"]
        # 等后台任务收尾,避免事件循环关闭时留下悬挂任务
        for _ in range(100):
            g = await c.get(f"/scan/{first.json()['job_id']}")
            if g.json()["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.02)
    assert calls["n"] == 1


async def test_save_result_cannot_escape_result_dir(monkeypatch, tmp_path):
    """即使绕过 API 校验直接构造恶意 domain_key,落盘也不能穿越出结果目录。"""
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    job = Job(
        job_id="abcdef1234567890",
        domain_key="..\\..\\pwned",
        plan="basic",
        status="completed",
        created_at=time.time(),
        finished_at=time.time(),
    )
    job.result = None
    await _save_result(job)

    assert job.saved_path is not None
    path = Path(job.saved_path).resolve()
    assert path.parent == tmp_path.resolve()
    assert path.exists()
    # 文件名里不能出现路径分隔符
    assert "/" not in path.name and "\\" not in path.name
    path.unlink()


async def test_save_result_skips_oversized_payload(monkeypatch, tmp_path):
    """超过 RESULT_MAX_BYTES 的结果只留在内存里,不写盘(也不报错)。"""
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))
    monkeypatch.setattr(main.settings, "RESULT_MAX_BYTES", 64)

    job = Job(
        job_id="oversize123456",
        domain_key="example.com",
        plan="basic",
        status="completed",
        created_at=time.time(),
        finished_at=time.time(),
    )
    job.result = ScanData(total_found=1, subdomains=["a.example.com"], total_assets=0)
    await _save_result(job)

    assert job.saved_path is None
    assert list(tmp_path.iterdir()) == []


async def test_get_unknown_job_returns_404():
    async with _client() as c:
        r = await c.get("/scan/deadbeef")
    assert r.status_code == 404


# ==================== 新增端点 ====================


async def _wait_completed(client, job_id, tries=200):
    job = None
    for _ in range(tries):
        g = await client.get(f"/scan/{job_id}")
        job = g.json()
        if job["status"] in ("completed", "failed"):
            return job
        await asyncio.sleep(0.02)
    raise AssertionError(f"job did not finish: {job}")


async def test_meta_and_probes():
    async with _client() as c:
        meta = await c.get("/api/meta")
        assert meta.status_code == 200
        body = meta.json()
        assert body["version"] == main.settings.VERSION
        assert [p["name"] for p in body["plans"]] == ["Basic", "Pro", "Ultra"]
        assert body["limits"]["batch_domains"] >= 1

        health = await c.get("/healthz")
        assert health.status_code == 200 and health.json()["status"] == "ok"

        ready = await c.get("/readyz")
        assert ready.status_code == 200

        metrics = await c.get("/metrics")
        assert "reconifyx_requests_total" in metrics.text
        assert "reconifyx_jobs" in metrics.text


async def test_responses_carry_security_headers():
    async with _client() as c:
        r = await c.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
    # 结果里含目标域名与资产信息,不能被中间代理缓存
    assert r.headers["cache-control"] == "no-store"


async def test_ui_assets_are_served():
    async with _client() as c:
        for path, needle in (
            ("/", b"<html"),
            ("/app.js", b"use strict"),
            ("/style.css", b"--bg"),
            ("/favicon.svg", b"<svg"),
        ):
            r = await c.get(path)
            assert r.status_code == 200, path
            assert needle in r.content, path


async def test_debug_endpoint_returns_400_for_unknown_plan():
    """以前这里返回 200 + unavailable 载荷,脚本会当成成功。"""
    async with _client() as c:
        r = await c.get("/debug/scan", params={"domain": "example.com", "plan": "Enterprise"})
    assert r.status_code == 400
    assert "Basic" in r.json()["message"]


async def test_batch_creates_one_job_per_domain(monkeypatch, tmp_path):
    monkeypatch.setattr(basic, "discover", _fake_discover)
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    async with _client() as c:
        r = await c.post(
            "/scan/batch",
            json={"domains": ["a.example.com", "b.example.com"], "plan": "Basic"},
        )
        assert r.status_code == 202, r.text
        jobs = r.json()["jobs"]
        assert len(jobs) == 2
        assert {j["domain"] for j in jobs} == {"a.example.com", "b.example.com"}
        for job in jobs:
            assert job["job_id"]


async def test_batch_rejects_too_many_domains(monkeypatch):
    monkeypatch.setattr(main.settings, "BATCH_MAX_DOMAINS", 2)
    async with _client() as c:
        r = await c.post(
            "/scan/batch", json={"domains": ["a.com", "b.com", "c.com"], "plan": "Basic"}
        )
    assert r.status_code == 400
    assert "too many domains" in r.json()["message"]


async def test_batch_rejects_invalid_domain():
    async with _client() as c:
        r = await c.post("/scan/batch", json={"domains": ["ok.com", "bad_domain"], "plan": "Basic"})
    assert r.status_code == 422


async def test_batch_rejects_unknown_plan():
    async with _client() as c:
        r = await c.post("/scan/batch", json={"domains": ["ok.com"], "plan": "Enterprise"})
    assert r.status_code == 400


async def test_export_formats(monkeypatch, tmp_path):
    monkeypatch.setattr(basic, "discover", _fake_discover)
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    async with _client() as c:
        acc = await c.post("/scan", json={"domain": "export.example.com", "plan": "Basic"})
        job = await _wait_completed(c, acc.json()["job_id"])

        for fmt, marker in (("json", b"export.example.com"), ("csv", b"host"), ("md", b"# ReconifyX")):
            r = await c.get(f"/scan/{job['job_id']}/export?format={fmt}")
            assert r.status_code == 200, fmt
            assert "attachment" in r.headers["content-disposition"]
            assert marker in r.content, fmt

        bad = await c.get(f"/scan/{job['job_id']}/export?format=xml")
        assert bad.status_code == 400


async def test_export_and_diff_require_a_finished_job():
    async with _client() as c:
        assert (await c.get("/scan/nope/export")).status_code == 404
        assert (await c.get("/scan/nope/diff")).status_code == 404


async def test_diff_reports_baseline_without_history(monkeypatch, tmp_path):
    monkeypatch.setattr(basic, "discover", _fake_discover)
    monkeypatch.setattr(main.settings, "RESULT_DIR", str(tmp_path))

    async with _client() as c:
        acc = await c.post("/scan", json={"domain": "diff.example.com", "plan": "Basic"})
        job = await _wait_completed(c, acc.json()["job_id"])
        r = await c.get(f"/scan/{job['job_id']}/diff")

    assert r.status_code == 200
    body = r.json()
    assert body["baseline"] is True
    assert body["new_subdomains"] == []


async def test_dns_endpoint_uses_configured_resolver(monkeypatch):
    async with _client() as c:
        r = await c.get("/dns", params={"domain": "example.com"})
        assert r.status_code == 200
        assert r.json()["a"] == ["192.0.2.1"]

        bad = await c.get("/dns", params={"domain": "bad_domain"})
        assert bad.status_code == 400


async def test_history_endpoint_returns_empty_when_disabled():
    async with _client() as c:
        r = await c.get("/history", params={"domain": "example.com"})
    assert r.status_code == 200
    assert r.json()["count"] == 0
    assert r.json()["entries"] == []


async def test_history_endpoint_validates_domain():
    async with _client() as c:
        r = await c.get("/history", params={"domain": "../etc"})
    assert r.status_code == 400


async def test_api_key_is_enforced_when_configured(monkeypatch):
    monkeypatch.setattr(main.settings, "API_KEY", "topsecret")
    async with _client() as c:
        denied = await c.get("/scan/whatever")
        assert denied.status_code == 401
        assert "X-API-Key" in denied.json()["message"]

        allowed = await c.get("/scan/whatever", headers={"X-API-Key": "topsecret"})
        assert allowed.status_code == 404  # 过了鉴权,只是 job 不存在

        # 静态页与探针不受影响
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/")).status_code == 200


async def test_rate_limit_returns_429(monkeypatch):
    monkeypatch.setattr(main, "_limiter", main.TokenBucket(per_minute=60, burst=1))
    async with _client() as c:
        first = await c.get("/scan/one")
        second = await c.get("/scan/two")
    assert first.status_code == 404  # 过了限流,只是 job 不存在
    assert second.status_code == 429
    assert second.headers["Retry-After"].isdigit()
