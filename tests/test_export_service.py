"""导出:JSON / CSV / Markdown 三种形态的内容正确性与健壮性。"""

import csv
import io
import json

from app.services import export_service

PAYLOAD = {
    "job_id": "abc123",
    "domain": "example.com",
    "plan": "Ultra",
    "plan_key": "ultra",
    "status": "completed",
    "created_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:01:00Z",
    "elapsed_ms": 60000,
    "from_cache": False,
    "degraded": False,
    "sources": [
        {"name": "crt.sh", "ok": True, "count": 12, "detail": ""},
        {"name": "fofa", "ok": False, "count": 0, "detail": "disabled (no password)"},
    ],
    "result": {
        "total_found": 3,
        "subdomains": ["api.example.com", "example.com", "www.example.com"],
        "total_assets": 1,
        "assets": [{"ip": "192.0.2.10", "hostnames": ["example.com"], "ports": [80, 443]}],
        "dns": {
            "domain": "example.com",
            "a": ["192.0.2.10"],
            "ns": ["ns1.example.net"],
            "soa": "ns1.example.net hostmaster.example.com serial=1",
            "has_spf": True,
            "has_dmarc": True,
            "resolved": True,
        },
        "total_live": 1,
        "live_assets": [
            {
                "url": "https://example.com",
                "host": "example.com",
                "status_code": 200,
                "title": "Example | Domain",
                "server": "nginx",
                "content_type": "text/html",
                "tls": {"verified": True, "subject": "example.com", "issuer": "Test CA",
                        "days_left": 120, "not_after": "2026-05-01T00:00:00Z"},
                "security": {"grade": "C", "score": 64, "findings": [
                    {"code": "CSP_MISSING", "severity": "Warning", "message": "no csp"}]},
            }
        ],
        "probe_complete": True,
        "email_audit": {
            "primary": {"domain": "example.com", "is_spoofable": False, "risk_level": "Secure",
                        "spf_record": "v=spf1 -all", "dmarc_record": "v=DMARC1; p=reject",
                        "dmarc_policy": "reject", "findings": []},
            "subdomain_policy": "reject",
            "total_discovered": 2,
            "total_subdomains_audited": 2,
            "spoofable_subdomains": 1,
            "audit_complete": True,
            "subdomains": [
                {"domain": "api.example.com", "has_own_spf": False, "has_own_mx": False,
                 "is_spoofable": False, "risk_level": "Info", "findings": []},
                {"domain": "www.example.com", "has_own_spf": False, "has_own_mx": True,
                 "is_spoofable": True, "risk_level": "Critical", "findings": []},
            ],
        },
        "takeover": {
            "total_discovered": 2,
            "total_checked": 2,
            "vulnerable_count": 1,
            "takeover_complete": True,
            "findings": [
                {"domain": "www.example.com", "cname_chain": ["old.github.io"],
                 "matched_provider": "GitHub Pages", "matched_fingerprint": "GitHub Pages 404",
                 "is_vulnerable": True, "confidence": "High", "status_code": 404,
                 "evidence": "dangling"},
            ],
        },
        "risk": {
            "risk_score": 42,
            "grade": "C",
            "counts": {"critical": 1, "warning": 1, "info": 0},
            "items": [
                {"code": "TAKEOVER_VULNERABLE", "severity": "Critical", "subject": "www.example.com",
                 "message": "dangling", "count": 1},
            ],
        },
    },
}


def test_json_export_roundtrips():
    text = export_service.render_json(PAYLOAD)
    assert json.loads(text) == PAYLOAD


def test_csv_export_has_bom_and_header():
    text = export_service.render_csv(PAYLOAD)
    assert text.startswith("\ufeff")  # Excel 直接打开不乱码
    rows = list(csv.DictReader(io.StringIO(text[1:])))
    assert len(rows) == 3  # api / example.com / www
    by_host = {row["host"]: row for row in rows}
    assert by_host["example.com"]["ip"] == "192.0.2.10"
    assert by_host["example.com"]["url"] == "https://example.com"
    assert by_host["example.com"]["headers_grade"] == "C"
    assert by_host["www.example.com"]["takeover_confidence"] == "High"
    assert by_host["www.example.com"]["email_risk"] == "Critical"


def test_csv_merges_host_seen_in_multiple_sections():
    rows = list(csv.DictReader(io.StringIO(export_service.render_csv(PAYLOAD)[1:])))
    example = next(row for row in rows if row["host"] == "example.com")
    # 同一个 host 同时出现在 subdomains / live_assets / email primary / assets
    assert example["in_subdomains"] == "yes"
    assert example["status_code"] == "200"
    assert example["email_risk"] == "Secure"


def test_markdown_export_contains_key_sections():
    text = export_service.render_markdown(PAYLOAD)
    assert "# ReconifyX 扫描报告" in text
    assert "`example.com`" in text
    assert "## 概览" in text
    assert "## 风险清单" in text
    assert "## 子域名接管" in text
    assert "## 存活资产" in text
    assert "TAKEOVER_VULNERABLE" in text
    assert "192.0.2.10" in text


def test_markdown_escapes_pipes_in_cells():
    payload = json.loads(json.dumps(PAYLOAD))
    payload["result"]["live_assets"][0]["title"] = "a | b"
    text = export_service.render_markdown(payload)
    assert "a \\| b" in text


def test_markdown_survives_empty_result():
    empty = {"job_id": "x", "domain": "example.com", "plan": "Basic", "result": {}}
    text = export_service.render_markdown(empty)
    assert "## 概览" in text
    assert "example.com" in text


def test_render_dispatches_by_format():
    for fmt, expected_ext in (("json", "json"), ("csv", "csv"), ("md", "md")):
        content, media_type, ext = export_service.render(fmt, PAYLOAD)
        assert content
        assert ext == expected_ext
        assert "charset=utf-8" in media_type


def test_suggested_filename_is_safe_and_ordered():
    name = export_service.suggested_filename(PAYLOAD, "csv")
    assert name.startswith("example.com_Ultra_")
    assert name.endswith(".csv")
    assert ":" not in name and "/" not in name


def test_suggested_filename_sanitizes_hostile_domain():
    payload = dict(PAYLOAD)
    payload["domain"] = "../../etc/passwd"
    name = export_service.suggested_filename(payload, "json")
    assert "/" not in name
    assert not name.startswith(".")
