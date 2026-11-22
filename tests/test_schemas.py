"""响应模型的类型保真度。

ScanJobStatus.result 是 Union[ScanData, ProScanData, UltraScanData]。三个模型共享
一大批字段名,若允许"额外字段被忽略",Pro/Ultra 结果被误判成 ScanData 时会静默
丢掉 live_assets / email_audit / takeover —— 发起方能拿到 200 却少了半份数据。
extra="forbid" 让这种串型直接失败,而不是悄悄丢字段。
"""

import pytest
from pydantic import ValidationError

from app.schemas.scan import (
    EmailAuditResult,
    EmailSecurityReport,
    LiveAsset,
    ProScanData,
    ScanData,
    ScanJobStatus,
    TakeoverReport,
    UltraScanData,
)

CREATED = "2026-01-01T00:00:00Z"


def _email_report() -> EmailSecurityReport:
    return EmailSecurityReport(
        primary=EmailAuditResult(domain="example.com", is_spoofable=False, risk_level="Secure"),
        total_subdomains_audited=0,
        spoofable_subdomains=0,
    )


def _pro() -> ProScanData:
    return ProScanData(
        total_found=1,
        subdomains=["example.com"],
        total_assets=0,
        total_live=1,
        live_assets=[LiveAsset(url="https://example.com", status_code=200)],
        email_audit=_email_report(),
    )


def _ultra() -> UltraScanData:
    return UltraScanData(
        total_found=1,
        subdomains=["example.com"],
        total_assets=0,
        total_live=1,
        live_assets=[LiveAsset(url="https://example.com", status_code=200)],
        email_audit=_email_report(),
        takeover=TakeoverReport(total_checked=0, vulnerable_count=0),
    )


def test_pro_result_survives_job_status_union():
    status = ScanJobStatus(
        job_id="j", domain="example.com", plan="pro", status="completed",
        created_at=CREATED, result=_pro(),
    )
    assert isinstance(status.result, ProScanData)
    dumped = status.model_dump()["result"]
    assert dumped["total_live"] == 1
    assert dumped["email_audit"]["spoofable_subdomains"] == 0


def test_ultra_result_survives_job_status_union():
    status = ScanJobStatus(
        job_id="j", domain="example.com", plan="ultra", status="completed",
        created_at=CREATED, result=_ultra(),
    )
    assert isinstance(status.result, UltraScanData)
    assert status.model_dump()["result"]["takeover"]["vulnerable_count"] == 0


def test_pro_data_rejects_basic_shaped_dict_with_extra_fields():
    # 一个"带 Pro 字段的 dict"不能被悄悄塞进 ScanData
    with pytest.raises(ValidationError):
        ScanData(
            total_found=1, subdomains=[], total_assets=0, total_live=3  # total_live 不属于 ScanData
        )


def test_basic_data_roundtrip():
    data = ScanData(total_found=0, subdomains=[], total_assets=0)
    dumped = data.model_dump()
    assert dumped["total_found"] == 0
    assert dumped["subdomains"] == []
    assert dumped["total_assets"] == 0
    assert dumped["assets"] == []
    # 新增的情报字段默认缺省为 None,不进响应体噪音
    assert dumped["dns"] is None
    assert dumped["risk"] is None
