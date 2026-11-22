"""TLS 情报:证书字典解析与判定(不依赖真实网络)。"""

import ssl

from app.core.config import Settings
from app.services import tls_service

S = Settings()

CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": (
        (("commonName", "Test CA"),),
        (("organizationName", "Test Org"),),
    ),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2099 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}

EXPIRED_CERT = {
    "subject": ((("commonName", "*.old.example"),),),
    "issuer": ((("commonName", "Old CA"),),),
    "notBefore": "Jan  1 00:00:00 2015 GMT",
    "notAfter": "Jan  1 00:00:00 2016 GMT",
    "subjectAltName": (),
}

SELF_SIGNED_CERT = {
    "subject": ((("commonName", "self.example"),),),
    "issuer": ((("commonName", "self.example"),),),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2099 GMT",
    "subjectAltName": (),
}


class FakeSSLObject:
    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


def test_name_field_reads_first_match():
    assert tls_service._name_field(CERT["subject"], "commonName") == "example.com"
    assert tls_service._name_field(CERT["issuer"], "organizationName") == "Test Org"
    assert tls_service._name_field(CERT["subject"], "organizationName") is None
    assert tls_service._name_field((), "commonName") is None


def test_cert_time_conversion():
    assert tls_service._cert_time_iso("Jan  1 00:00:00 2026 GMT") == "2026-01-01T00:00:00Z"
    assert tls_service._cert_time_iso(None) is None
    assert tls_service._cert_time_iso("not a date") is None


def test_days_left_positive_for_future_cert():
    days = tls_service._days_left(CERT["notAfter"])
    assert days is not None and days > 0
    assert tls_service._days_left(None) is None


def test_verified_cert_gets_full_fields():
    info = tls_service._build(
        "example.com", 443, CERT, FakeSSLObject(), S, verified=True
    )
    assert info.verified is True
    assert info.subject == "example.com"
    assert info.issuer == "Test CA"
    assert info.not_after == "2099-01-01T00:00:00Z"
    assert info.days_left > 0
    assert info.expired is False
    assert info.self_signed is False
    assert info.san_count == 2
    assert info.tls_version == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.error is None


def test_expired_cert_marked_expired():
    info = tls_service._build("old.example", 443, EXPIRED_CERT, None, S, verified=False,
                              verification_error="certificate has expired")
    assert info.expired is True
    assert info.days_left is not None and info.days_left < 0
    assert info.expiring_soon is False
    assert info.verification_error == "certificate has expired"


def test_self_signed_detected_by_equal_subject_and_issuer():
    info = tls_service._build("self.example", 443, SELF_SIGNED_CERT, None, S, verified=False)
    assert info.self_signed is True


def test_missing_certificate_is_reported_honestly():
    info = tls_service._build("x.example", 443, None, None, S, verified=True)
    assert info.verified is True
    assert info.subject is None
    assert info.error == "no peer certificate exposed"


def test_unverified_cert_keeps_error_text():
    info = tls_service._build(
        "x.example", 443, None, None, S, verified=False,
        error="certificate not trusted: self-signed certificate",
        verification_error="self-signed certificate",
    )
    assert info.error.startswith("certificate not trusted")
    assert info.verification_error == "self-signed certificate"


def test_decode_der_returns_none_for_empty_input():
    assert tls_service._decode_der(None) is None
    assert tls_service._decode_der(b"") is None
    # 垃圾字节:两条解析路线都失败,必须安静返回 None 而不是抛
    assert tls_service._decode_der(b"\x00\x01\x02") is None


def test_verification_reason_extraction():
    exc = ssl.SSLCertVerificationError(1, "certificate verify failed: foo")
    # CPython 会把 verify_message 填上;没有时退化为整条消息
    assert tls_service._verification_reason(exc)


def test_expiring_soon_threshold_is_configurable():
    strict = Settings(TLS_EXPIRY_WARN_DAYS=100000)
    info = tls_service._build("example.com", 443, CERT, None, strict, verified=True)
    assert info.expiring_soon is True
