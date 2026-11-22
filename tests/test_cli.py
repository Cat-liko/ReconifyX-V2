"""CLI:参数解析、退出码、与打包版本号的一致性。"""

from pathlib import Path

import pytest

from app.core.config import get_settings
from reconifyx import cli


def test_version_matches_packaging_metadata():
    """pyproject 与运行时版本号必须一致,否则 pip 包和 --version 会对不上。"""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    declared = None
    for line in text.splitlines():
        if line.startswith("version = "):
            declared = line.split("=", 1)[1].strip().strip('"')
            break
    assert declared == get_settings().VERSION


def test_version_command(capsys):
    assert cli.main(["version"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "ReconifyX" in out
    assert get_settings().VERSION in out


def test_scan_parser_defaults():
    args = cli.build_parser().parse_args(["scan", "Example.COM"])
    assert args.command == "scan"
    assert args.domain == "Example.COM"
    assert args.plan == "basic"
    assert args.json is None
    assert args.allow_degraded is False


def test_scan_parser_rejects_unknown_plan():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["scan", "example.com", "-p", "enterprise"])


def test_scan_rejects_invalid_domain_without_network(capsys):
    """域名校验发生在任何网络调用之前 —— 非法输入必须快速失败。"""
    code = cli.main(["scan", "localhost"])
    assert code == cli.EXIT_USAGE
    assert "invalid domain" in capsys.readouterr().err


def test_dns_rejects_invalid_domain(capsys):
    assert cli.main(["dns", "not a domain"]) == cli.EXIT_USAGE
    assert capsys.readouterr().err


def test_dns_command_explains_a_null_mx(monkeypatch, capsys):
    """`MX 0 .` 单独出现没人看得懂,必须带一句 RFC 7505 的解释。"""
    from app.schemas.scan import DnsIntel
    from app.services import dns_service

    async def _fake_collect(domain, _settings):
        return DnsIntel(
            domain=domain, a=["192.0.2.1"], mx=["0 ."], null_mx=True, resolved=True
        )

    monkeypatch.setattr(dns_service, "collect", _fake_collect)

    assert cli.main(["dns", "example.com", "--no-color"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "0 ." in out
    assert "Null MX" in out
    assert "RFC 7505" in out


def test_serve_parser_defaults():
    args = cli.build_parser().parse_args(["serve"])
    assert args.command == "serve"
    assert args.port is None  # 用配置里的默认值,而不是写死 8000
    assert args.log_level == "info"


def test_serve_on_occupied_explicit_port_fails_clearly(capsys):
    """`serve --port N` 撞端口时必须报错退出,而不是抛 uvicorn 的堆栈。"""
    import socket

    taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    taken.bind(("127.0.0.1", 0))
    taken.listen(4)
    port = taken.getsockname()[1]
    try:
        code = cli.main(["serve", "--port", str(port)])
    finally:
        taken.close()

    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert "in use" in err
    assert "Traceback" not in err


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_painter_disabled_produces_plain_text():
    paint = cli._Painter(False)
    assert paint("hello", "bold") == "hello"


def test_painter_enabled_wraps_in_ansi():
    paint = cli._Painter(True)
    assert "\033[" in paint("hello", "red")


def test_fmt_int_handles_bad_input():
    assert cli._fmt_int(1234) == "1,234"
    assert cli._fmt_int(None) == "0"
    assert cli._fmt_int("nope") == "nope"


def test_help_survives_a_locale_that_cannot_encode_chinese():
    """回归:英文 Windows 上 `reconifyx --help | more` 曾带着 traceback 崩掉。

    ``PYTHONIOENCODING=cp437`` 精确复现了那个环境(stdout 是管道 + locale 编不出中文)。
    修复后输出应该是合法的 UTF-8,退出码 0。
    """
    import os
    import subprocess
    import sys

    root = Path(__file__).resolve().parent.parent
    env = dict(os.environ, PYTHONIOENCODING="cp437", PYTHONPATH=str(root))
    proc = subprocess.run(
        [sys.executable, "-m", "reconifyx", "--help"],
        cwd=str(root),
        env=env,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    text = proc.stdout.decode("utf-8")  # 必须是 UTF-8,否则抛 UnicodeDecodeError
    assert "ReconifyX" in text
    assert "Traceback" not in text


# ==================== 导出到 stdout 的纯度 ====================


def _stub_scan(monkeypatch):
    """把扫描层换成立即返回的空结果,让导出路径可以离线断言。"""
    import app.main as app_main

    async def _fake_scan(domain, plan):
        data = app_main.ScanData(total_found=0, subdomains=[], total_assets=0, assets=[])
        return ("example.com", "basic", data, False, [])

    monkeypatch.setattr(app_main, "scan_domain", _fake_scan)


def test_json_to_stdout_is_pure_json(monkeypatch, capsys):
    """回归:`--json -` 曾把人类可读摘要也打到 stdout,管道给 jq 就解析失败。"""
    import json

    _stub_scan(monkeypatch)
    code = cli.main(["scan", "example.com", "--json", "-", "--no-save", "--no-color"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    payload = json.loads(out)  # 整段 stdout 必须能被一次解析
    assert payload["domain"] == "example.com"
    assert "ReconifyX v" not in out  # 横幅不能混进来


def test_csv_to_stdout_is_pure_csv(monkeypatch, capsys):
    _stub_scan(monkeypatch)
    code = cli.main(["scan", "example.com", "--csv", "-", "--no-save", "--no-color"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert out.lstrip().startswith("\ufeff") or out.splitlines()[0].startswith("domain")
    assert "ReconifyX v" not in out


def test_two_formats_to_stdout_is_a_usage_error(monkeypatch, capsys):
    """两个文档挤一个 stdout 会互相破坏,必须当场拒绝而不是产出拼接垃圾。"""

    async def _explode(*_args, **_kw):  # pragma: no cover - 被调用即失败
        raise AssertionError("usage error should be raised before the scan")

    import app.main as app_main

    monkeypatch.setattr(app_main, "scan_domain", _explode)
    code = cli.main(["scan", "example.com", "--json", "-", "--md", "-", "--no-color"])

    assert code == cli.EXIT_USAGE
    assert "only one format" in capsys.readouterr().err


# ==================== 概览里的"可伪造邮件域" ====================


def _summary_for(capsys, primary_spoofable, subdomains_spoofable):
    payload = {
        "domain": "example.com",
        "plan": "Pro",
        "result": {
            "total_found": 1,
            "email_audit": {
                "primary": {"is_spoofable": primary_spoofable},
                "spoofable_subdomains": subdomains_spoofable,
            },
        },
    }
    cli._print_summary(payload, [], cli._Painter(False))
    out = capsys.readouterr().out
    line = next(row for row in out.splitlines() if "可伪造邮件域" in row)
    return line.split()[-1]


def test_summary_counts_spoofable_primary_domain(capsys):
    """badssl.com 那种"主域可伪造、子域干净"的目标曾显示 0,与详情页矛盾。"""
    assert _summary_for(capsys, True, 0) == "1"


def test_summary_adds_primary_and_subdomains(capsys):
    assert _summary_for(capsys, True, 2) == "3"


def test_summary_is_zero_when_nothing_is_spoofable(capsys):
    assert _summary_for(capsys, False, 0) == "0"
