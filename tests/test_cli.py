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


def test_serve_parser_defaults():
    args = cli.build_parser().parse_args(["serve"])
    assert args.command == "serve"
    assert args.port is None  # 用配置里的默认值,而不是写死 8000
    assert args.log_level == "info"


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
