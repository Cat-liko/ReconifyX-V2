"""命令行入口 —— 让 ReconifyX 既是 WebUI,也是一个能进管道的普通工具。

为什么值得有 CLI
----------------
WebUI 适合"看一眼";但真正要接进 CI / 定时任务 / 运维脚本时,需要的是:

    reconifyx scan example.com -p ultra --json out.json --md report.md

一个能返回退出码、能把结果写到指定文件、能静默运行的命令。此时起一个 HTTP 服务再让
脚本去轮询,纯属多此一举。

两种执行方式
------------
``scan`` / ``dns`` 默认**在进程内**直接跑管线(不起服务),复用与 API 完全相同的
函数,因此缓存、single-flight、降级语义都一致。
``serve`` 起 HTTP 服务,对应 WebUI。
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

#: 退出码:脚本据此判断结果,不要用 1 表示"扫到了风险" —— 那和"出错了"混在一起。
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_PLAN_CHOICES = ("basic", "pro", "ultra")

# ANSI 颜色
_COLORS = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


class _Painter:
    """极简着色器:非 tty 或 --no-color 时自动退化为纯文本。"""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: Any, *styles: str) -> str:
        text = str(text)
        if not self.enabled or not styles:
            return text
        prefix = "".join(_COLORS.get(s, "") for s in styles)
        return f"{prefix}{text}{_COLORS['reset']}"


def _version() -> str:
    from app.core.config import get_settings

    return get_settings().VERSION


def _project_name() -> str:
    from app.core.config import get_settings

    return get_settings().PROJECT_NAME


# ==================== 输出 ====================


def _fmt_int(value: Any) -> str:
    if value is None:
        return "0"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def _section(title: str, p: _Painter) -> None:
    print()
    print(p(title, "bold", "cyan"))
    print(p("─" * 60, "dim"))


def _kv(label: str, value: Any, p: _Painter, level: Optional[str] = None) -> None:
    pad = "  " + label.ljust(14)
    text = _fmt_int(value)
    if level == "critical":
        text = p(text, "red", "bold")
    elif level == "warn":
        text = p(text, "yellow")
    print(f"{pad}{text}")


def _print_summary(
    payload: Dict[str, Any], sources: Sequence[Any], p: _Painter, show_subdomains: int = 15
) -> None:
    result: Dict[str, Any] = payload.get("result") or {}
    domain = payload.get("domain", "?")
    plan = payload.get("plan", "?")

    print()
    print(p(f"{_project_name()} v{_version()}", "bold") + p(f"  ·  {plan}  ·  {domain}", "dim"))

    _section("概览", p)
    _kv("子域名", result.get("total_found", 0), p)
    _kv("IP 资产", result.get("total_assets", 0), p)
    if "total_live" in result:
        _kv("存活主机", result.get("total_live", 0), p)
    takeover = result.get("takeover") or {}
    if takeover:
        count = takeover.get("vulnerable_count", 0)
        _kv("可接管", count, p, "critical" if count else None)
    email = result.get("email_audit") or {}
    if email:
        count = email.get("spoofable_subdomains", 0)
        _kv("可伪造邮件域", count, p, "warn" if count else None)
    risk = result.get("risk") or {}
    if risk:
        _kv("风险分", f"{risk.get('risk_score', 0)}/100 ({risk.get('grade', '-')})", p)

    if payload.get("degraded"):
        print()
        print(p("⚠ 数据源降级:结果可能不完整(骨干证书透明度源全部失败)", "yellow"))

    # ---- 风险项 ----
    items: List[Dict[str, Any]] = risk.get("items") or []
    if items:
        _section("风险项", p)
        for item in items[:12]:
            sev = str(item.get("severity") or "")
            style = "red" if sev == "Critical" else ("yellow" if sev == "Warning" else "dim")
            subject = item.get("subject") or "-"
            print(
                "  "
                + p(sev.ljust(8), style)
                + " "
                + p(str(item.get("code", "")).ljust(28), "bold")
                + p(f"x{item.get('count', 0)}", "dim")
                + "  "
                + subject
            )

    # ---- 接管 ----
    findings = takeover.get("findings") or []
    if findings:
        _section("子域名接管", p)
        for f in findings[:15]:
            flag = p("VULN", "red", "bold") if f.get("is_vulnerable") else p("REVIEW", "yellow")
            provider = f.get("matched_provider") or "-"
            print(f"  {flag}  {f.get('domain', ''):<45} {provider}")

    # ---- 子域名样本 ----
    subdomains = result.get("subdomains") or []
    if subdomains and show_subdomains > 0:
        _section(f"子域名(前 {min(show_subdomains, len(subdomains))} 个)", p)
        for host in subdomains[:show_subdomains]:
            print("  " + host)
        if len(subdomains) > show_subdomains:
            print(p(f"  … 其余 {len(subdomains) - show_subdomains} 个见导出文件", "dim"))

    # ---- DNS ----
    dns = result.get("dns") or {}
    if dns:
        _section("DNS", p)
        for key, label in (("a", "A"), ("aaaa", "AAAA"), ("ns", "NS"), ("mx", "MX")):
            values = dns.get(key) or []
            if values:
                print(f"  {label.ljust(6)} {', '.join(str(v) for v in values[:4])}")
        flags = []
        if dns.get("has_spf"):
            flags.append("SPF")
        if dns.get("has_dmarc"):
            flags.append("DMARC")
        if dns.get("caa"):
            flags.append("CAA")
        print("  记录   " + (", ".join(flags) if flags else p("无 SPF/DMARC/CAA", "yellow")))

    # ---- 数据源 ----
    if sources:
        _section("数据源", p)
        for src in sources:
            ok = bool(getattr(src, "ok", False))
            mark = p("ok  ", "green") if ok else p("fail", "red")
            detail = getattr(src, "detail", "") or ""
            print(
                f"  {mark}  {str(getattr(src, 'name', '?')):<12}"
                f"{_fmt_int(getattr(src, 'count', 0)):>8}  {p(detail, 'dim')}"
            )


# ==================== 子命令 ====================


def _do_scan(args: argparse.Namespace) -> int:
    from app.main import build_payload, scan_domain, settings
    from app.services import export_service

    p = _Painter(_use_color(args))

    started = time.time()
    try:
        domain_key, plan_norm, data, degraded, sources = asyncio.run(
            scan_domain(args.domain, args.plan)
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI 边界:任何异常都变成可读错误 + 退出码
        print(f"error: scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    finished = time.time()
    payload = build_payload(
        job_id=f"cli-{uuid4().hex[:12]}",
        domain_key=domain_key,
        plan_norm=plan_norm,
        result=data,
        degraded=degraded,
        sources=sources,
        created_at=started,
        finished_at=finished,
        elapsed_ms=int((finished - started) * 1000),
    )

    if not args.quiet:
        _print_summary(payload, sources, p)

    # ---- 导出 ----
    written: List[Path] = []
    out_dir = Path(args.outdir or settings.RESULT_DIR)
    requests = {
        "json": args.json,
        "csv": args.csv,
        "md": args.md,
    }
    for fmt, target in requests.items():
        if target is None:
            continue
        content, _mime, _ext = export_service.render(fmt, payload)
        if target == "-":
            # 写 stdout 时不打印摘要,避免机器解析被人类文案污染
            sys.stdout.write(content if content.endswith("\n") else content + "\n")
            continue
        path = Path(target)
        if path.is_dir():
            path = path / export_service.suggested_filename(payload, fmt)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {path}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        written.append(path)

    # 没指定任何导出时,默认落一份 json 到结果目录(与 API 行为一致)
    if not any(v is not None for v in requests.values()) and not args.no_save:
        content, _mime, _ext = export_service.render("json", payload)
        path = out_dir / export_service.suggested_filename(payload, "json")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            written.append(path)
        except OSError as exc:
            print(f"warning: cannot write {path}: {exc}", file=sys.stderr)

    if written and not args.quiet:
        _section("已写出", p)
        for path in written:
            print("  " + str(path))

    if degraded and not args.allow_degraded:
        # 数据不可信时不要静默返回 0:CI 里这应该是一次失败
        print(
            "error: result is degraded (backbone sources failed); "
            "pass --allow-degraded to accept it anyway",
            file=sys.stderr,
        )
        return EXIT_ERROR

    return EXIT_OK


def _do_dns(args: argparse.Namespace) -> int:
    from app.core.config import get_settings
    from app.core.domain import normalize_domain
    from app.services import dns_service

    settings = get_settings()
    try:
        domain_key = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        intel = asyncio.run(dns_service.collect(domain_key, settings))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"error: dns lookup failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if intel is None:
        print("error: DNS intel is disabled (DNS_INTEL_ENABLED=false)", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(intel.model_dump(), ensure_ascii=False, indent=2))
        return EXIT_OK

    p = _Painter(_use_color(args))
    print()
    print(p(f"DNS · {domain_key}", "bold"))
    _section("记录", p)
    for key, label in (
        ("a", "A"),
        ("aaaa", "AAAA"),
        ("ns", "NS"),
        ("mx", "MX"),
        ("txt", "TXT"),
        ("caa", "CAA"),
    ):
        values = getattr(intel, key) or []
        if not values:
            continue
        for idx, value in enumerate(values):
            prefix = label.ljust(6) if idx == 0 else " " * 6
            print(f"  {prefix} {value}")
    if intel.soa:
        print(f"  {'SOA':<6} {intel.soa}")
    print()
    print(
        "  "
        + (p("SPF", "green") if intel.has_spf else p("no SPF", "yellow"))
        + "  "
        + (p("DMARC", "green") if intel.has_dmarc else p("no DMARC", "yellow"))
        + "  "
        + (p("CAA", "green") if intel.caa else p("no CAA", "yellow"))
        + ("  " + p("resolved", "dim") if intel.resolved else "  " + p("no A/AAAA", "red"))
    )
    return EXIT_OK


def _do_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from app.core.config import get_settings

    settings = get_settings()
    host = args.host or settings.HOST
    port = args.port or settings.PORT

    if host not in ("127.0.0.1", "localhost", "::1") and not settings.API_KEY:
        print(
            "warning: binding to a non-loopback address without API_KEY. "
            "Anyone who can reach this port can use it to probe arbitrary domains. "
            "Set API_KEY before exposing it.",
            file=sys.stderr,
        )

    print(f"{_project_name()} v{_version()} → http://{host}:{port}/")
    try:
        uvicorn.run(
            "app.main:app",
            host=host,
            port=port,
            log_level=args.log_level,
            reload=args.reload,
        )
    except KeyboardInterrupt:
        return EXIT_OK
    return EXIT_OK


def _do_version(_args: argparse.Namespace) -> int:
    print(f"{_project_name()} {_version()}")
    return EXIT_OK


# ==================== argparse ====================


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001 - 某些打包环境下 stdout 没有 isatty
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconifyx",
        description="ReconifyX —— 本地攻击面管理:子域名发现 / 探活审计 / 接管检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  reconifyx scan example.com            # Basic,最快\n"
            "  reconifyx scan example.com -p ultra   # 全家桶\n"
            "  reconifyx scan example.com --json out.json --md report.md\n"
            "  reconifyx dns example.com\n"
            "  reconifyx serve --port 8000\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {_version()}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- scan ----
    scan = sub.add_parser("scan", help="扫描一个域名并输出结果")
    scan.add_argument("domain", help="主域名,如 example.com(可粘贴完整 URL)")
    scan.add_argument(
        "-p",
        "--plan",
        default="basic",
        choices=_PLAN_CHOICES,
        help="扫描深度(默认 basic)",
    )
    scan.add_argument("-o", "--outdir", help="默认 json 落盘目录(默认 res/)")
    scan.add_argument("--json", metavar="PATH", help="导出 JSON(PATH 为 - 时写到 stdout)")
    scan.add_argument("--csv", metavar="PATH", help="导出 CSV(一行一个主机)")
    scan.add_argument("--md", metavar="PATH", help="导出 Markdown 报告")
    scan.add_argument("--no-save", action="store_true", help="不写任何文件")
    scan.add_argument(
        "--allow-degraded",
        action="store_true",
        help="即使骨干数据源降级也返回退出码 0(默认判失败,便于 CI 感知)",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="不打印人类可读摘要")
    scan.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    scan.set_defaults(func=_do_scan)

    # ---- dns ----
    dns = sub.add_parser("dns", help="只查 DNS 记录(不跑子域名发现)")
    dns.add_argument("domain", help="主域名")
    dns.add_argument("--json", action="store_true", help="输出 JSON")
    dns.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    dns.set_defaults(func=_do_dns)

    # ---- serve ----
    serve = sub.add_parser("serve", help="启动 HTTP 服务 + WebUI")
    serve.add_argument("--host", help="监听地址(默认取 HOST 配置,通常是 127.0.0.1)")
    serve.add_argument("--port", type=int, help="监听端口(默认取 PORT 配置)")
    serve.add_argument(
        "--log-level",
        default="info",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        help="uvicorn 日志级别",
    )
    serve.add_argument("--reload", action="store_true", help="开发模式:改动自动重载")
    serve.set_defaults(func=_do_serve)

    # ---- version ----
    ver = sub.add_parser("version", help="打印版本")
    ver.set_defaults(func=_do_version)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI 入口。返回退出码(不直接 sys.exit,便于测试与作为库调用)。"""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except BrokenPipeError:
        # 被 `| head` 之类截断:安静退出,不要刷一堆 traceback
        return EXIT_OK
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
