"""进程内指标 —— 零依赖,手写 Prometheus 文本暴露格式。

为什么不引 prometheus_client
----------------------------
那个库会把整个 ``prometheus_client`` 打进 PyInstaller 单文件包(约 1 MB),还带来
它自己的 multiprocess 目录约定。本项目是单进程本地服务,需要的只是十几个计数器。
自己实现 60 行,换掉一个依赖 + 更小的二进制体积,划算。

语义约定
--------
- counter(``inc``):只增不减,用于请求数 / 扫描数 / 错误数;
- gauge(``gauge``):瞬时值,每次采到就覆盖,用于队列长度 / 缓存条目数。
只在事件循环里读写,因此不需要锁(所有写入点都是协程)。
"""

from typing import Dict, List, Optional, Tuple


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _label_key(labels: Dict[str, str]) -> str:
    """稳定排序的 label 串:同一组 label 必须永远映射到同一个 key 上。"""
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(str(v))}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


def _num(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return repr(round(value, 6))


class Metrics:
    """登记表 + 一个计数器/仪表盘混合容器。"""

    def __init__(self) -> None:
        self._series: Dict[str, Dict[str, float]] = {}
        self._meta: Dict[str, Tuple[str, str]] = {}

    def describe(self, name: str, kind: str, help_text: str) -> None:
        """声明指标类型与说明(只影响 HELP/TYPE 注释行)。"""
        self._meta[name] = (kind, help_text)

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        series = self._series.setdefault(name, {})
        key = _label_key(labels)
        series[key] = series.get(key, 0.0) + value

    def gauge(self, name: str, value: float, **labels: str) -> None:
        self._series.setdefault(name, {})[_label_key(labels)] = float(value)

    def render(self) -> str:
        lines: List[str] = []
        for name in sorted(self._series):
            kind, help_text = self._meta.get(name, ("gauge", name))
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {kind}")
            for labels, value in sorted(self._series[name].items()):
                lines.append(f"{name}{labels} {_num(value)}")
        return "\n".join(lines) + ("\n" if lines else "")

    def reset(self) -> None:
        """清空(测试用)。"""
        self._series.clear()


METRICS = Metrics()

# ---- 指标声明(集中在这里,避免散落各处拼错名字)----
METRICS.describe("reconifyx_requests_total", "counter", "HTTP requests handled")
METRICS.describe("reconifyx_request_seconds_sum", "counter", "Total request handling time")
METRICS.describe("reconifyx_rate_limited_total", "counter", "Requests rejected by rate limiter")
METRICS.describe("reconifyx_auth_failed_total", "counter", "Requests rejected by API key check")
METRICS.describe("reconifyx_scans_total", "counter", "Scan jobs that reached a terminal state")
METRICS.describe("reconifyx_scan_failures_total", "counter", "Scan jobs that failed")
METRICS.describe("reconifyx_scan_seconds_sum", "counter", "Total scan execution time")
METRICS.describe("reconifyx_jobs", "gauge", "Scan jobs currently held in memory")
METRICS.describe("reconifyx_cache_entries", "gauge", "Entries in the result cache")
METRICS.describe("reconifyx_cache_events_total", "counter", "Cache lookups by outcome")
METRICS.describe("reconifyx_singleflight_total", "counter", "Single-flight events")
METRICS.describe("reconifyx_history_scans", "gauge", "Scan snapshots stored in history DB")
METRICS.describe("reconifyx_history_domains", "gauge", "Distinct domains in history DB")
METRICS.describe("reconifyx_build_info", "gauge", "Build information")


def observe_request(path: str, status: int, seconds: float) -> None:
    METRICS.inc("reconifyx_requests_total", path=path, status=str(status))
    METRICS.inc("reconifyx_request_seconds_sum", seconds)


def render_text(extra_gauges: Optional[Dict[str, float]] = None) -> str:
    """渲染全部指标。``extra_gauges`` 用于临时注入几个采集时才拿得到的值。"""
    for name, value in (extra_gauges or {}).items():
        METRICS.gauge(name, value)
    return METRICS.render()
