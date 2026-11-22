"""指标渲染:输出必须是合法的 Prometheus 文本暴露格式。"""

import re

from app.core.metrics import Metrics

_LINE_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?\d+(\.\d+)?$")


def test_counter_accumulates_and_gauge_overwrites():
    m = Metrics()
    m.describe("x_total", "counter", "help")
    m.inc("x_total")
    m.inc("x_total", 2)
    m.gauge("x_now", 5)
    m.gauge("x_now", 7)

    text = m.render()
    assert "# HELP x_total help" in text
    assert "# TYPE x_total counter" in text
    assert "x_total 3" in text
    assert "x_now 7" in text
    assert "x_now 5" not in text


def test_labels_are_sorted_and_escaped():
    m = Metrics()
    m.inc("req", 1, zeta="z", alpha="a")
    m.inc("req", 1, alpha='a"b')
    text = m.render()
    # label 顺序稳定,便于 diff 与抓取
    assert 'req{alpha="a",zeta="z"} 1' in text
    # 引号必须被转义
    assert 'alpha="a\\"b"' in text


def test_non_integer_float_rendered_with_decimals():
    m = Metrics()
    m.gauge("ratio", 0.5)
    assert "ratio 0.5" in m.render()


def test_every_data_line_is_well_formed():
    m = Metrics()
    m.inc("a_total", 3, path="/scan", status="200")
    m.gauge("b_gauge", 0)
    lines = [ln for ln in m.render().splitlines() if not ln.startswith("#")]
    assert lines
    for line in lines:
        assert _LINE_RE.match(line), line


def test_render_empty_is_empty():
    assert Metrics().render() == ""
