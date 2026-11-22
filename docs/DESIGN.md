# 设计说明

这份文档解释**为什么**代码长成这样。改代码之前值得先看一遍——很多看起来"多余"的写法，
都是踩过坑之后留下的。

## 1. 并发模型：一条主线程 + 全协程

整个应用是单个事件循环上的 `asyncio`。没有线程池做网络 IO，没有多进程 worker。

理由：这类工具的瓶颈 100% 在网络等待（证书透明度 API、目标站点、DNS）。
协程能让"等 1000 个目标"与"等 1 个目标"在代码上完全一样，而线程模型会在 1000 线程时
先被内存和上下文切换拖垮。

代价：**任何一处同步阻塞调用都会卡住全部并发**。因此：

- 文件写入走 `asyncio.to_thread`（见 `_save_result`）；
- DER 证书解析走 `asyncio.to_thread`（畸形证书上 CPU 时间不可预测）；
- SQLite 读写走 `asyncio.to_thread`（见 `HistoryStore`）；
- 事件循环里没有 `time.sleep`，只有 `asyncio.sleep`。

## 2. 三条管线，墙钟取 max

```
Basic:  discover ─┐
        dns_intel ─┴─ gather  →  ScanData

Pro:    ensure_discovery ──┬─ probe (HTTP)      ─┐
                          └─ audit (DNS 扇出)   ─┴─ gather → ProScanData

Ultra:  ensure_discovery ──┬─ probe_with_bodies ─┐
                          ├─ audit              ├─ gather (max)
                          └─ cname_fanout       ─┘
                                  ↓
                           assemble_takeover   ← 纯 CPU，零额外墙钟
```

关键点：Ultra 的接管判定被**拆成两阶段**。

- 阶段 A（慢，IO）：CNAME 扇出只依赖子域名列表，因此能和探活、邮件审计完全并发；
- 阶段 B（快，纯 CPU）：拿到探活正文后做指纹交叉，墙钟可忽略。

如果把它们合成"一个依赖正文的函数"，就只能串行，总耗时变成三者之和而不是最大值。
这是这个项目里最容易被无意识破坏的性能设计。

## 3. 缓存：两段窗口 + fresh_ttl 覆盖

上游（crt.sh / CertSpotter / FOFA）零 SLA。若"没命中就现拉"，一旦上游抖动，用户拿到的
就是接口失败。

所以分两段：

| 窗口 | 行为 |
|---|---|
| `CACHE_TTL_SECONDS`（12h） | FRESH：直接返回 |
| `CACHE_STALE_MAX_SECONDS`（7d） | STALE：先返回旧的 + 后台静默刷新 |
| 超过 | MISS：同步现拉 |

`fresh_ttl` 是后来加的一层：**降级的残缺快照也值得缓存**（否则故障期间每次请求都要重打
上游），但不该被当权威结果。以 `fresh_ttl=0` 写入 → 永远判 STALE → 本次能秒回，
下次立刻重试。另有保护：已有 FRESH 的完整快照时，不会被降级快照覆盖。

时间基准用 `time.time()`（epoch）而不是 `monotonic`：后者是单进程相对时间，切 Redis /
多 worker 时无法跨进程比较。

抽象层（`CacheBackend`）把"存取删"与"fresh/stale 判定"分开，切 Redis 只需替换后端。

## 4. single-flight：缓存解决"先后"，它解决"同时"

真实场景里同一个域名经常被同时点好几次：用户双击、脚本重试、CI 并发、同事互发链接。
没有这层时，N 个并发请求各自去 crt.sh + CertSpotter + FOFA 拉一遍，再各自探活上千个子域。

- 第一个调用者是 leader，真正执行；其余 joined 直接 await 同一个 Task；
- follower 用 `asyncio.shield` 等待 —— 某个 HTTP 客户端断开导致自己协程被取消时，
  **不能**顺带取消别人还在等的那次扫描；
- 异常原样广播给每个 await 方；done_callback 里消费一次异常，避免
  "exception was never retrieved" 警告。

发现层一把锁（`_discovery_sf`），三条完整管线各一把（键带计划前缀），因此
"Basic + Pro + Ultra 同时请求同一域名"只会产生一次发现。

## 5. 降级语义：宁可说"不完整"，也不假装扫完

对外字段里有一组完整性信号，全部是刻意的设计：

| 字段 | 含义 |
|---|---|
| `degraded` | 骨干源（crt.sh / CertSpotter）全挂：子域名列表可能严重缺失 |
| `probe_complete` / `audit_complete` / `takeover_complete` | 该阶段是否被上限截断 |
| `probe_note` / `audit_note` / `takeover_note` | 英文人读说明（含 cap 与实际覆盖数） |
| `stale` | 返回的是过期快照 |

对外返回"最近但残缺"还是"略旧但完整"？**选后者**：现拉成功但 `degraded` 时，
如果还有 stale 完整快照，优先返回旧的。残缺数据会让人做出错误决策，而"略旧三小时"
几乎不影响任何决策。

## 6. 判定从严：宁可漏报也不制造假阳性

假阳性对安全工具是最贵的错误 —— 它让人去改根本不存在的配置，几次之后就没人看报告了。

- **接管**：只有"CNAME 指向托管商 **且** 正文命中该商悬空指纹"才判 High（`is_vulnerable`）。
  单信号进 Low 供人工复核，**不计入** `vulnerable_count`。CNAME 匹配只做后缀/整名/锚定
  正则，绝不做子串（`evil.s3.amazonaws.com.attacker.net` 必须判不通过）。
- **邮件**：子域缺 SPF 极常见（`api.` / `cdn.` 本来就不发信）。要结合"有无自己的 MX
  （真实邮件身份）"+"父域 DMARC `sp=` 是否兜底"分级，否则会瞬间吐出几百条假警告。
- **SPF 解析**：按 RFC 7208 token 化，而不是正则扫 `include:`。裸 `all` 等价 `+all`；
  裸 `a` / `mx` 也计入 DNS 查询数（超 10 次 = permerror = SPF 静默失效）。
- **无信号的子域不生成 finding**：否则超大域会吐出几百条"No takeover signal"垃圾，
  把真正的命中淹没。

## 7. 成本钉死

每个"会随目标数量增长"的动作都有一个显式上限：

| 上限 | 默认 | 为什么 |
|---|---|---|
| `PROBE_CONCURRENCY_CAP` | 120 | 不超本机 fd，也不把上游 WAF 打到封 IP |
| `PROBE_READ_MAX_BYTES` | 64 KiB | 单目标响应体：流式读取，读满立即断开 |
| `PROBE_OVERALL_TIMEOUT_SECONDS` | 12s | httpx 的 timeout 是"每次读"超时，持续滴水能永久占住槽位 |
| `PROBE_TLS_MAX_TARGETS` | 200 | 一次握手 ≈ 一次额外 TCP+TLS |
| `PRO_*_TARGETS` | 1000 | 单次请求的目标上限，超出显式标 `*_complete=false` |

配套的小优化：每目标独立随机 UA + 小抖动，打散整批请求的指纹特征；`crt.sh` 加
`deduplicate=Y` 让服务端先删重；源响应超过 `SOURCE_MAX_BYTES` 直接判该源失败而不是
把几十 MB 读进解析器。

### 一个实测数字

20 MiB 的畸形页面对比（本地流式服务器，见 `tests/test_probe_capped.py`）：

| | 实际下载 | 耗时 |
|---|---|---|
| 旧：`client.get()` 后切片 | 20.06 MiB | 86 ms |
| 新：流式读取到上限即断 | 0.31 MiB | 9 ms |

数据量 -98.5%，单目标耗时 -90%。带宽受限的真实链路上差距按比例放大。

## 8. 输入边界：域名会去三个危险的地方

域名是**攻击者可控值**，而它会进入：

1. **缓存键** —— `Basic + "pro::example.com"` 与 `Pro + "example.com"` 曾生成同一个键，
   两种数据结构互相覆盖；
2. **结果文件名** —— `"..\\..\\pwned"` 曾把 JSON 写到 `res/` 之外；
3. **DNS 查询与 URL** —— 含空格/斜杠/通配符的值会让下游解析器产生无意义请求。

所以有了 `app/core/domain.py`：一处 `normalize_domain`，所有入口（`ScanJobCreate`、
`/debug/scan`、`/dns`、`/history`、CLI）共用。它允许粘贴完整 URL（`https://user@host:8443/path`
会被抽出 host），但**不做"猜一个近似值"的静默修正** —— 猜错会扫到别人的资产。

落盘是最后一跳，所以还有第二道防线：文件名白名单消毒 + `path.parent` 包含性校验 +
先写临时文件再 `os.replace`。

## 9. Union 校验：`extra="forbid"` 不是洁癖

`ScanJobStatus.result` 是 `Union[ScanData, ProScanData, UltraScanData]`。若允许额外字段，
一个 Pro 结果被误判成 `ScanData` 时，`live_assets` / `email_audit` 会被**静默丢掉**而不报错 ——
那是最难查的一类数据丢失（接口 200、字段消失、没人知道为什么）。

`extra="forbid"` 让类型不匹配直接报错暴露问题。`ProScanData` 继承 `ScanData` 也保证了
两个对象共享 `dns` / `risk`，不需要在两个地方各写一遍。

## 10. 前端：不用 innerHTML

所有展示的数据（域名、页面 `<title>`、`Server` 头、证书主体、finding message）
**全部来自被扫描目标**，属于不可信输入。

把目标页面的标题塞进一个安全工具的界面上执行脚本，会是这个项目最讽刺的一个漏洞。
所以前端一律 `createElement` + `textContent`，配合 `script-src 'self'` 的严格 CSP。

## 11. 一致性保障

几处"同一件事写了三遍就会漂移"的地方被刻意收成一份：

- `_serve_cached`：Basic/Pro/Ultra 的 stale-while-revalidate 读路径（之前 Pro/Ultra 的兜底
  逻辑已经开始各写各的）；
- `build_payload`：落盘 / 导出 / diff 共用的结果 dict；
- `_probe_coverage_note`：Pro 与 Ultra 的覆盖度文案；
- `_is_fofa_noise` → `publicsuffix.embedded_registrable_domain`：噪声判定只有一处规则。
