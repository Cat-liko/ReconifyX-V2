# Changelog

本文件记录有意义的变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-11-22

第一个公开版本。相比内部的 0.1.0 PoC，这是一次完整的重写与加固：
补齐了输入边界、判定逻辑、性能瓶颈与可观测性，并加上命令行、导出、历史对比与打包。

### Added

- **命令行入口** `reconifyx`：`scan` / `dns` / `serve` / `version`，支持
  `--json` / `--csv` / `--md` 导出（`-` 表示 stdout），退化为非零退出码便于 CI 使用。
  `python -m reconifyx` 等价可用，`ReconifyX.exe scan ...` 同样可用。
- **DNS 情报**：主域 `A/AAAA/NS/MX/TXT/CAA/SOA` 与 SPF/DMARC 存在性，独立端点 `GET /dns`。
- **TLS 证书情报**：主体 / 签发者 / 有效期 / 剩余天数 / SAN 数 / 是否通过系统信任库验证 /
  协商的 TLS 版本与套件。验证失败时会再取一次证书原文，因此"过期证书"仍能给出到期时间。
- **安全响应头审计**：HSTS / CSP / X-Content-Type-Options / 点击劫持防护 / Cookie 属性 /
  CORS / 版本号泄露，输出 0-100 分与 A-F 等级。零额外网络成本（复用探活的响应头）。
- **风险总账**：0-100 加权分 + A-F 等级 + Critical/Warning/Info 计数 + 按严重度排序的
  聚合风险项（同 `code` 合并并带 `count`）。
- **扫描历史与差异对比**：SQLite 记录每次扫描的快照，`GET /scan/{id}/diff` 给出新增/消失的
  子域名、新上线/不再存活的 URL、新出现的接管信号、新增 IP。无历史时显式返回
  `baseline=true`，不会把"第一次看到的全部"伪装成新增。
- **导出**：`GET /scan/{id}/export?format=json|csv|md`。CSV 一行一个主机（带 UTF-8 BOM，
  Excel 直接打开不乱码），Markdown 为可直接粘贴进工单/PR 的报告。
- **批量扫描** `POST /scan/batch`，上限 `BATCH_MAX_DOMAINS`。
- **观测**：`/healthz`、`/readyz`、`/metrics`（Prometheus 文本格式，零第三方依赖）。
- **可选鉴权与限流**：`API_KEY`（常量时间比较）+ 每 IP 令牌桶，只作用于会对外发起探测的路径。
- **WebUI 重做**：多标签页、可过滤表格、明暗主题、导出按钮、批量模式、原始 JSON。
  前端拆成 `index.html` + `app.js` + `style.css`，配合严格 CSP。
- **工程配套**：`pyproject.toml`、`ruff.toml`、`Makefile`、`Dockerfile`、`docker-compose.yml`、
  GitHub Actions（lint / 4×2 测试矩阵 / 前端语法 / tag 自动出 exe）、Issue/PR 模板。

### Changed

- Pro / Ultra 复用 Basic 的发现结果（`_ensure_discovery`），先用 Basic 再上 Pro 不会白打一遍上游。
- 降级的残缺快照现在也会入缓存，但以 `fresh_ttl=0` 标记为"永远 STALE"：立刻可返回，
  同时立刻可重试。之前完全不缓存，导致故障期间同一域名的每次请求都要重打上游。
- `/debug/scan` 对未知计划返回 `400`（此前返回 `200` + `unavailable` 载荷，脚本会当成成功）。
- 任务状态改为"先落盘/写历史，最后才置 completed"，避免客户端看到 completed 却读不到 `saved_path`。
- TLS 面板区分"未取到证书（握手超时/连接失败）"与"证书验证失败"：前者不是安全发现，
  不应读起来像一张不合格的证书。

### Fixed

- **SPF 裸 `all` 被判为 Secure**：按 RFC 7208 §5.1，裸 `all` 等价 `+all`（任何 IP 可代发），
  旧实现因正则强制要求限定符而漏报最严重的一类配置。
- **不含 `all` 机制的 SPF 被判为 Secure**：隐式 `?all` 与显式 `?all` 同等无效，现统一按
  Neutral 处理（有强 DMARC 兜底时仍判 Secure）。
- **CNAME 子串匹配导致接管误报**：`evil.s3.amazonaws.com.attacker.net` 曾命中 AWS S3，
  叠加正文 `NoSuchBucket` 后产出"高置信可接管"。现只做后缀/整名/锚定正则匹配。
- **缓存键可被域名污染**：`Basic + domain="pro::example.com"` 与 `Pro + domain="example.com"`
  生成同一个缓存键，两种结构互相覆盖。现由 `normalize_domain` 在入口拦截。
- **路径穿越**：`domain_key` 直接拼进结果文件名，`"..\\..\\pwned"` 可写出到 `res/` 之外。
  现为白名单字符消毒 + 目录包含性校验 + 原子写。
- **探活无界下载**：旧实现把整个响应体收进内存再截断，实测一个 20 MiB 页面会被完整下载
  （86 ms / 20.06 MiB）；改为流式读取后为 9 ms / 0.31 MiB。
- **慢速滴水可占住并发槽**：新增单目标整体墙钟上限 `PROBE_OVERALL_TIMEOUT_SECONDS`。
- **FOFA 噪声过滤误杀合法子域**：`cn.example.com` / `io.example.com` 曾被当作"嵌了别人域名"
  丢弃；现按公共后缀（含 `com.cn` / `co.uk` 这类两标签后缀）判定。
- **SPF DNS 查询数漏计**：`v=spf1 a mx -all` 里的裸 `a` / `mx` 曾不被计数，低估 permerror 风险。
- **容量淘汰会踢掉正在跑的任务**：job 存储按 `created_at` 淘汰最老一条时不看状态，
  导致轮询中的任务突然 404。现只淘汰已终结任务；全部在跑时宁可暂时超限。
- **后台任务可能被 GC**：`asyncio.create_task` 的返回值未被持有，事件循环只持弱引用。
- **启动器端口竞态**：旧的 `connect_ex` 探测 + 让 uvicorn 再 bind 之间存在窗口；
  现改为自己 bind 成功后把 socket 交给 uvicorn。
- **`ScanData` 允许额外字段**：Pro 结果被 Union 误判成 ScanData 时会静默丢字段，现为 `extra="forbid"`。
- **`datetime.utcnow()` / `utcfromtimestamp()` 已废弃**。
- `.env.example` 里的占位 token 会让 CertSpotter 返回 401 并把整次扫描标成降级。
- **中文输出在非 CJK 环境的终端里直接崩溃**：stdout 是管道/文件时 Python 用 locale 编码，
  英文 Windows 上 `reconifyx --help | more` 会抛 `UnicodeEncodeError` 带 traceback 退出。
  现在非终端流强制 UTF-8 + `errors="replace"`（重定向出来的文件也终于是 UTF-8 了），
  并顺手把重定向流的全缓冲改成行缓冲 —— 否则 `serve > log.txt` 里的地址会一直卡在缓冲区。
- **`--json -` / `--csv -` 的输出不是纯文档**：人类可读摘要会一起打到 stdout，管道给 `jq`
  必然解析失败（注释写着"写 stdout 时不打印摘要"，但摘要在判断导出之前就打了）。
  现在只要有一个格式走 stdout，摘要就让路；两个格式同时走 stdout 直接按用法错误拒绝。
- **`httpx` 每条请求刷一行 INFO**：一次 Ultra 扫描能有上千行 `HTTP Request: GET ...`，
  淹没 CLI 的 stderr 与服务端日志。现默认压到 WARNING，`LOG_LEVEL=debug` 时再放开。
- **RFC 7505 的 null MX 被渲染成裸 `0`**：`MX 0 .` 的 exchange 是根域 `.`，被 `rstrip(".")`
  吃成空串后只剩一个 `0`，看着像"没有 MX 记录"，语义正好相反。现保留 `0 .` 并新增
  `dns.null_mx` 字段，CLI 与 WebUI 都会明确标注"该域声明不接收邮件"。
- **"可伪造邮件域"漏掉主域**：只统计 `spoofable_subdomains`，于是 `badssl.com` 这类
  "主域可伪造、子域干净"的目标显示 0，与同一份数据里的 `primary.is_spoofable=true` 自相矛盾。
- **401 没有 `WWW-Authenticate`**：RFC 7235 要求 401 告知认证方案，现返回
  `ApiKey realm="reconifyx", header="X-API-Key"`。
- **CLI `serve` 仍是 check-then-bind**：桌面模式早已改成"先 bind 再交给 uvicorn"，
  命令行这条路却还是让 uvicorn 自己 bind，且默认端口被占时直接退出。现两条路共用
  `app/core/net.py`：`--port` 显式给出时撞车就明确报错，未给出时依次退让到空闲端口。
- **浅色主题里原生控件还是深色**：缺 `color-scheme`，于是浅色背景下出现深色滚动条和
  "看着像已勾选"的深色复选框。现明暗主题各自声明 `color-scheme`。

### Security

- 域名输入白名单校验（也覆盖同步调试端点）。
- 结果落盘的文件名消毒 + 目录包含性校验 + 原子写。
- 可选 API Key（`hmac.compare_digest`）与每 IP 限流。
- 全站安全响应头 + 严格 CSP；前端不使用 `innerHTML`。
- 默认只监听回环地址。

## [0.1.0] - 内部 PoC

Basic / Pro / Ultra 三条管线的初版：证书透明度发现、FOFA 增强、HTTP 探活、SPF/DMARC 审计、
子域名接管检测、stale-while-revalidate 缓存、异步 job 轮询。未公开。
