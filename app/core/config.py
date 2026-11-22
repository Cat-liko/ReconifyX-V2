from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """全局配置。所有敏感项从环境变量 / .env 读取,严禁硬编码在业务逻辑中。"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # 项目元信息
    PROJECT_NAME: str = "ReconifyX"
    VERSION: str = "1.0.0"
    PLAN_BASIC: str = "Basic"

    # ==================== 服务运行(CLI / 容器 / 本地) ====================
    # 默认只监听回环:本工具会主动向目标发起探测,绝不应该在用户不知情时暴露到
    # 局域网/公网。要对外提供服务,必须显式改 HOST(此时强烈建议同时设 API_KEY)。
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    LOG_LEVEL: str = "info"

    # 可选 API Key:非空时,所有"会对外发起探测"的端点都要求 X-API-Key 头。
    # 留空 = 不鉴权(适合本机单人使用)。绑定非回环地址时务必设置。
    API_KEY: str = ""
    # 每 IP 每分钟允许的 API 请求数(令牌桶)。仅约束 API,不约束静态页。
    # 目的是防止误把服务暴露出去后被当作免费代理刷爆,不是安全边界(真正的边界是 API_KEY)。
    RATE_LIMIT_PER_MINUTE: int = 240
    # 桶容量 = 允许的瞬时突发量(冷启动时一次最多放这么多请求进来)
    RATE_LIMIT_BURST: int = 60
    # 批量扫描接口单次最多接受的域名数
    BATCH_MAX_DOMAINS: int = 20

    # 缓存:fresh 窗口 12 小时 = 43200 秒(命中直接返回)
    CACHE_TTL_SECONDS: int = 12 * 60 * 60
    # stale 窗口:fresh 过期后仍可"先返回旧的+后台刷新"的最长存活期 = 7 天。
    # 超过此期才视同未命中、强制同步现拉。上游抖动 → 退化成"数据略旧"而非"接口失败"。
    CACHE_STALE_MAX_SECONDS: int = 7 * 24 * 60 * 60
    CACHE_MAXSIZE: int = 1024

    # ---- 免费被动子域名数据源(Basic 发现引擎)----
    # 单个源的 HTTP 超时(秒);任一源失败不影响其他源
    SOURCE_TIMEOUT_SECONDS: float = 12.0
    # 单源响应体上限:超过即判该源失败并如实上报 degraded,而不是把几十上百 MB
    # 的全量证书日志读进内存后再解析(证书透明度源对大域名会返回超大 JSON)。
    SOURCE_MAX_BYTES: int = 32 * 1024 * 1024
    # 本地自部署无网关限制:所有源并发跑完、各自受 SOURCE_TIMEOUT_SECONDS 单条超时约束,
    # 不再设整体墙钟截止,慢的增强源也自然跑完以收全结果。
    # crt.sh 证书透明度日志(无需 key,但后端偶发 502/超时,配重试)
    # certspotter 是热备,crt.sh 不必过度重试,以免拖慢骨干阶段
    CRTSH_URL: str = "https://crt.sh/"
    CRTSH_RETRIES: int = 1  # 首发失败后额外重试次数
    CRTSH_RETRY_BACKOFF: float = 1.0  # 重试间隔基数(秒),指数退避
    # CertSpotter 证书透明度日志(与 crt.sh 同类,做热备;匿名可用,配 key 限额更高)
    CERTSPOTTER_URL: str = (
        "https://api.certspotter.com/v1/issuances"
        "?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    CERTSPOTTER_TOKEN: str = ""  # 可选:https://sslmate.com/certspotter/ 免费注册

    # ---- FOFA 第三方中转站(增强源:唯一能带出 IP+端口+指纹,补齐 assets)----
    # 这是借用的私人中转,非官方 API:稳定性/合规性不受我们控制,故设为"增强源"——
    # 它挂了不影响 degraded 判定(骨干仍是证书透明度),只是 assets 会退化为空。
    # 鉴权:密码 POST 到解锁页换取 mk_encrypt cookie(Max-Age=1h),故每次查询前重新登录。
    # 密码为敏感项,经环境变量 FOFA_PASSWORD 注入;留空则整个 FOFA 源自动禁用。
    FOFA_PASSWORD: str = ""
    FOFA_UNLOCK_URL: str = "https://fofx.hacktwohub.us/fofa-vip"       # 密码解锁页
    FOFA_QUERY_URL: str = "https://fofx.hacktwohub.us/function.php"    # 查询后端
    FOFA_PWD_FIELD: str = "pagepwd"   # 解锁表单的密码字段名
    FOFA_RESULT_SIZE: int = 100       # 单次查询取回条数(fofa_ts)
    # FOFA 瞬时抖动重试:中转站是三方 VPS,密集访问偶发 TCP 连不上(ConnectError)。
    # 只对"连接层"瞬时错误退避重试,不对 error=true / bad json 重试(那是稳定故障,重试无用)。
    FOFA_RETRIES: int = 1             # 连接层失败后额外重试次数
    FOFA_RETRY_BACKOFF: float = 0.8   # 重试间隔基数(秒),指数退避
    # FOFA 去噪:domain= 是模糊命中,常混入别人拿本域当反代/DNS 后缀拼出的脏数据
    # (如 aaa.bbb.chinaoct.com.example.com)。子域层级超过此值视为拼接噪声,丢弃。
    FOFA_MAX_SUB_DEPTH: int = 5

    # 深度测绘(host/search)翻页控制 —— 预留给 Pro / Ultra,Basic 不使用
    SEARCH_MAX_PAGES: int = 1
    SEARCH_PAGE_SIZE: int = 100

    # ==================== Pro 计划:高并发探活 + 邮件安全审计 ====================
    PLAN_PRO: str = "Pro"
    # 探活并发上限。注意:全程 asyncio 协程,不是线程。实际并发 = min(目标数, 此上限),
    # 即"按发现的子域名数量动态收敛,但绝不超 120",避免小域名也开满 120 个空信号量。
    PROBE_CONCURRENCY_CAP: int = 120
    PROBE_TIMEOUT_SECONDS: float = 8.0
    # 单目标探活的整体墙钟上限(秒)。httpx 的 timeout 是"每次读"的超时,
    # 一个持续滴水的服务端可以让单个目标占住并发槽位远超该值;这里再加一道总闸。
    PROBE_OVERALL_TIMEOUT_SECONDS: float = 12.0
    # 单目标最多读取的响应体字节数。旧实现用 client.get() 把整个响应体收进内存
    # 再切片(实测一个 20 MiB 的畸形页面会被完整下载,1000 目标即 GB 级流量)。
    # 改为流式读:读满此上限立即断开,只保留够做 title/指纹匹配的头部。
    PROBE_READ_MAX_BYTES: int = 64 * 1024
    # 单次 Pro 请求最多探活的目标数,兜底防止超大域名(上万子域)把单请求拖垮。
    # 超出部分由 probe_complete=False 如实告知"只覆盖了前 N 个",不假装全覆盖。
    PRO_MAX_PROBE_TARGETS: int = 1000
    # 进入 live_assets 的状态码白名单。刻意比规格的"200/301/302"更宽:
    # 401/403 在 ASM/红队里是高价值命中(有服务但需授权 = 最佳打点),不该被当死资产丢弃。
    PROBE_LIVE_STATUS_CODES: set[int] = {200, 301, 302, 401, 403}

    # ---- 邮件伪造风险审计(SPF / DMARC)----
    # 全部使用 dns.asyncresolver 异步解析,DNS 查询与 HTTP 探活并行不互相阻塞
    DNS_TIMEOUT_SECONDS: float = 5.0
    # SPF 触发 DNS 查询的机制数超过此值 → RFC 7208 permerror,SPF 整体静默失效(可伪造)
    SPF_MAX_DNS_LOOKUPS: int = 10
    # SPF 中被视为"过大"的 ip4 CIDR 前缀:前缀 <= 此值(如 /8 /16)即授权范围过宽
    SPF_LARGE_CIDR_PREFIX: int = 16

    # ---- 全子域邮件审计(Pro 核心卖点:发现后对所有子域并发查 SPF)----
    # 审计扇出并发上限。比探活的 120 保守:DNS 扇出打的是目标域权威 NS,过猛易触发限速。
    # 实际并发 = min(子域数, 此上限),按发现的子域数量动态收敛,绝不空转开满。
    AUDIT_CONCURRENCY_CAP: int = 50
    # 单次 Pro 请求最多审计的子域数,兜底防止超大域(上万子域)把 DNS 扇出拖垮。
    # 与探活目标数对齐(两条并行支线覆盖同一批子域);超出部分由
    # audit_complete=False 如实告知,不假装全覆盖。
    PRO_MAX_AUDIT_TARGETS: int = 1000
    # 单目标域速率收敛:每个探活/审计请求发出前 random.uniform(0, 此值) 抖动,
    # 打散整批扇出的突发特征,降低 WAF / 权威 NS 因瞬时爆量限速或封禁本机 IP 的概率。
    PER_TARGET_JITTER_SECONDS: float = 0.15
    # 子域扇出的单条 DNS 超时:比主域审计的 DNS_TIMEOUT_SECONDS 更短。扇出量大,
    # 单条不能等太久,否则少数慢查询会把整体预算吃光,拖垮已能完成的大多数。
    SUBDOMAIN_DNS_TIMEOUT_SECONDS: float = 3.0

    # ==================== Ultra 计划:子域名接管(Subdomain Takeover)风险检测 ====================
    # Ultra = Pro 全量能力(发现 + 探活 + 全域邮件审计)+ 子域名接管风险检测(差异化卖点)。
    # 接管检测两条信号并行:
    #   1) CNAME 链解析:子域是否 CNAME 指向第三方托管服务(S3/GitHub Pages/Azure/Heroku…)。
    #   2) HTTP 正文指纹:对已探活抓取的正文做"未认领/悬空"指纹匹配(如 NoSuchBucket、
    #      "There isn't a GitHub Pages site here"、"Fastly error: unknown domain")。
    # 关键:正文指纹的最强信号恰恰在 404/500 等非存活状态码上,故 Ultra 探活必须保留这些
    # 正文用于指纹匹配(collect_body),而非像 Pro 那样直接丢弃。
    PLAN_ULTRA: str = "Ultra"
    # CNAME 扇出并发上限。与审计一样对权威 NS 保守,避免扇出爆量触发限速。
    # 实际并发 = min(子域数, 此上限)。
    TAKEOVER_CONCURRENCY_CAP: int = 50
    # 单次 Ultra 请求最多做接管检测的子域数,与探活/审计目标数对齐(护栏超大域)。
    ULTRA_MAX_TAKEOVER_TARGETS: int = 1000
    # 接管检测单条 CNAME 查询超时:扇出量大,单条不能等太久(镜像 SUBDOMAIN_DNS_TIMEOUT_SECONDS)。
    TAKEOVER_DNS_TIMEOUT_SECONDS: float = 3.0
    # CNAME 链最多跟随的跳数,防御 CNAME 环 / 超长链把单目标预算吃光。
    TAKEOVER_MAX_CNAME_HOPS: int = 10
    # 探活正文用于指纹匹配时,最多保留的字符数。接管指纹都在页面头部,截断足够且限制内存
    # (1000 目标 × 此值 ≈ 数 MB 上限),避免畸形大页面塞爆响应体内存。
    TAKEOVER_BODY_MAX_CHARS: int = 8192

    # ==================== 异步任务(job)生命周期 ====================
    # 异步扫描(轮询)把长扫描拆成快 POST + 快 GET。job 完成后在 store 里保留此窗口供轮询,
    # 过期 GET 返 404(客户端据此判失败/重试)。太短客户端来不及轮询,太长内存堆积。
    JOB_TTL_SECONDS: int = 600
    # job 存储上限。1000 目标 Ultra 结果 ~4-12MB,256 条封顶约 1-3GB;超限按 created_at 淘汰最老。
    JOB_STORE_MAXSIZE: int = 256
    # 结果落盘目录:每次扫描完成自动把结果 JSON 保存到本地此目录(相对项目根)。
    RESULT_DIR: str = "res"
    # job 结果 JSON 单文件上限:超出则不落盘(只在内存/JOB_STORE 里留一份),
    # 避免超大域一次扫描就写出几十 MB 文件。落盘失败不影响扫描结果本身。
    RESULT_MAX_BYTES: int = 8 * 1024 * 1024

    # ==================== DNS 情报(所有计划共享) ====================
    # 主域的 A/AAAA/NS/MX/TXT/CAA/SOA 记录。与 discover 完全并发,墙钟几乎不增加。
    # 这些记录是资产归属、邮件路由、云厂商识别的第一手证据,比子域名列表更"结构性"。
    DNS_INTEL_ENABLED: bool = True
    # 单类记录最多保留多少条(防畸形域返回上千条 TXT 把响应撑大)
    DNS_MAX_RECORDS: int = 40
    # 单条记录字符串最大长度(TXT 可能是超长拼串 / DKIM 公钥)
    DNS_MAX_RECORD_CHARS: int = 512

    # ==================== TLS 证书情报(Pro / Ultra) ====================
    # 对存活资产的 https 端点额外做一次 TLS 握手,取证书主体/签发者/有效期/
    # 是否通过系统信任库验证。过期证书、自签证书、域名不匹配都是 ASM 的高价值信号。
    PROBE_TLS_ENABLED: bool = True
    # 单次扫描最多做多少个 TLS 握手:一次握手 = 一次额外的 TCP+TLS,成本约等于
    # 一次 HTTP 请求。上限把"证书情报"的成本钉死,不随超大域线性增长。
    PROBE_TLS_MAX_TARGETS: int = 200
    TLS_TIMEOUT_SECONDS: float = 6.0
    # 自定义 CA 包(企业代理 / 自建 PKI 场景)。留空时优先用 certifi,再退回系统信任库。
    # certifi 是 httpx 的传递依赖,几乎总在;系统信任库在部分 Linux 容器里可能是空的。
    TLS_CA_BUNDLE: str = ""
    # 证书剩余天数低于此值 → 打"即将过期"告警
    TLS_EXPIRY_WARN_DAYS: int = 30

    # ==================== 安全响应头审计(Pro / Ultra) ====================
    # 纯 CPU:对探活已经拿到的响应头做 HSTS/CSP/X-Frame-Options/... 判定,零额外网络成本。
    SECURITY_HEADERS_ENABLED: bool = True
    # 浏览器侧低等级缺失项(Referrer-Policy / Permissions-Policy)只记 Info,
    # 在报告里降噪;设为 False 则连这些 Info 也一起省略。
    SECURITY_HEADERS_INCLUDE_INFO: bool = True

    # ==================== 扫描历史与差异对比 ====================
    # 每完成一次真实扫描就把"指纹摘要 + 子域名清单"记进本地 SQLite。
    # 有了历史才能回答 ASM 最关心的那个问题:这一次比上一次多了/少了什么。
    HISTORY_ENABLED: bool = True
    HISTORY_DB_PATH: str = "data/reconifyx.db"
    # 每个 (domain, plan) 组合最多保留多少次历史扫描(超出按时间淘汰最老)
    HISTORY_MAX_SCANS_PER_DOMAIN: int = 50


@lru_cache
def get_settings() -> Settings:
    return Settings()
