# 参与贡献

感谢你愿意花时间。这个项目的目标是"一个小而可靠的本地 ASM 工具"，所以下面几条
比一般项目更严格一点：

## 三件不能破的事

1. **测试必须离线。** 单元测试不访问外网：HTTP 用 `httpx.ASGITransport` 或本地
   `asyncio.start_server`，DNS 用桩。CI 里没有网络，也不该因为上游抖动而红。
2. **不猜。** 判定逻辑的每一处分歧都要能说清依据（RFC 条款、浏览器行为、实测结果）。
   PR 里请写出你依据什么改了判定，而不是"看起来应该这样"。
3. **降级要如实上报。** 任何"数据可能不完整"的情况都必须体现在响应字段里
   （`degraded` / `*_complete` / `*_note`），不能只写日志。

## 开发环境

```bash
git clone <repo> && cd ReconifyX
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt
```

## 提交前自查

```bash
python -m pytest -q                  # 必须全绿
python -m ruff check .               # 必须零输出
python -m pyflakes app launcher.py reconifyx tests
python -m compileall -q app reconifyx tests launcher.py
node --check app/static/app.js       # 改了前端才需要
```

## 代码约定

- **语言**：注释与文档用中文；**对外字段、finding 的 `message`、日志用英文**（面向全球用户）。
- **注释写"为什么"**，不写"做了什么"。一段代码如果看起来可以直接读懂，就不要加注释；
  如果它绕开了一个坑（RFC 条款、CPython 行为、上游缺陷），必须把那句话写清楚，并在
  必要时给出复现方式。
- **并发**：所有 IO 走 `asyncio`，绝不在事件循环里做同步阻塞调用（文件、CPU 重活丢
  `asyncio.to_thread`）。新增扇出必须带上限，并说明上限的理由。
- **异常**：单目标失败必须被隔离（一个子域超时不能拖垮整批扫描）；但**不允许静默**——
  要么体现在结果字段里，要么 `logger.warning(..., exc_info=True)`。
- **前端**：只用 `createElement` + `textContent`，不用 `innerHTML`。数据全部来自被扫描
  目标，属于不可信输入。
- **类型**：对外模型都用 pydantic；结果类模型保持 `extra="forbid"`。

## 想加一个新能力？

### 新增一个被动数据源（Basic 发现层）

1. 在 `app/services/basic.py` 里写一个 `_fetch_xxx(client, domain, s) -> _SourceResult`；
2. 用 `_SourceResult("xxx").finalize(ok=..., detail=...)` 返回，**不要**抛异常；
3. 在 `discover()` 的 `tasks` 里并发加入；
4. 判断它属于"骨干"还是"增强"：骨干失败才会让 `degraded=True`，增强失败只影响自己的字段；
5. 加测试：成功、超时、响应过大、脏数据清洗。

### 新增一个接管指纹（Ultra）

在 `app/services/takeover_service.py` 的 `_PROVIDERS` 里加一条 `ProviderSignature`：

- `cname_suffixes` 是**后缀**（前导点），`cname_patterns` 用于区域型端点（锚定正则，
  **不要**用子串匹配 —— 子串会把 `evil.s3.amazonaws.com.attacker.net` 判成 S3）；
- `fingerprints` 是悬空页面的正文特征，尽量取整句而不是单词；
- 若该平台悬空后**不允许**第三方认领（如 Zendesk），把 `is_vulnerable` 设为 `False`；
- 参考来源可以看 can-i-take-over-xyz，但要用真实页面验证正文指纹。

### 新增一个 finding code

- `code` 用大写下划线，语义自解释（`SPF_MISSING` 而不是 `FINDING_1`）；
- `severity` 只有 `Critical` / `Warning` / `Info`；
- `message` 用英文，并且要**说清后果 + 怎么修**（用户看到的就这一句）；
- 如果它应该影响风险分，在 `app/services/risk_service.py` 里加权重——但先问一句：
  这条 finding 真的会改变优先级吗？不会的话，`Info` 就够了。

## 分支与提交

- 分支名：`feat/...`、`fix/...`、`docs/...`、`refactor/...`。
- 一个 PR 只做一件事。混着"顺手格式化全仓"的 PR 无法 review，会被要求拆分。
- 提交信息用祈使句描述结果：`fix(spf): treat bare 'all' as +all`。
- 改动行为的话，同时更新 `CHANGELOG.md`。

## PR 检查清单

- [ ] `pytest` 全绿，新增行为有对应测试
- [ ] `ruff` / `pyflakes` 零输出
- [ ] 改了对外字段/端点/配置 → 更新了 `README.md`
- [ ] 改了行为 → 更新了 `CHANGELOG.md`
- [ ] 没有提交 `.env`、扫描结果（`res/`）、`data/`、构建产物
- [ ] 没有把测试改成"需要联网才能过"

## 报告安全问题

请不要开公开 issue，走 [`SECURITY.md`](SECURITY.md) 里的渠道。
