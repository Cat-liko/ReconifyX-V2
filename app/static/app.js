'use strict';

/* ReconifyX WebUI
 *
 * 三条硬约束,写之前先说清楚,免得后面"优化"时踩回去:
 *
 * 1) **不拼 HTML**。所有数据都来自被扫描目标(域名、页面标题、Server 头、证书主体…),
 *    它们全都是不可信输入。这里一律用 createElement + textContent 构图,全程不碰
 *    innerHTML —— 否则一条精心构造的 <title> 就能在安全工具的界面上执行脚本,
 *    这会是本项目最讽刺的一个漏洞。
 *
 * 2) **不猜后端行为**。除错文案统一从 message / detail 里提;422 的 detail 是数组;
 *    404 表示 job 过期;409 表示还没跑完 —— 每种都已经有明确分支。
 *
 * 3) **轮询有上限**。后端 job TTL 默认 10 分钟,这里最多等 ~18 分钟就放弃,
 *    避免后端异常时永远转圈。
 */

// ==================== 常量 ====================

const POLL_INTERVAL_MS = 1200;
const MAX_POLLS = 900;
const THEME_KEY = 'reconifyx.theme';
const KEY_STORE = 'reconifyx.apiKey';

const state = {
  meta: null,
  plan: 'Basic',
  job: null,
  diff: undefined,
  history: undefined,
  abort: null,
  busy: false,
  tabNodes: null,
  activeTab: null,
  batchRun: false,
};

// ==================== 小工具 ====================

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function pill(text, kind) {
  return el('span', 'pill ' + (kind || 'muted'), text);
}

function sevKind(sev) {
  if (sev === 'Critical') return 'critical';
  if (sev === 'Warning') return 'warning';
  if (sev === 'Info') return 'info';
  if (sev === 'Secure' || sev === 'High') return 'ok';
  return 'muted';
}

function fmtInt(n) {
  const num = Number(n);
  return Number.isFinite(num) ? num.toLocaleString('en-US') : '0';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toast(msg) {
  const node = $('toast');
  node.textContent = msg;
  node.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => node.classList.remove('show'), 2400);
}

function spinner() {
  return el('i', 'spinner');
}

function statusLine(msg, kind) {
  const node = $('status');
  node.className = 'status' + (kind === 'error' ? ' error' : kind === 'ok' ? ' ok' : '');
  node.replaceChildren();
  if (kind === 'loading') node.append(spinner());
  node.append(document.createTextNode(msg));
  $('progress').hidden = kind !== 'loading';
}

// ==================== 表格 ====================

function toCell(value) {
  if (value instanceof Node) {
    const td = el('td');
    td.append(value);
    return td;
  }
  if (value && typeof value === 'object') {
    const td = el('td', value.cls || null, value.text === undefined ? '' : value.text);
    if (value.title) td.title = String(value.title);
    return td;
  }
  return el('td', null, value === undefined || value === null ? '' : value);
}

function makeTable(headers, rows) {
  const wrap = el('div', 'table-wrap');
  const table = el('table');
  const thead = el('thead');
  const headRow = el('tr');
  headers.forEach((spec) => {
    const s = typeof spec === 'string' ? { label: spec } : spec;
    headRow.append(el('th', s.cls, s.label));
  });
  thead.append(headRow);
  const tbody = el('tbody');
  const rowEls = rows.map((cells) => {
    const tr = el('tr');
    cells.forEach((cell) => tr.append(toCell(cell)));
    tbody.append(tr);
    return tr;
  });
  table.append(thead, tbody);
  wrap.append(table);
  return { root: wrap, rowEls };
}

/**
 * 带过滤框的表格。过滤直接按行的 textContent 做子串匹配 —— 简单、可预期,
 * 而且天然覆盖所有列(用户不用记"该在哪个框里搜")。
 */
function searchableTable(headers, rows, opts) {
  const options = opts || {};
  const box = el('div');
  if (!rows.length) {
    box.append(el('div', 'empty', options.empty || '没有数据'));
    return box;
  }

  const bar = el('div', 'toolbar');
  const input = el('input');
  input.type = 'text';
  input.className = 'grow';
  input.placeholder = options.placeholder || '过滤…';
  input.spellcheck = false;
  const count = el('span', 'count', `${rows.length}`);
  bar.append(input, count);

  const { root, rowEls } = makeTable(headers, rows);
  const apply = () => {
    const q = input.value.trim().toLowerCase();
    let shown = 0;
    rowEls.forEach((tr) => {
      const hit = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
      tr.hidden = !hit;
      if (hit) shown += 1;
    });
    count.textContent = `${shown} / ${rows.length}`;
  };
  input.addEventListener('input', apply);

  box.append(bar, root);
  return box;
}

function kv(pairs) {
  const dl = el('dl', 'kv');
  pairs.forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    dl.append(el('dt', null, key));
    const dd = el('dd');
    if (value instanceof Node) dd.append(value);
    else dd.textContent = String(value);
    dl.append(dd);
  });
  return dl;
}

function findingList(findings) {
  const ul = el('ul', 'finding-list');
  (findings || []).forEach((f) => {
    const li = el('li');
    li.append(pill(f.severity, sevKind(f.severity)));
    li.append(el('span', 'code', f.code));
    li.append(el('span', 'msg', f.message || ''));
    ul.append(li);
  });
  return ul;
}

// ==================== 主题 ====================

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  $('themeBtn').textContent = theme === 'dark' ? '深色' : '浅色';
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch (_) {
    /* 隐私模式下 localStorage 可能不可用,忽略 */
  }
}

function initTheme() {
  let theme = 'dark';
  try {
    theme = localStorage.getItem(THEME_KEY) || 'dark';
  } catch (_) {
    /* ignore */
  }
  applyTheme(theme);
  $('themeBtn').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });
}

// ==================== API ====================

function apiKey() {
  const input = $('apiKey');
  const typed = input ? input.value.trim() : '';
  if (typed) return typed;
  try {
    return localStorage.getItem(KEY_STORE) || '';
  } catch (_) {
    return '';
  }
}

function errorMessage(payload, status) {
  if (!payload) return `HTTP ${status}`;
  if (typeof payload.message === 'string' && payload.message) return payload.message;
  if (typeof payload.detail === 'string' && payload.detail) return payload.detail;
  if (Array.isArray(payload.detail)) {
    return payload.detail
      .map((item) => {
        if (!item) return JSON.stringify(item);
        if (item.msg) return `${(item.loc || []).join('.')}: ${item.msg}`;
        return JSON.stringify(item);
      })
      .join('; ');
  }
  return `HTTP ${status}`;
}

async function api(path, options) {
  const opts = options || {};
  const headers = Object.assign({}, opts.headers || {});
  const key = apiKey();
  if (key) headers['X-API-Key'] = key;
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(path, {
    method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'),
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  const text = await res.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_) {
      payload = { message: text.slice(0, 300) };
    }
  }
  if (!res.ok) throw new Error(errorMessage(payload, res.status));
  return payload;
}

// ==================== 元信息 / 计划 ====================

async function loadMeta() {
  const meta = await api('/api/meta');
  state.meta = meta;
  $('ver').textContent = 'v' + meta.version;

  const limits = meta.limits || {};
  $('limits').textContent =
    `探活上限 ${fmtInt(limits.probe_targets)} · 并发 ${fmtInt(limits.probe_concurrency)}` +
    ` · 批量 ${fmtInt(limits.batch_domains)}`;

  $('batchInput').placeholder =
    `每行一个域名（最多 ${fmtInt(limits.batch_domains)} 个）\nexample.com\nexample.org`;

  renderPlans(meta.plans || []);

  if (meta.auth_required) {
    $('keyWrap').hidden = false;
    let saved = '';
    try {
      saved = localStorage.getItem(KEY_STORE) || '';
    } catch (_) {
      saved = '';
    }
    // 支持 ?key=xxx 直接带进来(方便脚本/书签),随后仍以输入框为准
    const fromUrl = new URLSearchParams(location.search).get('key');
    $('apiKey').value = fromUrl || saved;
    if (fromUrl) {
      try {
        localStorage.setItem(KEY_STORE, fromUrl);
      } catch (_) {
        /* ignore */
      }
    }
  }

  const defaultPlan = (meta.plans || []).find((p) => p.name === 'Ultra') ? 'Ultra' : 'Basic';
  selectPlan(defaultPlan);
}

function renderPlans(plans) {
  const grid = $('plans');
  grid.replaceChildren();
  plans.forEach((plan) => {
    const card = el('button');
    card.type = 'button';
    card.className = 'plan';
    card.dataset.plan = plan.name;
    const name = el('div', 'name', plan.name);
    name.append(el('span', 'pill muted', plan.title || ''));
    card.append(name, el('div', 'desc', plan.description || ''));
    if (Array.isArray(plan.features) && plan.features.length) {
      const ul = el('ul');
      plan.features.forEach((f) => ul.append(el('li', null, f)));
      card.append(ul);
    }
    card.addEventListener('click', () => selectPlan(plan.name));
    grid.append(card);
  });
}

function selectPlan(name) {
  state.plan = name;
  Array.from($('plans').children).forEach((node) => {
    node.classList.toggle('active', node.dataset.plan === name);
  });
}

// ==================== 扫描编排 ====================

function parseDomains(raw) {
  return String(raw || '')
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function startScan() {
  if (state.busy) return;
  const batch = $('batchMode').checked;
  const domains = batch ? parseDomains($('batchInput').value) : parseDomains($('domain').value);

  if (!domains.length) {
    statusLine(batch ? '请至少输入一个域名' : '请输入要扫描的主域名', 'error');
    return;
  }

  resetResults();
  state.busy = true;
  state.abort = new AbortController();
  $('goBtn').disabled = true;
  $('cancelBtn').hidden = false;
  statusLine(batch ? `提交 ${domains.length} 个域名…` : '提交扫描…', 'loading');

  try {
    if (batch) {
      await runBatch(domains);
    } else {
      await runSingle(domains[0]);
    }
  } catch (err) {
    if (err && err.name === 'AbortError') {
      statusLine('已取消', '');
    } else {
      statusLine(err && err.message ? err.message : String(err), 'error');
    }
  } finally {
    state.busy = false;
    state.abort = null;
    $('goBtn').disabled = false;
    $('cancelBtn').hidden = true;
    $('progress').hidden = true;
  }
}

async function runSingle(domain) {
  const accepted = await api('/scan', {
    body: { domain, plan: state.plan },
    signal: state.abort.signal,
  });
  if (!accepted || !accepted.job_id) throw new Error('服务端未返回 job_id');

  if (accepted.status === 'completed') {
    statusLine('缓存命中', 'ok');
  } else {
    statusLine(`已创建任务 ${String(accepted.job_id).slice(0, 8)}…`, 'loading');
  }

  const job = await pollJob(accepted.job_id);
  renderJob(job);
}

async function runBatch(domains) {
  const accepted = await api('/scan/batch', {
    body: { domains, plan: state.plan },
    signal: state.abort.signal,
  });
  const jobs = (accepted && accepted.jobs) || [];
  if (!jobs.length) throw new Error('服务端未返回任何 job');

  $('batchCard').hidden = false;
  state.batchRun = true;
  const tableHost = $('batchBody');
  tableHost.replaceChildren();
  $('batchHint').textContent = `${jobs.length} 个域名 · ${accepted.plan} 计划`;

  const rowState = jobs.map((job) => ({ job, status: 'queued', result: null }));
  const { root, rowEls } = makeTable(
    ['域名', '状态', '风险', '子域名', '存活', '操作'],
    rowState.map((item) => [
      { text: item.job.domain, cls: 'mono' },
      pill('排队中', 'muted'),
      '',
      '',
      '',
      '',
    ])
  );
  tableHost.append(root);

  const repaint = (index) => {
    const item = rowState[index];
    const tr = rowEls[index];
    const data = (item.result && item.result.result) || {};
    const risk = data.risk;
    const cells = [
      { text: item.job.domain, cls: 'mono' },
      pill(
        item.status === 'completed' ? '完成' : item.status === 'failed' ? '失败' : '扫描中',
        item.status === 'completed' ? 'ok' : item.status === 'failed' ? 'critical' : 'muted'
      ),
      risk ? pill(`${risk.risk_score} (${risk.grade})`, risk.risk_score > 45 ? 'critical' : risk.risk_score > 25 ? 'warning' : 'ok') : '',
      data.total_found === undefined ? '' : fmtInt(data.total_found),
      data.total_live === undefined ? '' : fmtInt(data.total_live),
      item.status === 'completed'
        ? buttonNode('查看', () => renderJob(item.result))
        : item.status === 'failed'
          ? el('span', 'mono', (item.result && item.result.error) || '失败')
          : el('span', 'count', '…'),
    ];
    tr.replaceChildren();
    cells.forEach((cell) => tr.append(toCell(cell)));
  };

  await Promise.all(
    jobs.map(async (job, index) => {
      try {
        const done = await pollJob(job.job_id);
        rowState[index].status = done.status;
        rowState[index].result = done;
      } catch (err) {
        rowState[index].status = 'failed';
        rowState[index].result = { status: 'failed', error: err && err.message ? err.message : String(err) };
      }
      repaint(index);
    })
  );

  const ok = rowState.filter((r) => r.status === 'completed').length;
  statusLine(`批量完成：${ok} / ${jobs.length} 成功`, ok === jobs.length ? 'ok' : 'error');
}

function buttonNode(label, onClick) {
  const btn = el('button', 'small', label);
  btn.type = 'button';
  btn.addEventListener('click', onClick);
  return btn;
}

async function pollJob(jobId) {
  for (let i = 0; i < MAX_POLLS; i += 1) {
    if (state.abort && state.abort.signal.aborted) {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    }

    let job;
    try {
      job = await api('/scan/' + encodeURIComponent(jobId), { signal: state.abort ? state.abort.signal : undefined });
    } catch (err) {
      // 404 = job 已过期(后端只保留有限时间),给出可执行的提示而不是"HTTP 404"
      if (err && /not found|expired/i.test(err.message)) {
        throw new Error('任务不存在或已过期(结果只保留有限时间),请重新扫描');
      }
      throw err;
    }

    if (job.status === 'completed') return job;
    if (job.status === 'failed') throw new Error('扫描失败：' + (job.error || '未知错误'));

    statusLine(`扫描中… ${job.status}（已等待 ${Math.round((i * POLL_INTERVAL_MS) / 1000)}s）`, 'loading');
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error('等待超时：任务仍未完成,请稍后重试或查看后端日志');
}

// ==================== 渲染:头部 ====================

function renderJob(job) {
  state.job = job;
  state.diff = undefined;
  state.history = undefined;

  const data = job.result || {};
  $('resultCard').hidden = false;
  // 批量模式下保留批量结果表(结果卡在它上面,两者并存才有对照价值);
  // 单域名扫描时必须把空白的批量卡藏起来 —— 否则页面底部会挂一个空容器。
  $('batchCard').hidden = !state.batchRun;
  $('headline').textContent = `${job.domain} · ${job.plan} · ${job.status}`;

  renderMetrics(job, data);
  renderBadges(job, data);
  buildTabs();

  statusLine(job.from_cache ? '完成（来自缓存）' : `完成 · ${job.elapsed_ms || 0} ms`, 'ok');

  if ($('wantDiff').checked) loadDiff(job.job_id);
  if ($('wantHistory').checked) loadHistory(job.domain);
}

function renderMetrics(job, data) {
  const host = $('metrics');
  host.replaceChildren();

  const add = (label, value, sub, kind) => {
    const box = el('div', 'metric' + (kind ? ' ' + kind : ''));
    box.append(el('div', 'k', label));
    box.append(el('div', 'v', value));
    if (sub) box.append(el('div', 's', sub));
    host.append(box);
  };

  add('子域名', fmtInt(data.total_found), '去重 FQDN');
  add('IP 资产', fmtInt(data.total_assets), '测绘元数据');

  if (data.total_live !== undefined) {
    add('存活主机', fmtInt(data.total_live), data.probe_complete === false ? '已截断' : 'HTTP 探活', 'good');
  }

  if (data.takeover) {
    const n = data.takeover.vulnerable_count || 0;
    add('可接管', fmtInt(n), 'High 置信度', n > 0 ? 'alert' : 'good');
  }

  if (data.email_audit) {
    const n = data.email_audit.spoofable_subdomains || 0;
    add('可伪造邮件域', fmtInt(n), 'Critical + Warning', n > 0 ? 'warn' : 'good');
  }

  if (data.risk) {
    const score = data.risk.risk_score || 0;
    add('风险分', `${score}`, `等级 ${data.risk.grade || '-'}`,
      score > 45 ? 'alert' : score > 25 ? 'warn' : 'good');
  }
}

function renderBadges(job, data) {
  const host = $('badges');
  host.replaceChildren();

  if (job.from_cache) host.append(el('span', 'badge ok', '结果来自缓存'));
  if (job.degraded) host.append(el('span', 'badge warn', '骨干数据源降级：结果可能不完整'));
  if (job.elapsed_ms !== undefined && job.elapsed_ms !== null) {
    host.append(el('span', 'badge', `${fmtInt(job.elapsed_ms)} ms`));
  }
  if (data.risk) {
    const c = data.risk.counts || {};
    if (c.critical) host.append(el('span', 'badge err', `Critical × ${fmtInt(c.critical)}`));
    if (c.warning) host.append(el('span', 'badge warn', `Warning × ${fmtInt(c.warning)}`));
    if (c.info) host.append(el('span', 'badge info', `Info × ${fmtInt(c.info)}`));
  }
  if (data.dns && data.dns.soa) host.append(el('span', 'badge', 'DNS 已解析'));
  if (job.saved_path) {
    const badge = el('span', 'badge ok', '结果已落盘');
    badge.title = job.saved_path;
    host.append(badge);
  }
}

// ==================== 渲染:标签页 ====================

function buildTabs() {
  const job = state.job;
  const data = job.result || {};
  const tabs = [{ id: 'overview', label: '概览', build: () => panelOverview(job, data) }];

  if ((data.subdomains || []).length) {
    tabs.push({ id: 'subdomains', label: '子域名', count: data.subdomains.length, build: () => panelSubdomains(data) });
  }
  if ((data.live_assets || []).length) {
    tabs.push({ id: 'live', label: '存活资产', count: data.live_assets.length, build: () => panelLive(data) });
  }
  if (data.dns) tabs.push({ id: 'dns', label: 'DNS', build: () => panelDns(data.dns) });
  if (data.email_audit) tabs.push({ id: 'email', label: '邮件审计', build: () => panelEmail(data.email_audit) });
  if (data.takeover) {
    tabs.push({
      id: 'takeover',
      label: '接管',
      count: (data.takeover.findings || []).length,
      build: () => panelTakeover(data.takeover),
    });
  }
  const hasIntel = (data.live_assets || []).some((a) => a.tls || a.security);
  if (hasIntel) tabs.push({ id: 'web', label: '证书与响应头', build: () => panelWeb(data) });
  if ((job.sources || []).length) tabs.push({ id: 'sources', label: '数据源', build: () => panelSources(job) });
  tabs.push({ id: 'diff', label: '对比', build: () => panelDiff() });
  tabs.push({ id: 'raw', label: '原始 JSON', build: () => panelRaw(job) });

  const tabBar = $('tabs');
  const panels = $('panels');
  tabBar.replaceChildren();
  panels.replaceChildren();

  const built = {};
  state.tabNodes = built;
  const show = (id) => {
    state.activeTab = id;
    Array.from(tabBar.children).forEach((node) => {
      node.classList.toggle('active', node.dataset.tab === id);
    });
    Object.entries(built).forEach(([key, node]) => {
      node.hidden = key !== id;
    });
    if (!built[id]) {
      const spec = tabs.find((t) => t.id === id);
      const node = el('div', 'panel');
      node.append(spec.build());
      panels.append(node);
      built[id] = node;
    }
    built[id].hidden = false;
  };

  tabs.forEach((spec) => {
    const btn = el('button', 'tab');
    btn.type = 'button';
    btn.dataset.tab = spec.id;
    btn.append(document.createTextNode(spec.label));
    if (spec.count !== undefined) btn.append(el('span', 'n', fmtInt(spec.count)));
    btn.addEventListener('click', () => show(spec.id));
    tabBar.append(btn);
  });

  show('overview');
}

// ==================== 渲染:各面板 ====================

function panelOverview(job, data) {
  const box = el('div');

  const risk = data.risk;
  if (risk && (risk.items || []).length) {
    box.append(el('h2', null, '风险清单'));
    box.append(
      searchableTable(
        ['严重度', '代码', '命中', '示例主体'],
        risk.items.map((item) => [
          pill(item.severity, sevKind(item.severity)),
          { text: item.code, cls: 'mono' },
          fmtInt(item.count),
          { text: item.subject || '-', cls: 'mono', title: item.message },
        ]),
        { placeholder: '过滤风险项…', empty: '没有风险项' }
      )
    );
  } else {
    box.append(el('div', 'empty', '未发现需要跟进的风险项'));
  }

  // 覆盖率说明:被截断的地方必须显式说出来,不能假装全覆盖
  const notes = [
    ['探活覆盖', data.probe_note],
    ['邮件审计覆盖', data.email_audit && data.email_audit.audit_note],
    ['接管检测覆盖', data.takeover && data.takeover.takeover_note],
  ].filter((pair) => pair[1]);
  if (notes.length) {
    box.append(el('h2', null, '覆盖范围'));
    const dl = el('dl', 'kv');
    notes.forEach(([label, note]) => {
      dl.append(el('dt', null, label));
      dl.append(el('dd', null, note));
    });
    box.append(dl);
  }

  if (data.email_audit && data.email_audit.primary) {
    const primary = data.email_audit.primary;
    box.append(el('h2', null, '邮件伪造（主域）'));
    box.append(
      kv([
        ['风险等级', pill(primary.risk_level, sevKind(primary.risk_level))],
        ['可被伪造', primary.is_spoofable ? '是' : '否'],
        ['DMARC 策略', primary.dmarc_policy || '无'],
        ['SPF', primary.spf_record || '无'],
        ['DMARC', primary.dmarc_record || '无'],
      ])
    );
    if ((primary.findings || []).length) box.append(findingList(primary.findings));
  }

  if (state.history && state.history.length) {
    box.append(el('h2', null, '历史扫描'));
    box.append(
      makeTable(
        ['时间', '计划', '风险分', '子域名', '存活', '数据'],
        state.history.map((row) => [
          { text: row.finished_at, cls: 'mono' },
          row.plan,
          pill(String(row.risk_score), row.risk_score > 45 ? 'critical' : row.risk_score > 25 ? 'warning' : 'ok'),
          fmtInt(row.total_found),
          fmtInt(row.total_live),
          row.degraded ? pill('降级', 'warning') : pill('完整', 'ok'),
        ])
      ).root
    );
  }

  box.append(el('h2', null, '元信息'));
  box.append(
    kv([
      ['任务 ID', job.job_id],
      ['域名', job.domain],
      ['计划', job.plan],
      ['创建时间', job.created_at],
      ['完成时间', job.finished_at || '-'],
      ['耗时', job.elapsed_ms === null || job.elapsed_ms === undefined ? '-' : `${job.elapsed_ms} ms`],
      ['落盘路径', job.saved_path || '-'],
    ])
  );

  return box;
}

function panelSubdomains(data) {
  const box = el('div');
  const list = data.subdomains || [];
  const rows = list.map((host) => [{ text: host, cls: 'mono' }]);
  const copy = buttonNode('复制全部', async () => {
    try {
      await navigator.clipboard.writeText(list.join('\n'));
      toast(`已复制 ${list.length} 个域名`);
    } catch (_) {
      toast('复制失败：浏览器拒绝了剪贴板访问');
    }
  });
  box.append(
    searchableTable(['子域名'], rows, {
      placeholder: '过滤子域名…',
      empty: '没有发现子域名',
    })
  );
  box.insertBefore(copy, box.firstChild);
  return box;
}

function tlsCell(tls) {
  if (!tls) return { text: '-', cls: 'nowrap' };
  if (tls.error && !tls.verified) {
    return { text: '验证失败', cls: 'nowrap', title: tls.verification_error || tls.error };
  }
  if (tls.expired) return { text: '已过期', cls: 'nowrap', title: tls.not_after || '' };
  if (tls.expiring_soon) return { text: `${tls.days_left}d`, cls: 'nowrap', title: '即将过期' };
  const days = tls.days_left === null || tls.days_left === undefined ? '?' : `${tls.days_left}d`;
  return { text: days, cls: 'nowrap', title: tls.issuer || '' };
}

function panelLive(data) {
  const box = el('div');
  const assets = data.live_assets || [];
  const rows = assets.map((asset) => [
    { text: asset.url, cls: 'mono' },
    asset.status_code,
    { text: asset.title || '-', title: asset.title || '' },
    { text: asset.server || '-', cls: 'nowrap' },
    tlsCell(asset.tls),
    asset.security ? pill(asset.security.grade, asset.security.score >= 75 ? 'ok' : asset.security.score >= 60 ? 'warning' : 'critical') : '-',
  ]);
  box.append(
    searchableTable(
      ['URL', '状态', '标题', 'Server', '证书', '安全头'],
      rows,
      { placeholder: '过滤 URL / 标题 / Server…', empty: '没有存活资产' }
    )
  );
  return box;
}

function panelDns(dns) {
  const box = el('div');
  const rows = [];
  const push = (type, values) => {
    (values || []).forEach((value) => rows.push([pill(type, 'muted'), { text: value, cls: 'mono' }]));
  };
  push('A', dns.a);
  push('AAAA', dns.aaaa);
  push('NS', dns.ns);
  push('MX', dns.mx);
  push('TXT', dns.txt);
  push('CAA', dns.caa);
  if (dns.soa) rows.push([pill('SOA', 'muted'), { text: dns.soa, cls: 'mono' }]);

  box.append(
    kv([
      ['解析状态', dns.resolved ? pill('已解析', 'ok') : pill('无 A/AAAA', 'critical')],
      ['SPF', dns.has_spf ? pill('存在', 'ok') : pill('缺失', 'warning')],
      ['DMARC', dns.has_dmarc ? pill('存在', 'ok') : pill('缺失', 'warning')],
      ['CAA', (dns.caa || []).length ? pill('已限制签发', 'ok') : pill('未限制', 'warning')],
    ])
  );
  box.append(el('h2', null, '记录'));
  box.append(searchableTable(['类型', '值'], rows, { placeholder: '过滤记录…', empty: '没有记录' }));
  return box;
}

function panelEmail(report) {
  const box = el('div');
  const primary = report.primary || {};

  box.append(
    kv([
      ['主域', report.primary ? primary.domain : '-'],
      ['主域等级', pill(primary.risk_level || '-', sevKind(primary.risk_level))],
      ['子域生效策略', report.subdomain_policy || '无（继承 p=）'],
      ['发现子域', fmtInt(report.total_discovered)],
      ['实际审计', fmtInt(report.total_subdomains_audited)],
      ['可伪造子域', fmtInt(report.spoofable_subdomains)],
      ['覆盖完整', report.audit_complete ? '是' : '否（已截断）'],
    ])
  );

  if ((primary.findings || []).length) {
    box.append(el('h2', null, '主域发现'));
    box.append(findingList(primary.findings));
  }

  const subs = report.subdomains || [];
  box.append(el('h2', null, '子域审计'));
  box.append(
    searchableTable(
      ['子域', '等级', '自有 SPF', '自有 MX', '发现'],
      subs.map((sub) => [
        { text: sub.domain, cls: 'mono' },
        pill(sub.risk_level, sevKind(sub.risk_level)),
        sub.has_own_spf ? '是' : '否',
        sub.has_own_mx ? '是' : '否',
        { text: (sub.findings || []).map((f) => f.code).join(', ') || '-', cls: 'mono' },
      ]),
      { placeholder: '过滤子域 / 等级 / code…', empty: '没有子域审计结果' }
    )
  );
  return box;
}

function panelTakeover(report) {
  const box = el('div');
  box.append(
    kv([
      ['发现子域', fmtInt(report.total_discovered)],
      ['实际检测', fmtInt(report.total_checked)],
      ['可接管(High)', pill(String(report.vulnerable_count), report.vulnerable_count > 0 ? 'critical' : 'ok')],
      ['覆盖完整', report.takeover_complete ? '是' : '否（已截断）'],
    ])
  );

  const findings = (report.findings || []).slice().sort((a, b) => {
    if (a.is_vulnerable !== b.is_vulnerable) return a.is_vulnerable ? -1 : 1;
    return String(a.domain).localeCompare(String(b.domain));
  });

  box.append(el('h2', null, '检测结论'));
  box.append(
    searchableTable(
      ['子域', '置信度', '托管商', '可接管', '状态码', 'CNAME 链', '依据'],
      findings.map((f) => [
        { text: f.domain, cls: 'mono' },
        pill(f.confidence, f.is_vulnerable ? 'critical' : 'warning'),
        f.matched_provider || '-',
        f.is_vulnerable ? pill('是', 'critical') : pill('待复核', 'muted'),
        f.status_code === null || f.status_code === undefined ? '-' : f.status_code,
        { text: (f.cname_chain || []).join(' → ') || '-', cls: 'mono' },
        { text: f.evidence || '', title: f.evidence || '' },
      ]),
      { placeholder: '过滤子域 / 托管商…', empty: '没有检测到接管信号' }
    )
  );
  return box;
}

function panelWeb(data) {
  const box = el('div');
  const assets = (data.live_assets || []).filter((a) => a.tls || a.security);

  box.append(el('h2', null, 'TLS 证书'));
  box.append(
    searchableTable(
      ['主机', '验证', '主体', '签发者', '到期', '剩余', '版本', '备注'],
      assets
        .filter((a) => a.tls)
        .map((a) => {
          const tls = a.tls;
          return [
            { text: a.host || a.url, cls: 'mono' },
            tls.verified ? pill('通过', 'ok') : pill('失败', 'critical'),
            { text: tls.subject || '-', cls: 'mono' },
            { text: tls.issuer || '-', cls: 'mono' },
            { text: tls.not_after || '-', cls: 'mono nowrap' },
            tlsCell(tls),
            tls.tls_version || '-',
            { text: tls.verification_error || tls.error || '-', title: tls.verification_error || tls.error || '' },
          ];
        }),
      { placeholder: '过滤主机 / 签发者…', empty: '没有 TLS 情报（可能未启用或全是 http）' }
    )
  );

  const withSecurity = assets.filter((a) => a.security);
  box.append(el('h2', null, '安全响应头'));
  box.append(
    searchableTable(
      ['主机', '等级', '分数', '缺失/错误项'],
      withSecurity.map((a) => [
        { text: a.host || a.url, cls: 'mono' },
        pill(a.security.grade, a.security.score >= 75 ? 'ok' : a.security.score >= 60 ? 'warning' : 'critical'),
        String(a.security.score),
        {
          text: (a.security.findings || []).map((f) => f.code).join(', ') || '无',
          cls: 'mono',
          title: (a.security.findings || []).map((f) => `${f.code}: ${f.message}`).join('\n'),
        },
      ]),
      { placeholder: '过滤主机 / code…', empty: '没有响应头评估' }
    )
  );
  return box;
}

function panelSources(job) {
  const box = el('div');
  const sources = job.sources || [];
  box.append(
    searchableTable(
      ['数据源', '状态', '条数', '备注'],
      sources.map((src) => [
        { text: src.name, cls: 'mono' },
        src.ok ? pill('ok', 'ok') : pill('失败', 'critical'),
        fmtInt(src.count),
        { text: src.detail || '-', cls: 'mono' },
      ]),
      { placeholder: '过滤数据源…', empty: '没有数据源信息' }
    )
  );
  if (job.degraded) {
    box.append(
      el(
        'div',
        'empty',
        '骨干数据源全部失败：本次结果可能不完整。稍后重试通常会恢复（缓存里会保留旧快照）。'
      )
    );
  }
  return box;
}

function panelDiff() {
  const box = el('div');
  if (state.diff === undefined) {
    box.append(el('div', 'empty', '正在获取对比结果…'));
    return box;
  }
  const diff = state.diff;
  if (!diff) {
    box.append(el('div', 'empty', '没有历史基线（该域名第一次扫描，或历史功能未启用）'));
    return box;
  }
  if (diff.baseline) {
    box.append(
      el(
        'div',
        'empty',
        '没有可比的历史扫描。这是该域名的第一个基线快照 —— 下一次扫描后这里会显示新增/消失的资产。'
      )
    );
    return box;
  }

  box.append(
    kv([
      ['对比对象', diff.compared_to_job_id || '-'],
      ['上次时间', diff.compared_at || '-'],
    ])
  );

  const grid = el('div', 'diff-grid');
  const block = (title, items, kind) => {
    const cellEl = el('div', 'diff-box');
    const head = el('h3');
    head.append(document.createTextNode(title), el('span', 'n', fmtInt((items || []).length)));
    cellEl.append(head);
    if (!items || !items.length) {
      cellEl.append(el('div', 'count', '无变化'));
    } else {
      const ul = el('ul');
      items.slice(0, 100).forEach((item) => ul.append(el('li', kind, item)));
      cellEl.append(ul);
      if (items.length > 100) cellEl.append(el('div', 'count', `… 其余 ${items.length - 100} 条见导出`));
    }
    grid.append(cellEl);
  };

  block('新增子域名', diff.new_subdomains, 'add');
  block('消失子域名', diff.removed_subdomains, 'del');
  block('新上线 URL', diff.new_live_urls, 'add');
  block('不再存活', diff.removed_live_urls, 'del');
  block('新接管信号', diff.new_takeover_domains, 'add');
  block('新增 IP', diff.new_ip_assets, 'add');
  box.append(grid);
  return box;
}

function panelRaw(job) {
  const box = el('div');
  const pre = el('pre', 'raw', JSON.stringify(job, null, 2));
  box.append(pre);
  return box;
}

// ==================== 差异 / 历史 / 导出 ====================

async function loadDiff(jobId) {
  try {
    state.diff = await api('/scan/' + encodeURIComponent(jobId) + '/diff');
  } catch (_) {
    state.diff = null;
  }
  refreshTabIfActive('diff', () => panelDiff());
}

async function loadHistory(domain) {
  try {
    const payload = await api('/history?domain=' + encodeURIComponent(domain));
    state.history = payload.entries || [];
  } catch (_) {
    state.history = [];
  }
  refreshTabIfActive('overview', () => panelOverview(state.job, state.job.result || {}));
}

/** 异步数据到位后,如果用户正停在该标签页,原地刷新它的内容。 */
function refreshTabIfActive(tabId, build) {
  if (state.activeTab !== tabId) return;
  const node = state.tabNodes && state.tabNodes[tabId];
  if (!node) return;
  node.replaceChildren();
  node.append(build());
}

async function downloadExport(format) {
  if (!state.job) return;
  const url = `/scan/${encodeURIComponent(state.job.job_id)}/export?format=${format}`;
  const headers = {};
  const key = apiKey();
  if (key) headers['X-API-Key'] = key;
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      toast(`导出失败（HTTP ${res.status}）`);
      return;
    }
    const blob = await res.blob();
    const disposition = res.headers.get('content-disposition') || '';
    const match = /filename="([^"]+)"/.exec(disposition);
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(blob);
    anchor.download = match ? match[1] : `reconifyx.${format}`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(anchor.href), 5000);
    toast(`已导出 ${format.toUpperCase()}`);
  } catch (err) {
    toast('导出失败：' + (err && err.message ? err.message : String(err)));
  }
}

// ==================== 生命周期 ====================

function resetResults() {
  state.job = null;
  state.diff = undefined;
  state.history = undefined;
  state.tabNodes = null;
  state.activeTab = null;
  state.batchRun = false;
  $('resultCard').hidden = true;
  $('batchCard').hidden = true;
  $('metrics').replaceChildren();
  $('badges').replaceChildren();
  $('tabs').replaceChildren();
  $('panels').replaceChildren();
}

function bindEvents() {
  $('goBtn').addEventListener('click', startScan);
  $('cancelBtn').addEventListener('click', () => {
    if (state.abort) state.abort.abort();
  });
  $('domain').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      startScan();
    }
  });
  $('batchMode').addEventListener('change', (event) => {
    const on = event.target.checked;
    $('batchInput').hidden = !on;
    $('domain').closest('.grow').hidden = on;
  });
  $('expJson').addEventListener('click', () => downloadExport('json'));
  $('expCsv').addEventListener('click', () => downloadExport('csv'));
  $('expMd').addEventListener('click', () => downloadExport('md'));

  const keyInput = $('apiKey');
  if (keyInput) {
    keyInput.addEventListener('change', () => {
      try {
        localStorage.setItem(KEY_STORE, keyInput.value.trim());
      } catch (_) {
        /* ignore */
      }
    });
  }
}

async function boot() {
  initTheme();
  bindEvents();
  try {
    await loadMeta();
  } catch (err) {
    statusLine(
      '无法加载服务端元信息：' + (err && err.message ? err.message : String(err)) +
        '（若服务端启用了 API Key，请在上方输入）',
      'error'
    );
    $('keyWrap').hidden = false;
  }
}

document.addEventListener('DOMContentLoaded', boot);
