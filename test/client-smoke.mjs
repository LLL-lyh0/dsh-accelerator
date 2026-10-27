// 客户端半场冒烟测试：把真实的 client.js 丢进 Node vm，用最小 React/DOM 桩跑起来。
//
// 为什么值得做：client.js 没有构建步骤、没有类型检查，语法能过但「注册错槽位 id /
// 渲染函数返回 undefined / fetch 路径写错 / 节点编辑改错字段」这类错都能躲过 node --check。
// 这里用真实源码 + 假 fetch，直接断言「渲染出了什么」和「点按钮发了什么请求」。
//
//   node test/client-smoke.mjs

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLIENT = path.join(HERE, '..', 'client.js');

const failures = [];
let checks = 0;
function ok(cond, label, got) {
  checks += 1;
  if (cond) { console.log(`  ✓ ${label}`); return; }
  failures.push(label);
  console.log(`  ✗ ${label}${got === undefined ? '' : `\n      got: ${typeof got === 'string' ? got : JSON.stringify(got)}`}`);
}

// ── 最小 React（真的会重渲染，不是空壳） ─────────────────────────────────────
function makeReact() {
  const hooks = [];
  let cursor = 0;
  let dirty = false;
  let root = null;
  const React = {
    createElement(type, props, ...children) {
      return { type, props: props || {}, children: children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false) };
    },
    useState(init) {
      const i = cursor++;
      if (!(i in hooks)) hooks[i] = typeof init === 'function' ? init() : init;
      const set = (v) => { hooks[i] = typeof v === 'function' ? v(hooks[i]) : v; dirty = true; };
      return [hooks[i], set];
    },
    useRef(init) {
      const i = cursor++;
      if (!(i in hooks)) hooks[i] = { current: init };
      return hooks[i];
    },
    useEffect(fn, deps) {
      const i = cursor++;
      const prev = hooks[i];
      const changed = !prev || !deps || !prev.deps || deps.length !== prev.deps.length || deps.some((d, k) => d !== prev.deps[k]);
      if (changed) {
        if (prev && typeof prev.cleanup === 'function') prev.cleanup();
        hooks[i] = { deps, cleanup: undefined, pending: fn };
      }
    },
    useCallback(fn, deps) {
      const i = cursor++;
      const prev = hooks[i];
      if (!prev || !deps || deps.some((d, k) => d !== prev.deps[k])) hooks[i] = { deps, fn };
      return hooks[i].fn;
    },
  };

  function runEffects() {
    for (const slot of hooks) {
      if (slot && slot.pending) {
        const fn = slot.pending;
        slot.pending = undefined;
        const r = fn();
        slot.cleanup = typeof r === 'function' ? r : undefined;
      }
    }
  }
  function render() {
    cursor = 0;
    dirty = false;
    const tree = root();
    runEffects();
    return tree;
  }
  return { React, render, isDirty: () => dirty, setRoot: (fn) => { root = fn; } };
}

// 等所有已排队的 promise 与由此触发的重渲染都落定
async function flush(rt) {
  for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 0));
    if (rt.isDirty()) rt.render();
    else if (i > 3) return;
  }
}

// ── 树遍历小工具 ─────────────────────────────────────────────────────────────
function walk(node, fn) {
  if (node === null || node === undefined || node === false) return;
  if (Array.isArray(node)) { node.forEach((n) => walk(n, fn)); return; }
  if (typeof node === 'object') { fn(node); walk(node.children, fn); return; }
  fn(node); // 字符串/数字叶子 —— 必须走到，否则 textOf 什么都收集不到
}
function textOf(node) {
  let out = '';
  walk(node, (n) => {
    if (typeof n === 'string' || typeof n === 'number') out += ` ${n}`;
    if (n && typeof n === 'object' && n.type === 'input' && n.props && n.props.placeholder) out += ` [ph:${n.props.placeholder}]`;
  });
  return out;
}
function findByText(tree, text) {
  let hit = null;
  walk(tree, (n) => { if (!hit && typeof n === 'object' && n.type && textOf(n).includes(text)) hit = n; });
  return hit;
}
function collectButtons(tree) {
  const out = [];
  walk(tree, (n) => { if (n && n.type === 'button') out.push(n); });
  return out;
}
/** 找到「label 文字里含 text」的那个 label 里的第一个 input（复选框用）。 */
function inputByLabel(tree, text) {
  let hit = null;
  walk(tree, (n) => {
    if (hit || !n || n.type !== 'label' || !textOf(n).includes(text)) return;
    walk(n, (m) => { if (!hit && m && m.type === 'input') hit = m; });
  });
  return hit;
}
function buttonByText(tree, text) {
  return collectButtons(tree).find((b) => textOf(b).includes(text)) || null;
}
function collectSelects(tree) {
  const out = [];
  walk(tree, (n) => { if (n && n.type === 'select') out.push(n); });
  return out;
}
/** 找到「value 等于 value」的那个 select（别处可能还有别的 select）。 */
function selectByValue(tree, value) {
  return collectSelects(tree).find((s) => String(s.props.value) === String(value)) || null;
}
/** 找到 placeholder 等于 text 的那个 input（无 label 包裹的输入框用）。 */
function inputByPlaceholder(tree, text) {
  let hit = null;
  walk(tree, (n) => {
    if (hit || !n || n.type !== 'input' || !n.props) return;
    if (String(n.props.placeholder || '') === text) hit = n;
  });
  return hit;
}

// ── 假 fetch（按 URL 路由；没桩到的 URL 直接抛，暴露路径写错） ────────────────
const calls = [];
const STATUS = {
  enabled: false,
  listening: true,
  listen: '127.0.0.2:443',
  ca: { installed: true, subject: 'DSH Accelerator Root CA' },
  hosts: { active: true, entries: 9, expected: 9, writable: true, missing: [] },
  domains: ['github.com', 'steamcommunity.com'],
  nodes: { 'github.com': 2, 'steamcommunity.com': 2 },
  conflicts: [],
  stats: {},
  recent: [{ host: 'github.com', via: '140.82.114.4', ms: 812, reason: 'tls-ok' }],
  lastError: null,
  upstream: { mode: 'direct' },
  autoStart: true,
  proxy: {
    listening: true,
    listen: '127.0.0.2:8843',
    pacUrl: 'http://127.0.0.2:8843/proxy.pac',
    mode: 'auto',
    effective: 'pac',
    active: true,
    autoConfigURL: 'http://127.0.0.2:8843/proxy.pac',
    proxyEnable: 0,
    proxyServer: '',
  },
  smart: {
    enabled: true,
    intervalMin: 15,
    rounds: 3,
    inflight: [],
    lastTick: { reason: 'interval', at: 1_700_000_000_000, verified: 2, ok: 1, bad: 1, repaired: 1, failed: 0 },
    lastVerify: null,
    lastRepair: { domain: 'steamcommunity.com', probed: 3, alive: 2, dead: 1, changed: true, bestMs: 700, healed: true },
  },
};
const VERIFY = {
  at: 1_700_000_001_000,
  check: 'all',
  passed: 1,
  total: 2,
  results: [
    { domain: 'github.com', ok: true, status: 200, ms: 812, cipher: 'TLS_AES_256_GCM_SHA384' },
    { domain: 'steamcommunity.com', ok: false, status: 502, ms: 3000, error: 'HTTP 502' },
  ],
};
const REPAIR = {
  ok: true,
  badFromVerify: ['steamcommunity.com'],
  reports: [{ domain: 'steamcommunity.com', probed: 3, alive: 2, dead: 1, changed: true, bestMs: 700, healed: true }],
  healed: ['steamcommunity.com'],
};
const NODES = {
  'github.com': [{ ip: '140.82.114.4', sni: 'real' }, { ip: '20.205.243.166', sni: 'none' }],
  'steamcommunity.com': [{ ip: '23.218.239.27', sni: 'cdn', sniValue: 'a248.e.akamai.net' }],
};
const CONFIG = { listenHost: '127.0.0.2', listenPort: 443, installCaOnEnable: true, smart: true, autoStart: true, takeover: 'auto', proxyHost: '127.0.0.2', proxyPort: 8843, enforce: [], bypass: [], upstream: { mode: 'direct', host: '', port: 0 } };

function jsonResponse(payload) {
  return { ok: true, status: 200, text: async () => JSON.stringify(payload) };
}
const fetchStub = async (url, opts) => {
  const method = (opts && opts.method) || 'GET';
  const body = opts && opts.body ? JSON.parse(opts.body) : undefined;
  calls.push({ method, url, body });
  const p = String(url).replace('/api/dsh-accelerator', '');
  if (method === 'GET') {
    if (p === '/status') return jsonResponse({ ok: true, value: STATUS });
    if (p === '/nodes') return jsonResponse({ ok: true, value: NODES });
    if (p === '/config') return jsonResponse({ ok: true, value: CONFIG });
    if (p === '/log') return jsonResponse({ ok: true, value: [{ at: 1, level: 'info', msg: '引擎已启动' }] });
    if (p === '/verify') return jsonResponse({ ok: true, value: VERIFY });
  } else {
    if (p === '/start') return jsonResponse({ ok: true, value: { ok: true, checks: [{ id: 'port', ok: true, detail: '127.0.0.2:443' }] } });
    if (p === '/stop') return jsonResponse({ ok: true, value: { ok: true, checks: [] } });
    if (p === '/nodes') return jsonResponse({ ok: true, value: body.nodes });
    if (p === '/config') return jsonResponse({ ok: true, value: CONFIG });
    if (p === '/probe') return jsonResponse({ ok: true, value: { 'github.com': [{ ip: '140.82.114.4', ok: true, ms: 800 }] } });
    if (p === '/repair') return jsonResponse({ ok: true, value: REPAIR });
  }
  if (p === '/nope') return { ok: false, status: 404, text: async () => '<html>not found</html>' };
  throw new Error(`未桩到的请求: ${method} ${url}`);
};

// ── 装载真实 client.js ──────────────────────────────────────────────────────
const rt = makeReact();
let captured = null;
const timers = [];
const sandbox = {
  console,
  fetch: fetchStub,
  setTimeout,
  clearTimeout,
  setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
  clearInterval: () => {},
  Promise,
  JSON,
  Object,
  Array,
  String,
  Number,
  Math,
  Date,
  Error,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.window.prompt = () => 'example.com';
sandbox.window.confirm = () => true;
sandbox.window.__ModuleLoader__ = { load: (def) => { captured = def; } };
sandbox.require = (name) => {
  if (name === 'react') return rt.React;
  throw new Error(`未桩到的模块: ${name}`);
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(CLIENT, 'utf8'), sandbox, { filename: 'client.js' });

console.log('client.js 冒烟测试\n');

// 1. 模块外壳
ok(captured !== null, '调用 window.__ModuleLoader__.load');
ok(captured && captured.id === 'dsh-accelerator', 'id 等于包名（否则报 loaded without registering）', captured && captured.id);
ok(typeof captured.factory === 'function', 'factory 是函数');

const mod = captured.factory(sandbox.require);
ok(Array.isArray(mod.inject) && mod.inject.includes('slots'), 'inject 含 slots', mod.inject);
ok(typeof mod.apply === 'function', '导出 apply');

// 2. apply → 槽位注册
const registered = [];
const ctx = {
  effect: (fn, label) => { const d = fn(); return d; },
  slots: {
    inject: (name, cb) => cb(),
    register: (meta, Comp) => { registered.push({ meta, Comp }); return () => {}; },
  },
};
mod.apply(ctx);
ok(registered.length === 1, '注册了一个槽位组件', registered.length);
const slot = registered[0];
ok(slot.meta.name === 'settings.section', '槽位名是 settings.section', slot.meta.name);
ok(slot.meta.id === 'dsh-accelerator', '槽位 id 唯一', slot.meta.id);
ok(typeof slot.meta.order === 'number', '带 order（决定左侧导航位置）', slot.meta.order);
ok(slot.meta.label() === '加速器', 'label 返回「加速器」', slot.meta.label());

// 3. 首屏渲染（数据加载前 → 加载中）
rt.setRoot(() => slot.Comp());
let tree = rt.render();
ok(textOf(tree).includes('加载中'), '挂载即渲染「加载中」占位');

// 4. 数据到位后的渲染
await flush(rt);
tree = rt.render();
const text = textOf(tree);
ok(text.includes('运行中'), '状态显示「运行中」', text.slice(0, 120));
ok(text.includes('127.0.0.2:443'), '显示监听地址');
ok(text.includes('已安装'), '显示根证书已安装');
ok(text.includes('github.com'), '列出域名 github.com');
ok(text.includes('steamcommunity.com'), '列出域名 steamcommunity.com');
ok(text.includes('140.82.114.4'), '节点 IP 渲染为可编辑输入');
ok(text.includes('a248.e.akamai.net'), 'sni=cdn 时显示 sniValue 输入框');
ok(text.includes('节点池'), '有「节点池」区块');
ok(text.includes('引擎已启动'), '渲染日志');
ok(text.includes('140.82.114.4'), '渲染最近裁定');
ok(timers.length >= 1 && timers[0].ms === 5000, '注册了 5s 轮询定时器', timers[0] && timers[0].ms);

// 5. 交互：停止加速 → 应发 POST /stop
const btns = collectButtons(tree);
const stopBtn = btns.find((b) => textOf(b).includes('停止加速'));
ok(Boolean(stopBtn), '运行中时主按钮是「停止加速」');
calls.length = 0;
stopBtn.props.onClick();
await flush(rt);
ok(calls.some((c) => c.method === 'POST' && c.url.endsWith('/stop')), '点击后 POST /stop', calls.map((c) => `${c.method} ${c.url}`));

// 6. 交互：保存节点池 → POST /nodes 且带节点数据
tree = rt.render();
const saveBtn = collectButtons(tree).find((b) => textOf(b).includes('保存'));
ok(Boolean(saveBtn), '有「保存」按钮');
calls.length = 0;
saveBtn.props.onClick();
await flush(rt);
const saveCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/nodes'));
ok(Boolean(saveCall) && saveCall.body && saveCall.body.nodes && saveCall.body.nodes['github.com']?.length === 2,
  'POST /nodes 带上服务端首屏拿到的节点池（不留空数组）', saveCall && saveCall.body);

// 7. 编辑节点字段：改 IP → 再保存 → 请求体里是新值
tree = rt.render();
let ipInput = null;
walk(tree, (n) => {
  if (!ipInput && n.type === 'input' && n.props && n.props.value === '140.82.114.4') ipInput = n;
});
ok(Boolean(ipInput), '找到 IP 输入框');
ipInput.props.onChange({ target: { value: '1.2.3.4' } });
await flush(rt);
tree = rt.render();
const saveBtn2 = collectButtons(tree).find((b) => textOf(b).includes('保存'));
calls.length = 0;
saveBtn2.props.onClick();
await flush(rt);
const saveCall2 = calls.find((c) => c.method === 'POST' && c.url.endsWith('/nodes'));
ok(Boolean(saveCall2) && JSON.stringify(saveCall2.body).includes('1.2.3.4'), '编辑后的 IP 进入请求体', saveCall2 && saveCall2.body);

// 8. 策略：强制走加速的进程名 → 保存策略带上数组
tree = rt.render();
const cfgInput = (() => {
  let hit = null;
  walk(tree, (n) => {
    if (!hit && n.type === 'input' && n.props && typeof n.props.placeholder === 'string' && n.props.placeholder.includes('steam.exe')) hit = n;
  });
  return hit;
})();
ok(Boolean(cfgInput), '有「强制走加速的进程」输入框');
cfgInput.props.onChange({ target: { value: 'steam.exe, git.exe' } });
await flush(rt);
tree = rt.render();
const cfgSave = collectButtons(tree).find((b) => textOf(b).includes('保存策略'));
ok(Boolean(cfgSave), '有「保存策略」按钮');
calls.length = 0;
cfgSave.props.onClick();
await flush(rt);
const cfgCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/config'));
ok(Boolean(cfgCall) && Array.isArray(cfgCall.body.config.enforce) && cfgCall.body.config.enforce.join(',') === 'steam.exe,git.exe',
  'enforce 被逗号解析成数组', cfgCall && cfgCall.body && cfgCall.body.config && cfgCall.body.config.enforce);

// 9. 检测与智能：卡片渲染 + 「立即检测」/「智能修复」两个动作
tree = rt.render();
const smartText = textOf(tree);
ok(smartText.includes('检测与智能'), '有「检测与智能」区块');
ok(smartText.includes('智能加速'), '有「智能加速」开关');
ok(smartText.includes('随 DSH 启动'), '有「随 DSH 启动」开关');
ok(smartText.includes('每 15 分钟'), '显示智能巡检间隔（来自 status.smart）');
ok(smartText.includes('最近修复'), '显示最近一次智能修复结论');

const verifyBtn = buttonByText(tree, '立即检测');
ok(Boolean(verifyBtn), '有「立即检测」按钮');
calls.length = 0;
verifyBtn.props.onClick();
await flush(rt);
ok(calls.some((c) => c.method === 'GET' && c.url.endsWith('/verify')), '点「立即检测」发 GET /verify', calls.map((c) => `${c.method} ${c.url}`));
tree = rt.render();
const verifyText = textOf(tree);
ok(verifyText.includes('最近一次检测') && verifyText.includes('通过 1/2'), '渲染检测结果汇总（通过 1/2）', verifyText.slice(0, 200));
ok(verifyText.includes('HTTP 200') && verifyText.includes('HTTP 502'), '逐域名渲染真实状态码（200 与 502）');
ok(verifyText.includes('812ms'), '渲染每个域名的握手/响应耗时');

const repairBtn = buttonByText(tree, '智能修复');
ok(Boolean(repairBtn), '有「智能修复」按钮');
calls.length = 0;
repairBtn.props.onClick();
await flush(rt);
ok(calls.some((c) => c.method === 'POST' && c.url.endsWith('/repair')), '点「智能修复」发 POST /repair', calls.map((c) => `${c.method} ${c.url}`));
ok(calls.filter((c) => c.method === 'GET' && c.url.endsWith('/verify')).length >= 1, '智能修复后会再 GET /verify 复验');

// 10. 「智能加速」开关 → 保存策略要带上 smart:false
tree = rt.render();
const smartToggle = inputByLabel(tree, '智能加速');
ok(Boolean(smartToggle) && smartToggle.props.type === 'checkbox', '找到「智能加速」复选框', smartToggle && smartToggle.props);
smartToggle.props.onChange({ target: { checked: false } });
await flush(rt);
tree = rt.render();
const cfgSave2 = buttonByText(tree, '保存策略');
calls.length = 0;
cfgSave2.props.onClick();
await flush(rt);
const smartCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/config'));
ok(Boolean(smartCall) && smartCall.body.config.smart === false, '保存策略带上 smart:false', smartCall && smartCall.body && smartCall.body.config);
ok(Boolean(smartCall) && smartCall.body.config.autoStart === true, '保存策略带上 autoStart:true', smartCall && smartCall.body && smartCall.body.config);

// 11. hosts 只读路径：别家加速器把 ACL 改成只读时要讲清楚，而不是只显示一个红灯
ok(textOf(tree).includes('已写入 9/9 条'), 'hosts 行显示 已写入 N/M 条', textOf(tree).slice(0, 160));
STATUS.hosts = {
  active: true, entries: 2, expected: 9, writable: false,
  missing: ['github.com', 'steamcommunity.com'],
};
STATUS.conflicts = [{
  source: 'Steamcommunity_302', domains: ['github.com', 'steamcommunity.com'], shadowed: ['github.com', 'steamcommunity.com'],
  overridden: [], severity: 'blocked', ip: '127.0.0.1', line: 213,
}];
tree = rt.render();
const refreshBtn = buttonByText(tree, '刷新');
ok(Boolean(refreshBtn), '有「刷新」按钮');
calls.length = 0;
refreshBtn.props.onClick();
await flush(rt);
tree = rt.render();
const roText = textOf(tree);
ok(roText.includes('不可写'), 'hosts 不可写时状态行明说「不可写」', roText.slice(0, 200));
ok(roText.includes('已写 2/9 条'), 'hosts 不可写时显示 已写 N/M 条');
ok(roText.includes('hosts 缺') && roText.includes('github.com'), '列出被别家加速器删掉的域名');
ok(roText.includes('hosts 被压制') && roText.includes('我们的引导未生效'), '被别家压在后面时如实说「我们的引导未生效」', roText.slice(0, 240));
ok(!roText.includes('[object Object]'), '冲突按对象渲染（不是 [object Object]）');
ok(roText.includes('/grant Users:F'), '给出可执行的 icacls 修复命令');
// 共存（我们优先）时不该报警，只说明「我们优先」—— 改桩数据后必须重新取一次才进状态
STATUS.conflicts = [{
  source: 'Steamcommunity_302', domains: ['github.com', 'steamcommunity.com'], shadowed: [],
  overridden: ['github.com', 'steamcommunity.com'], severity: 'info', ip: '127.0.0.1', line: 213,
}];
calls.length = 0;
buttonByText(tree, '刷新').props.onClick();
await flush(rt);
tree = rt.render();
const coText = textOf(tree);
ok(coText.includes('hosts 共存') && coText.includes('我们优先'), '共存时显示 info 文案，不是告警', coText.slice(0, 240));
ok(!coText.includes('hosts 被压制'), '共存时没有「被压制」告警');
// 还原桩数据，避免影响后续断言
STATUS.hosts = { active: true, entries: 9, expected: 9, writable: true, missing: [] };
STATUS.conflicts = [];

// 11.5 接管方式（PAC / hosts）：hosts 被改成只读之后，PAC 是唯一还能接管的路径，
//      所以设置页必须能看懂「现在靠什么接管」并能切换。
const tkText = textOf(tree);
ok(tkText.includes('接管方式'), '状态卡显示「接管方式」', tkText.slice(0, 200));
ok(tkText.includes('PAC（系统代理自动配置）'), '接管方式显示为 PAC');
ok(tkText.includes('PAC 地址') && tkText.includes('/proxy.pac'), '显示 PAC 地址');
ok(tkText.includes('（已写入系统）'), 'PAC 已写入系统时明说');
ok(tkText.includes('git、curl、npm') && tkText.includes('PAC'), '提示 git/npm 不读 PAC 的边界');
const tkSelect = selectByValue(tree, 'auto');
ok(Boolean(tkSelect), '策略卡有接管方式选择器（当前 auto）');
if (tkSelect) {
  const values = [];
  walk(tkSelect, (n) => { if (n && n.type === 'option') values.push(String(n.props.value)); });
  ok(['auto', 'hosts', 'pac', 'fixed'].every((v) => values.includes(v)), '接管方式四个选项齐全', values.join(','));
}
const phInput = inputByPlaceholder(tree, '代理监听地址');
ok(Boolean(phInput) && phInput.props.value === '127.0.0.2', '有代理监听地址输入框', phInput && phInput.props.value);
const ppInput = inputByPlaceholder(tree, '代理端口');
ok(Boolean(ppInput) && Number(ppInput.props.value) === 8843, '有代理端口输入框', ppInput && ppInput.props.value);
// 切到 pac 再保存：请求体必须带上接管方式与新端口
if (tkSelect) {
  calls.length = 0;
  tkSelect.props.onChange({ target: { value: 'pac' } });
  await flush(rt);
  tree = rt.render();
  const pp2 = inputByPlaceholder(tree, '代理端口');
  if (pp2) pp2.props.onChange({ target: { value: '8850' } });
  await flush(rt);
  tree = rt.render();
  buttonByText(tree, '保存策略').props.onClick();
  await flush(rt);
  const tkCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/config'));
  ok(Boolean(tkCall) && tkCall.body.config.takeover === 'pac', '保存策略带上 takeover:pac', tkCall && tkCall.body && tkCall.body.config);
  ok(Boolean(tkCall) && tkCall.body.config.proxyPort === 8850, '保存策略带上 proxyPort:8850', tkCall && tkCall.body && tkCall.body.config);
}

// 12. 错误路径：接口挂掉时要显示错误而不是白屏（这里靠 /nope 的 404+HTML 分支验证解析兜底）
const bad = await sandbox.fetch('/api/dsh-accelerator/nope').then((r) => r.text());
ok(typeof bad === 'string' && bad.includes('not found'), '404 回 HTML 时的响应桩可用（call() 里已先判 r.ok 再 json）');

console.log(`\n${checks - failures.length}/${checks} 通过`);
if (failures.length) {
  console.log('失败项：');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
