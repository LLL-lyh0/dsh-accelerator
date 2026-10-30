// dsh-accelerator — Host half.
//
// 随 DSH 自启动：profile 挂载本插件 → apply() 里初始化存储/证书 → 若 config.enabled
// 立即拉起 MITM 引擎并写 hosts；停用/卸载时回滚 hosts、停引擎。
//
// 外部 AI 扩展面（用户需求「支持外部使用 AI 扩展节点」）有两层，互为备份：
//   1) 文件即接口：~/.dsh/storages/dsh-accelerator/nodes.json —— 任何外部
//      AI/脚本直接改这个 JSON，管理页或工具「reload_nodes」即生效。
//   2) accelerator agent 工具 —— 会话内的 AI 用它查询/更新节点、开关加速、测活、策展。
//
// HTTP 面 /api/dsh-accelerator/* 只给同源设置页用（回环 Host + Origin 围栏）。
//
// 证书链：叶证书带 CDP（CRL 分发点，指向本地代理的 /dsh-accelerator.crl），
// 代理在任何接管模式下都要监听——hosts 模式下它只干「分发 CRL」这一件事。
// 少了它，Schannel 系客户端（curl.exe / git）会以 CRYPT_E_NO_REVOCATION_CHECK
// 拒绝握手；CRL 的 DER 里 crlExtensions 必须是 [0] 而不是 [3]（见 lib/certs.mjs）。
//
// 改动本文件会触发宿主重载整个包（含 lib/*.mjs 的新模块图）；只改 lib/ 下的文件
// 有时不会被拾取 —— 需要重载时顺手在这里动一行。
// reload-token: 2026-10-27 (hosts 只读诊断：status.hosts.{writable,expected,missing} + 冲突按来源归因)

import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync, cpSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Accelerator } from './lib/accelerator.mjs';
import { SmartController } from './lib/smart.mjs';
import { curateDomain, pickAlive } from './lib/curator.mjs';
import { isBadResult } from './lib/verify.mjs';
import { readHosts, parseOwnBlock, missingManaged, detectConflicts } from './lib/hosts.mjs';
import { currentTakeover } from './lib/system-proxy.mjs';

// 刻意不在模块级硬依赖 webServer/tools：纯 CLI 宿主里这两个服务不存在，
// 硬 inject 会让 cordis 永远等不齐、插件静默不加载（dsh-zen-free 在 0.2.1 踩过这个坑）。
export const inject = [];

const NS = 'dsh-accelerator';
const ROUTE_BASE = '/api/dsh-accelerator';

function dshHome() {
  const fromEnv = process.env.DSH_HOME;
  return typeof fromEnv === 'string' && fromEnv.trim() !== '' ? fromEnv : join(homedir(), '.dsh');
}

let acc = null;               // 单例：bundle 在 profile 里只挂一份
let smart = null;             // 智能加速控制器（巡检 / 自动换节点 / 自动验证）
let watchdog = null;
const lastLog = [];           // 环形日志，给管理页显示

function log(level, msg) {
  lastLog.push({ at: Date.now(), level, msg: String(msg) });
  if (lastLog.length > 300) lastLog.shift();
  try {
    const fn = acc?.logger?.[level === 'warn' ? 'warn' : level === 'error' ? 'error' : 'info'];
    (typeof fn === 'function' ? fn : console.log).call(acc?.logger ?? console, `[${NS}] ${msg}`);
  } catch { /* logger 不可用时别把主流程带崩 */ }
}

// ── origin fence（回环 Host + 同源 Origin；与 dsh-github-manager 同款） ───────
function isLoopbackAuthority(host) {
  if (typeof host !== 'string' || host === '') return false;
  try {
    const name = new URL(`http://${host}`).hostname;
    if (name === 'localhost' || name === '[::1]' || name === '::1') return true;
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(name);
  } catch { return false; }
}
function checkOrigin(req) {
  if (!isLoopbackAuthority(req.headers.host)) return 'forbidden host';
  if (req.headers['sec-fetch-site'] === 'cross-site') return 'cross-site';
  const origin = req.headers.origin;
  if (typeof origin === 'string' && origin !== '') {
    try {
      if (new URL(origin).host !== req.headers.host) return 'origin mismatch';
    } catch { return 'bad origin'; }
  }
  return null;
}

function sendJson(res, code, payload) {
  if (!res || res.writableEnded || res.destroyed) return;
  try {
    const body = JSON.stringify(payload);
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  } catch { /* client gone */ }
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 2 << 20) throw new Error('body too large');
    chunks.push(c);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// ── operations：HTTP 与 agent 工具共用同一实现，两边永不漂移 ─────────────────

const ops = {
  status: () => acc.status(),

  async start() {
    const r = await acc.start();
    log('info', `start → ${(r.checks ?? []).map((c) => `${c.id}:${c.ok ? 'ok' : c.detail}`).join(', ')}`);
    if (r.ok && acc.config.smart !== false) {
      smart.start();
      // 开启后立刻自检一轮，把「以为开着、其实不通」的域名当场挑出来修掉。
      selfCheck('start').catch(() => {});
    }
    return r;
  },

  async stop() {
    smart.stop();
    const r = await acc.stop();
    log('info', 'stopped & rolled back');
    return r;
  },

  /** 重载 nodes.json（外部 AI 改完文件后调这个，或管理页点「重载文件」）。 */
  async reloadNodes() {
    const stored = await acc.storage.readNodes(null);
    if (!stored || Object.keys(stored).length === 0) throw new Error('nodes.json 为空或不可解析');
    return acc.replaceNodes(stored);
  },

  nodesGet: () => acc.readonlyNodes(),
  nodesSet: (payload) => acc.replaceNodes(payload.nodes ?? payload),
  nodeUpsert: (payload) => acc.upsertNode(String(payload.domain), {
    ip: String(payload.ip),
    sni: payload.sni ?? 'real',
    sniValue: payload.sniValue,
  }),
  nodeDelete: (payload) => acc.removeNode(String(payload.domain), String(payload.ip)),

  async configSet(payload) {
    const patch = payload.config ?? payload;
    const wasRunning = acc.engine.listening;
    const next = await acc.updateConfig(patch);
    if (wasRunning && (patch.listenHost || patch.listenPort)) {
      await acc.engine.stop();
      await acc.engine.start();
    }
    return next;
  },

  caReinstall: () => acc.reinstallCa(),

  /** 测活：对每个受管域名的所有节点走一遍 TCP+TLS。只报告，不改数据。 */
  async probe() {
    const out = {};
    for (const domain of Object.keys(acc.nodes)) {
      const results = await curateDomain(domain, acc.nodes[domain] ?? [], acc.config.upstream, { addDoh: false });
      out[domain] = results;
    }
    return out;
  },

  /** 策展：测活 + DoH 补 IP + 写回 nodes.json（按延迟排序、只留可用）。 */
  async curate(payload) {
    const only = Array.isArray(payload?.domains) && payload.domains.length ? payload.domains : null;
    const next = acc.readonlyNodes();
    const summary = {};
    for (const domain of only ?? Object.keys(next)) {
      const results = await curateDomain(domain, next[domain] ?? [], acc.config.upstream, {
        addDoh: payload?.addDoh !== false,
        dohSni: ['real', 'none'],
      });
      const alive = pickAlive(results, 6);
      if (alive.length > 0) next[domain] = alive;
      summary[domain] = {
        alive: alive.length,
        dead: results.filter((r) => !r.ok).length,
        bestMs: results.filter((r) => r.ok).reduce((m, r) => (m === null || r.ms < m ? r.ms : m), null),
      };
    }
    await acc.replaceNodes(next);
    return summary;
  },

  /** 检测验证：经自己的代理逐个域名实测（不改数据）。 */
  async verify(payload) {
    const domains = Array.isArray(payload?.domains) && payload.domains.length ? payload.domains : undefined;
    const results = await smart.verify(domains);
    return {
      at: Date.now(),
      check: domains ? 'subset' : 'all',
      passed: results.filter((r) => !isBadResult(r)).length,
      total: results.length,
      results,
    };
  },

  /**
   * 智能修复：先验证，再对不通的域名换节点（测活 + DoH 补池 + 重新验证）。
   * 显式调用默认 `force: true` —— 用户/AI 明确说「修」的时候不该被冷却挡回去。
   */
  async repair(payload = {}) {
    let domains = Array.isArray(payload.domains)
      ? payload.domains.filter(Boolean)
      : (payload.domain ? [String(payload.domain)] : []);
    let badFromVerify = null;
    if (domains.length === 0) {
      const results = await smart.verify();
      badFromVerify = results.filter(isBadResult).map((r) => r.domain);
      const unhealthy = acc.engine.health.unhealthyHosts({ minFailures: 1 }).map((h) => h.host);
      domains = [...new Set([...badFromVerify, ...unhealthy])];
      if (domains.length === 0) {
        return { ok: true, nothingToDo: true, message: '所有受管域名验证通过，无需修复', verified: results.length };
      }
    }
    const reports = [];
    for (const d of domains) {
      reports.push(await smart.repair(d, { addDoh: payload.addDoh !== false, force: payload.force !== false }));
    }
    return {
      ok: true,
      badFromVerify,
      reports,
      healed: reports.filter((r) => r.healed).map((r) => r.domain),
    };
  },

  logSlice: () => lastLog.slice(-80),
};

/**
 * 启动自检：验证所有受管域名，**对不通的当场智能修复**。
 * 这是 m01160 的「检测验证」：不再只依赖连接失败的副作用，而是主动量一次。
 */
let selfCheckRunning = false;
async function selfCheck(reason) {
  if (selfCheckRunning || !smart || !acc?.engine?.listening) return null;
  selfCheckRunning = true;
  try {
    const results = await smart.verify();
    const bad = results.filter(isBadResult).map((r) => r.domain);
    log(bad.length ? 'warn' : 'info',
      `自检(${reason})：${results.length - bad.length}/${results.length} 个域名通过${bad.length ? `，异常 [${bad.join(', ')}]` : ''}`);
    const repairs = [];
    for (const d of bad) {
      repairs.push(await smart.repair(d, { addDoh: true }).catch((e) => ({ domain: d, error: String(e?.message ?? e) })));
    }
    return { reason, at: Date.now(), results, bad, repairs };
  } catch (e) {
    log('warn', `自检(${reason}) 失败: ${e?.message ?? e}`);
    return null;
  } finally {
    selfCheckRunning = false;
  }
}

// ── HTTP surface ────────────────────────────────────────────────────────────

const GET_ROUTES = {
  '/status': () => ops.status(),
  '/nodes': () => ops.nodesGet(),
  '/config': () => acc.config,
  '/log': () => ops.logSlice(),
  '/probe': () => ops.probe(),
  '/verify': () => ops.verify({}),
};

const POST_ROUTES = {
  '/start': () => ops.start(),
  '/stop': () => ops.stop(),
  '/reload-nodes': () => ops.reloadNodes(),
  '/nodes': (body) => ops.nodesSet(body),
  '/node-upsert': (body) => ops.nodeUpsert(body),
  '/node-delete': (body) => ops.nodeDelete(body),
  '/config': (body) => ops.configSet(body),
  '/ca-reinstall': () => ops.caReinstall(),
  '/curate': (body) => ops.curate(body),
  '/verify': (body) => ops.verify(body),
  '/repair': (body) => ops.repair(body),
  '/selfcheck': (body) => selfCheck(body?.reason ?? 'manual'),
};

function routeHandler() {
  return async (req, res) => {
    const denied = checkOrigin(req);
    if (denied) { sendJson(res, 403, { ok: false, code: 'forbidden', error: denied }); return; }
    let path = '/';
    try {
      path = new URL(req.url, 'http://localhost').pathname;
      if (path.startsWith(ROUTE_BASE)) path = path.slice(ROUTE_BASE.length) || '/';
    } catch { sendJson(res, 400, { ok: false, error: 'bad url' }); return; }

    try {
      if (req.method === 'GET' || req.method === 'HEAD') {
        const fn = GET_ROUTES[path];
        if (!fn) { sendJson(res, 404, { ok: false, error: `unknown route: ${path}` }); return; }
        sendJson(res, 200, { ok: true, value: await fn() });
        return;
      }
      if (req.method === 'POST') {
        const fn = POST_ROUTES[path];
        if (!fn) { sendJson(res, 404, { ok: false, error: `unknown route: ${path}` }); return; }
        const body = await readBody(req);
        sendJson(res, 200, { ok: true, value: await fn(body) });
        return;
      }
      sendJson(res, 405, { ok: false, error: 'GET or POST only' });
    } catch (e) {
      sendJson(res, 500, { ok: false, error: String(e?.message ?? e) });
    }
  };
}

// ── agent tool（会话内 AI 的扩展入口） ───────────────────────────────────────

function textRender(_args, value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }];
}

function registerTool(ctx) {
  ctx.effect(() => ctx.tools.register({
    name: 'accelerator',
    description: [
      'Manage this machine\'s local accelerator (dsh-accelerator): a loopback MITM proxy that unblocks SNI-blocked domains (steamcommunity/github/huggingface/opencode/openrouter...).',
      'Actions: status (running? domains? conflicts?), start, stop,',
      'nodes_get / nodes_set (full pool JSON keyed by domain, node = {ip, sni: "real"|"none"|"cdn", sniValue?}),',
      'node_upsert {domain,ip,sni} / node_delete {domain,ip},',
      'probe (test every node without writing), curate (test + DoH-expand pool and keep fastest alive nodes),',
      'verify (fetch every managed domain THROUGH this proxy and report the real HTTP status; pass domains to limit),',
      'repair (verify first, then for every failing domain re-pick nodes: probe + DoH-expand the pool and re-verify; pass domains to limit, force to ignore the 90s cooldown),',
      'config_set (partial: enforce/bypass process names, upstream {mode:http|socks5|direct,host,port,...}, listenHost/listenPort, domainGroups, smart, autoStart),',
      'reload_nodes (pick up an externally edited nodes.json), log.',
      'External AIs may also edit ~/.dsh/storages/dsh-accelerator/nodes.json directly, then call reload_nodes.',
    ].join(' '),
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['status', 'start', 'stop', 'nodes_get', 'nodes_set', 'node_upsert', 'node_delete', 'probe', 'curate', 'verify', 'repair', 'config_set', 'reload_nodes', 'log'],
          description: 'Which operation to perform.',
        },
        nodes: { type: 'object', description: 'nodes_set: full pool, e.g. {"github.com":[{"ip":"140.82.114.4","sni":"real"}]}' },
        domain: { type: 'string', description: 'node_upsert/node_delete: domain key' },
        ip: { type: 'string', description: 'node_upsert/node_delete: node IPv4' },
        sni: { type: 'string', enum: ['real', 'none', 'cdn'], description: 'node_upsert: SNI strategy (none = omit SNI; Akamai/CloudFront need it)' },
        sniValue: { type: 'string', description: 'node_upsert: literal SNI when sni=cdn (e.g. a248.e.akamai.net)' },
        config: { type: 'object', description: 'config_set: partial config object' },
        domains: { type: 'array', items: { type: 'string' }, description: 'curate/verify/repair: optional subset of domains' },
        force: { type: 'boolean', description: 'repair: ignore the per-domain cooldown (default true for explicit calls)' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object' }, render: textRender },
    timeoutMs: 180_000,
    async execute(args) {
      const a = String(args?.action ?? '');
      try {
        switch (a) {
          case 'status': return { ok: true, value: await ops.status() };
          case 'start': return await ops.start();
          case 'stop': return await ops.stop();
          case 'nodes_get': return { ok: true, value: await ops.nodesGet() };
          case 'nodes_set': return { ok: true, value: await ops.nodesSet(args ?? {}) };
          case 'node_upsert': return { ok: true, value: await ops.nodeUpsert(args ?? {}) };
          case 'node_delete': return { ok: true, value: await ops.nodeDelete(args ?? {}) };
          case 'probe': return { ok: true, value: await ops.probe() };
          case 'curate': return { ok: true, value: await ops.curate(args ?? {}) };
          case 'verify': return { ok: true, value: await ops.verify(args ?? {}) };
          case 'repair': return { ok: true, value: await ops.repair(args ?? {}) };
          case 'config_set': return { ok: true, value: await ops.configSet(args ?? {}) };
          case 'reload_nodes': return { ok: true, value: await ops.reloadNodes() };
          case 'log': return { ok: true, value: ops.logSlice() };
          default: return { ok: false, error: `unknown action: ${a}` };
        }
      } catch (e) {
        return { ok: false, error: String(e?.message ?? e) };
      }
    },
  }), `${NS}: accelerator tool`);
}

// ── 内置技能（m01160④：连接频繁失败时的三条修复路径） ───────────────────────
//
// 技能正文写在 skill/ 里而不是别处：离线可用、不会和工具定义漂移，
// 外部 AI 也能直接读这个目录来理解怎么修。

const SKILL_NAME = 'accelerator-repair';
const SKILL_PROVIDER = NS;
/** 与其它打包技能 provider 同一优先级（见 @deepseek-ai/dsh-skill）。 */
const BUNDLED_SKILL_RANK = 600;
/** 兜底描述：权威副本是 skill/SKILL.md 的 frontmatter，读不到时才用它，保证注册绝不炸插件。 */
const SKILL_FALLBACK_DESCRIPTION = '修复本机 dsh-accelerator（本地加速器）连不上、变慢、证书报错的问题，并在需要时扩充节点池。当 github / steamcommunity / huggingface 等域名反复超时、TLS 报错、502，或用户说「换节点 / 更新节点 / 加速器不管用了」时使用；也用于配置强制走加速的程序、屏蔽不想被接管的程序、切换外部上游，以及核查加速带来的隐私与数据安全影响。';

const SKILL_SOURCE_DIR = fileURLToPath(new URL('./skill/', import.meta.url));

/** 切掉 `---` frontmatter，容忍朴素 `key: value`。 */
function parseFrontmatter(raw) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u.exec(raw);
  if (match === null) return { attributes: {}, content: raw };
  const attributes = {};
  for (const line of match[1].split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim().replace(/^["']|["']$/gu, '');
    if (key !== '') attributes[key] = value;
  }
  return { attributes, content: raw.slice(match[0].length).trim() };
}

function registerSkill(ctx) {
  if (typeof ctx.inject !== 'function') return;
  try {
    ctx.inject(['skills'], (scope) => {
      scope.effect(function* () {
        // 插件可能被打进 ASAR（普通文件读取会被挡），所以技能掌握一份私有副本，
        // 生命周期与本注册绑定。
        const directory = mkdtempSync(join(tmpdir(), 'dsh-accelerator-skill-'));
        yield async () => { await rm(directory, { recursive: true, force: true }); };
        let locator = join(directory, 'SKILL.md');
        let description = SKILL_FALLBACK_DESCRIPTION;
        try {
          cpSync(SKILL_SOURCE_DIR, directory, { recursive: true });
          const parsed = parseFrontmatter(readFileSync(locator, 'utf8'));
          if (typeof parsed.attributes.description === 'string' && parsed.attributes.description !== '') {
            description = parsed.attributes.description;
          }
        } catch (error) {
          // 宁可只带兜底描述，也不要因为打包疏漏让插件激活失败。
          console.warn(`[${NS}] 加速器技能资源不可用，仍以最小描述注册：`, error);
          locator = join(SKILL_SOURCE_DIR, 'SKILL.md');
        }
        const candidate = {
          name: SKILL_NAME,
          description,
          invocation: { modelInvocable: true, userInvocable: true },
          provider: SKILL_PROVIDER,
          source: 'bundled',
          rank: BUNDLED_SKILL_RANK,
          resourceBase: { kind: 'directory', path: directory },
          locator,
        };
        const provider = {
          name: SKILL_PROVIDER,
          list: () => Promise.resolve([candidate]),
          async get(entry, options) {
            const { rank: _rank, locator: entryPath, ...summary } = entry;
            const raw = await readFile(entryPath, { encoding: 'utf8', signal: options?.signal });
            return { ...summary, content: parseFrontmatter(raw).content };
          },
        };
        yield scope.skills.registerProvider(() => provider);
      }, `${NS}: 加速器修复技能资源`);
    });
  } catch (error) {
    console.warn(`[${NS}] 技能服务不可用，加速器技能未注册：`, error);
  }
}

// ── 生命周期 ────────────────────────────────────────────────────────────────

export function apply(ctx) {
  const baseLogger = typeof ctx?.logger === 'function' ? ctx.logger(NS) : console;
  acc = new Accelerator({ dir: join(dshHome(), 'storages', NS), logger: baseLogger });
  smart = new SmartController({ acc, log });
  acc.smart = smart;

  // 智能加速的即时触发点：引擎报告「这个域名的候选池全挂了」→ 立刻换节点（有冷却保护）。
  acc.engine.on('exhausted', (info) => {
    if (!smart.enabled || !acc.config.enabled) return;
    smart.repair(info.host, { addDoh: true }).catch((e) => log('warn', `自动修复失败 ${info.host}: ${e?.message ?? e}`));
  });

  // effect 体内**不能 await**：cordis 把 effect 的返回值当 disposer，
  // async 函数返回 Promise（不是函数）→ disposer 会失效。初始化排成 promise 链，
  // disposer 同步返回，内部尽力做异步回滚。
  ctx.effect(() => {
    const boot = acc.init().then(async () => {
      // 自愈：上次进程被强杀（没走 dispose）→ hosts 还指着我们但引擎没跑 → 立刻回滚。
      // 同理，残留 PAC（重启后接管状态是空的）也要清：留着 PAC 却关掉引擎，
      // 认系统代理的程序会被指到没人听的 8843 → 受管域名全打不开。
      acc.hostsState = parseOwnBlock(await readHosts());
      const residual = acc.hostsState.active || (await currentTakeover(
        acc.config.proxyHost ?? '127.0.0.2', Number(acc.config.proxyPort) || 8843,
      )).pacActive;
      if (residual && !acc.config.enabled) {
        log('warn', '发现 hosts/系统代理残留且插件未启用 → 自动回滚');
        await acc.stop();
        return;
      }
      // m01160②：enabled（默认就是 true）时 DSH 一打开就自动启动，不需要用户再开一次。
      if (acc.config.enabled && acc.config.autoStart !== false) {
        const r = await acc.start().catch((e) => ({ ok: false, checks: [{ id: 'boot', ok: false, detail: String(e?.message ?? e) }] }));
        if (!r.ok) {
          log('warn', `自启动未完全成功: ${JSON.stringify(r.checks)}`);
        } else {
          log('info', '已随 DSH 自动启动加速');
          if (acc.config.smart !== false) {
            smart.start();
            await selfCheck('boot');       // 启动即量一次，不通的当场修
          }
        }
      }
    }).catch((e) => log('error', `init 失败: ${e?.message ?? e}`));

    watchdog = setInterval(async () => {
      try {
        await boot;                       // 初始化没完成前不做看门动作
        if (!acc.config?.enabled) return;
        acc.hostsState = parseOwnBlock(await readHosts());
        if (!acc.engine.listening) {
          log('error', 'watchdog: 引擎掉线 → 回滚 hosts 并重启');
          await acc.stop().catch(() => {});
          await acc.start().catch((e) => log('error', `watchdog 重启失败: ${e?.message}`));
        } else if (!acc.hostsState.active) {
          log('warn', 'watchdog: 引擎在跑但 hosts 段被别人删了 → 重新写入');
          await acc.start().catch(() => {});   // start 幂等：端口已监听时只补 hosts/CA 检查
        } else if (acc.config.takeover !== 'pac' && acc.config.takeover !== 'fixed') {
          // 段还在，但可能被别家加速器重写后压在后面（Windows 取首个命中 → 等于没生效），
          // 或者被它删掉几行。两者都靠 start() 的幂等重写修回来（applyHosts 会把我们的段
          // 插到别家的段之前）。
          const plain = acc.managedDomains().filter((d) => !d.includes('*'));
          const text = await readHosts();
          const missing = missingManaged(text, plain);
          const shadowed = detectConflicts(text, plain).some((c) => c.severity === 'blocked');
          if (missing.length > 0 || shadowed) {
            log('warn', `watchdog: hosts 引导被别家加速器改动（缺 ${missing.length} 条${shadowed ? '，且被压在后面' : ''}）→ 重写`);
            await acc.start().catch(() => {});
          }
        }
        // 智能定时器若被停掉（除 stop() 之外的路径），补起来，保证「智能加速」一直是活的。
        if (acc.config.smart !== false && !smart.timer) smart.start();
      } catch { /* 定时器里绝不外抛 */ }
    }, 30_000);
    if (watchdog.unref) watchdog.unref();

    return () => {
      clearInterval(watchdog);
      smart.stop();
      // 停用/卸载：尽力回滚。进程若在此之前被硬杀，下次启动由上面的自愈兜住。
      boot.then(() => (acc.engine.listening || acc.hostsState.active
        ? acc.stop().then(() => log('info', '已停用并回滚 hosts'))
        : undefined)).catch(() => {});
    };
  }, `${NS}: lifecycle`);

  // 服务懒注入：有 webServer 才挂 HTTP 面，有 tools 才注册 accelerator 工具，有 skills 才挂内置技能。
  ctx.inject(['webServer'], (child) => {
    child.effect(() => child.webServer.register({
      kind: 'prefix',
      path: ROUTE_BASE,
      handler: routeHandler(),
    }), `${NS}: http surface`);
  });
  ctx.inject(['tools'], (child) => registerTool(child));
  ctx.inject(['skills'], (child) => registerSkill(child));
}
