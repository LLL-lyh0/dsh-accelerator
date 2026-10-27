// 智能加速控制器。
//
// 「智能」在这里有确切含义，全部是本机实测逼出来的三条动作：
//   1) 主动验证：端口在听 ≠ 域名能通。周期性地**经自己的代理**打一遍，拿到真实状态码。
//   2) 自动换节点：实测发现某个域名整池都握不上手（Akamai/CDN 会随 IP 段变化），
//      就重新测活 + 用 DoH 补候选（同时试 real 与 none 两种 SNI 策略）并写回池子。
//   3) 结果反馈：修复后再验一次，成功就清掉失败计数，失败就降级为「已记录」，不空转。
//
// 触发点有两个：定时巡检（滚动抽查，避免每轮把所有域名都打一遍）和引擎的
// `exhausted` 事件（真实流量里整个池子都失败了 —— 这是最可信的信号）。

import { curateDomain, pickAlive } from './curator.mjs';
import { verifyAll, verifyDomain, isBadResult } from './verify.mjs';

const REPAIR_COOLDOWN_MS = 90_000;   // 同一域名两次自动修复之间的最短间隔
const VERIFY_SAMPLE = 3;             // 每轮巡检抽查的域名数（滚动覆盖全部）

/**
 * 换节点时的池子下限保护。
 *
 * 实测教训（store.steampowered.com）：`probeNode` 只证明「TCP + TLS 握手能成」，
 * 而握手成功**不代表完整 GET 拿得到响应**。一次策展只活下来 1 个 IP 时，如果直接
 * 用它替换整个池子，就会出现「池子从 5 条缩到 1 条、复验反而更差」。
 * 所以：存活数不足 `min` 时，把**原有候选并回来**（新增的优先生效、按 IP 去重），
 * 最多 `keep` 条 —— 宁可留几条没验证过的旧候选，也不要让池子塌成一条。
 *
 * @param {{ip:string,sni:string,sniValue?:string}[]} alive 本次策展的存活候选（已按耗时升序）
 * @param {{ip:string,sni:string,sniValue?:string}[]} previous 原池子
 */
export function mergeKeepPrevious(alive, previous = [], { min = 2, keep = 6 } = {}) {
  if (alive.length >= min) return alive.slice(0, keep);
  const seen = new Set(alive.map((n) => `${n.ip}|${n.sni}`));
  const out = [...alive];
  for (const n of previous) {
    if (out.length >= keep) break;
    const k = `${n.ip}|${n.sni}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ ip: n.ip, sni: n.sni, ...(n.sniValue ? { sniValue: n.sniValue } : {}) });
  }
  return out;
}

export class SmartController {
  /**
   * @param {{acc: any, log: (level: string, msg: string) => void}} deps
   */
  constructor(deps) {
    this.acc = deps.acc;
    this.log = deps.log ?? (() => {});
    this.timer = null;
    this.cursor = 0;
    this.rounds = 0;
    this.verifying = false;
    /** @type {Map<string, Promise<any>>} */
    this.inflight = new Map();
    /** @type {Map<string, number>} */
    this.cooldown = new Map();
    this.lastVerify = null;
    this.lastRepair = null;
    this.lastTick = null;
  }

  get cfg() { return this.acc?.config ?? {}; }
  get enabled() { return this.cfg.smart !== false; }
  get verifyOpts() {
    return {
      listenHost: this.cfg.listenHost ?? '127.0.0.2',
      listenPort: this.cfg.listenPort ?? 443,
      caPem: this.acc?.authority?.certPem,
    };
  }

  start() {
    if (this.timer) return;
    const minutes = Math.max(2, Number(this.cfg.smartIntervalMin ?? 15));
    this.timer = setInterval(() => { this.tick('interval').catch(() => {}); }, minutes * 60_000);
    this.timer.unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** 域名 → 池子里的模式键（用于判断一个 host 是不是我们管的域名）。 */
  patternFor(host) {
    const keys = Object.keys(this.acc?.nodes ?? {});
    for (const k of keys) {
      if (k === host) return k;
      if (k.startsWith('*.') && host.endsWith(k.slice(1)) && host !== k.slice(2)) return k;
    }
    return null;
  }

  /**
   * 经代理验证一批域名，并把结果反馈给健康表。
   * @param {string[]} [domains]
   */
  async verify(domains) {
    if (!this.acc?.engine?.listening || !this.acc?.authority?.certPem) return [];
    const list = (Array.isArray(domains) && domains.length ? domains : this.acc.managedDomains())
      .filter((d) => typeof d === 'string' && d && !d.includes('*'));
    if (list.length === 0) return [];
    this.verifying = true;
    try {
      const results = await verifyAll(list, this.verifyOpts, { concurrency: 4 });
      for (const r of results) {
        const h = this.acc.engine.health;
        if (isBadResult(r)) h.noteHostFailure(r.domain, r.error ?? (typeof r.status === 'number' ? `http ${r.status}` : r.note));
        else h.noteHostOk(r.domain);
      }
      this.lastVerify = {
        at: Date.now(),
        domains: list.length,
        ok: results.filter((r) => !isBadResult(r)).length,
        bad: results.filter(isBadResult).map((r) => r.domain),
        results,
      };
      this.acc.lastVerify = this.lastVerify;
      return results;
    } finally {
      this.verifying = false;
    }
  }

  /**
   * 修一个域名：重新测活（含 DoH 补候选，两种 SNI 策略）→ 写回池子 → 再验一次。
   * @param {string} domain
   * @param {{addDoh?: boolean, keep?: number, force?: boolean}} [opts]
   */
  async repair(domain, opts = {}) {
    const key = this.patternFor(domain) ?? domain;
    if (this.inflight.has(key)) return { domain: key, skipped: 'inflight' };
    const since = Date.now() - (this.cooldown.get(key) ?? 0);
    if (!opts.force && since < REPAIR_COOLDOWN_MS) {
      return { domain: key, skipped: `cooldown ${Math.round((REPAIR_COOLDOWN_MS - since) / 1000)}s` };
    }
    this.cooldown.set(key, Date.now());

    const task = (async () => {
      const nodes = this.acc.readonlyNodes();
      const before = nodes[key] ?? [];
      const results = await curateDomain(key, before, this.cfg.upstream, {
        addDoh: opts.addDoh !== false,
        dohLimit: opts.dohLimit ?? 8,   // DoH 全部候选都要试：只试 3 个时可能正好全是死的
        dohSni: ['real', 'none'],   // ★ 不试 none 的话 Akamai/CloudFront 系永远补不进来
      });
      const alive = pickAlive(results, opts.keep ?? 6);
      let changed = false;
      if (alive.length > 0) {
        const next = this.acc.readonlyNodes();
        // 存活太少时把旧候选并回来：禁止把池子缩成一条（见 mergeKeepPrevious 的实测教训）
        next[key] = mergeKeepPrevious(alive, before, { min: opts.minKeep ?? 2, keep: opts.keep ?? 6 });
        changed = JSON.stringify(next[key]) !== JSON.stringify(before);
        if (changed) await this.acc.replaceNodes(next);
      }
      const [after] = await this.verify([key]);
      const report = {
        domain: key,
        at: Date.now(),
        probed: results.length,
        alive: alive.length,
        dead: results.filter((r) => !r.ok).length,
        changed,
        bestMs: alive.length ? Math.min(...results.filter((r) => r.ok).map((r) => r.ms)) : null,
        verify: after ?? null,
        healed: after ? !isBadResult(after) : false,
      };
      this.lastRepair = report;
      this.acc.lastRepair = report;
      this.log(report.healed ? 'info' : 'warn',
        report.healed
          ? `智能修复：${key} → 换到 ${alive[0]?.ip ?? '?'}（${report.bestMs ?? '?'}ms），验证通过`
          : `智能修复：${key} 仍然不通（存活 ${alive.length}/${results.length}）`);
      return report;
    })();

    this.inflight.set(key, task);
    try {
      return await task;
    } finally {
      this.inflight.delete(key);
    }
  }

  /** 定时巡检：未健康域名优先，外加滚动抽查。 */
  async tick(reason = 'interval') {
    if (!this.enabled) return { skipped: 'smart disabled' };
    if (!this.acc?.engine?.listening) return { skipped: 'engine not listening' };

    const managed = this.acc.managedDomains().filter((d) => !d.includes('*'));
    if (managed.length === 0) return { skipped: 'no managed domain' };

    const unhealthy = this.acc.engine.health
      .unhealthyHosts({ minFailures: 1 })
      .map((h) => this.patternFor(h.host) ?? h.host)
      .filter((d) => managed.includes(d));

    const sample = [];
    for (let i = 0; i < VERIFY_SAMPLE && managed.length > 0; i += 1) {
      sample.push(managed[(this.cursor + i) % managed.length]);
    }
    this.cursor = (this.cursor + VERIFY_SAMPLE) % Math.max(1, managed.length);

    const targets = [...new Set([...unhealthy, ...sample])];
    if (targets.length === 0) return { skipped: 'no target' };

    this.rounds += 1;
    const results = await this.verify(targets);
    const bad = results.filter(isBadResult).map((r) => r.domain);
    const repairs = [];
    for (const d of bad) repairs.push(await this.repair(d, { addDoh: true }));

    const summary = {
      reason,
      at: Date.now(),
      verified: results.length,
      ok: results.length - bad.length,
      bad,
      repaired: repairs.filter((r) => r.healed).map((r) => r.domain),
      failed: repairs.filter((r) => !r.healed && !r.skipped).map((r) => r.domain),
    };
    this.lastTick = summary;
    if (bad.length > 0) {
      this.log('warn', `智能巡检(${reason})：验 ${results.length} 个，异常 ${bad.length} 个 [${bad.join(', ')}]`
        + (summary.repaired.length ? `，已修复 ${summary.repaired.join(', ')}` : ''));
    }
    return summary;
  }

  snapshot() {
    return {
      enabled: this.enabled,
      intervalMin: Math.max(2, Number(this.cfg.smartIntervalMin ?? 15)),
      rounds: this.rounds,
      inflight: [...this.inflight.keys()],
      lastTick: this.lastTick,
      lastVerify: this.lastVerify,
      lastRepair: this.lastRepair,
    };
  }
}

export { verifyDomain, isBadResult };
