// 节点健康度：把「哪条连接赢了」反馈回排序，让优选自己收敛。
//
// 这是「自配置」的另一半 —— 用户/AI 只给种子池，谁快谁慢由实际使用结果决定。
// 用 EWMA（指数加权移动平均）而不是「次数」：网络质量会变，旧成绩要能衰退。

const ALPHA = 0.3;      // EWMA 系数，越大越相信最近一次
const PENALTY_MS = 6000; // 一次失败的等效耗时

export class NodeHealth {
  constructor() {
    /** @type {Map<string, {ms: number, ok: number, fail: number}>} */
    this.map = new Map();
    /**
     * 域名级健康：**只有「这个域名的所有候选都失败」才算它不健康** ——
     * 单个节点挂掉是竞速的正常现象，不该触发修复。
     * @type {Map<string, {fail: number, lastFailAt: number, lastOkAt: number, reason: string|null}>}
     */
    this.hosts = new Map();
  }

  key(host, ip) { return `${host}|${ip}`; }

  record(host, ip, ok, ms) {
    const k = this.key(host, ip);
    const prev = this.map.get(k) ?? { ms: 2000, ok: 0, fail: 0 };
    const sample = ok ? (typeof ms === 'number' && ms > 0 ? ms : 1200) : PENALTY_MS;
    this.map.set(k, {
      ms: prev.ms * (1 - ALPHA) + sample * ALPHA,
      ok: prev.ok + (ok ? 1 : 0),
      fail: prev.fail + (ok ? 0 : 1),
    });
  }

  /** 域名整体成功：清掉它的失败计数（自愈后不再反复触发修复）。 */
  noteHostOk(host) {
    const h = this.hosts.get(host) ?? { fail: 0, lastFailAt: 0, lastOkAt: 0, reason: null };
    h.ok = (h.ok ?? 0) + 1;
    h.lastOkAt = Date.now();
    h.fail = 0;
    h.reason = null;
    this.hosts.set(host, h);
  }

  /** 域名整体失败（所有候选都挂 / 没有候选）。 */
  noteHostFailure(host, reason) {
    const h = this.hosts.get(host) ?? { fail: 0, lastFailAt: 0, lastOkAt: 0, ok: 0, reason: null };
    h.fail += 1;
    h.lastFailAt = Date.now();
    h.reason = reason ? String(reason).slice(0, 200) : null;
    this.hosts.set(host, h);
  }

  /** 待修复域名：失败次数够多、且最后一次是失败（成功过就自动出列）。 */
  unhealthyHosts({ minFailures = 1, withinMs = 3600_000 } = {}) {
    const now = Date.now();
    const out = [];
    for (const [host, h] of this.hosts) {
      if (h.fail < minFailures) continue;
      if (h.lastFailAt <= h.lastOkAt) continue;
      if (withinMs > 0 && now - h.lastFailAt > withinMs) continue;
      out.push({ host, ...h });
    }
    return out.sort((a, b) => b.fail - a.fail);
  }

  score(host, ip) {
    const s = this.map.get(this.key(host, ip));
    if (!s) return 2000;    // 没试过的排中间：既不会被无视，也不会压过已验证的好节点
    return s.ms;
  }

  /** 按历史表现排序候选（稳定的：同分保持原顺序）。 */
  sortCandidates(host, nodes) {
    return nodes
      .map((n, i) => ({ n, i, score: this.score(host, n.ip) }))
      .sort((a, b) => (a.score === b.score ? a.i - b.i : a.score - b.score))
      .map((x) => x.n);
  }

  snapshot() {
    const out = {};
    for (const [k, v] of this.map) {
      out[k] = { avgMs: Math.round(v.ms), ok: v.ok, fail: v.fail };
    }
    return out;
  }

  hostSnapshot() {
    const out = {};
    for (const [host, h] of this.hosts) {
      out[host] = { fail: h.fail, ok: h.ok ?? 0, lastFailAt: h.lastFailAt || null, lastOkAt: h.lastOkAt || null, reason: h.reason ?? null };
    }
    return out;
  }
}
