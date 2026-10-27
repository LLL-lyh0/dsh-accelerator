// 节点策展器：测活 + DoH 补 IP。
//
// 「自配置」的第三条腿：外部 AI 不懂网络细节也能把池子维护好 ——
// 直接把 domain 丢给 curateDomain，它返回每个节点的实测结果，
// 调用方（管理页 / accelerator 工具）拿结果写回 nodes.json。

import net from 'node:net';
import tls from 'node:tls';
import { resolveA } from './dns-and-pid.mjs';

const TCP_TIMEOUT = 5000;
const TLS_TIMEOUT = 7000;

/**
 * 单个节点测活：TCP 连通 + TLS 握手。
 * @param {{ip: string, sni?: string, sniValue?: string}} node
 * @param {string} host 目标域名（用于真 SNI / CDN 名替换）
 */
export function probeNode(node, host) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const strategy = node.sni ?? 'real';
    const servername = strategy === 'real' ? host : strategy === 'cdn' ? (node.sniValue ?? host) : undefined;

    const sock = net.connect({ host: node.ip, port: 443, timeout: TCP_TIMEOUT });
    let settled = false;
    const finish = (ok, why) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* noop */ }
      resolve({ ip: node.ip, sni: strategy, ...(node.sniValue ? { sniValue: node.sniValue } : {}), ok, ms: Date.now() - t0, ...(why ? { why } : {}) });
    };
    sock.on('error', (e) => finish(false, `tcp:${e.code}`));
    sock.on('timeout', () => finish(false, 'tcp:timeout'));
    sock.on('connect', () => {
      sock.setTimeout(TLS_TIMEOUT);
      const t = tls.connect({ socket: sock, servername, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
      t.on('error', (e) => finish(false, `tls:${e.code || e.message}`));
      t.on('timeout', () => finish(false, 'tls:timeout'));
      t.on('secureConnect', () => {
        let cn = null;
        try { cn = t.getPeerCertificate()?.subject?.CN ?? null; } catch { /* noop */ }
        finish(true);
        t._peerCn = cn;
      });
      sock.setTimeout(0);
    });
  });
}

/**
 * 一个域名的完整策展：现有节点全部测一遍；addDoh 时再用 DoH 解析补充候选。
 * @param {string} domain
 * @param {Array<{ip: string, sni?: string, sniValue?: string}>} nodes
 * @param {{mode?: string, host?: string, port?: number}} [_upstream] 暂未用（节点测活总走直连；上游模式由引擎在真实流量里生效）
 * @param {{addDoh?: boolean, dohLimit?: number, dohSni?: string[]}} [opts]
 *   dohLimit：DoH 解析出来的 IP 最多补几个进测活（默认 8）。**不要调小** ——
 *   实测 `api.steampowered.com` 的 DoH 结果有 10 个地址，其中只有 7 个能服务；
 *   曾经把这里写成 3，结果「补」进来的 3 个正好全是死的，修复报告成「存活 2/11」。
 *   dohSni：新解析出来的 IP 用哪些 SNI 策略去试。默认只试 real —— 但 Akamai/
 *   CloudFront 系（steamcommunity、huggingface）发真 SNI 必被 RST，所以要靠
 *   智能修复传 ['real','none']，否则 DoH 补进来的节点会「全都不可用」。
 */
export async function curateDomain(domain, nodes, _upstream, opts = {}) {
  const tasks = (nodes ?? []).map((n) => probeNode(n, domain));
  if (opts.addDoh) {
    const ips = await resolveA(domain).catch(() => []);
    const known = new Set((nodes ?? []).map((n) => n.ip));
    const limit = opts.dohLimit ?? 8;
    const strategies = Array.isArray(opts.dohSni) && opts.dohSni.length ? opts.dohSni : ['real'];
    let added = 0;
    for (const ip of ips) {
      if (added >= limit) break;
      if (known.has(ip)) continue;
      for (const sni of strategies) tasks.push(probeNode({ ip, sni }, domain));
      added += 1;
    }
  }
  return Promise.all(tasks);
}

/** 把测活结果收敛成可写回 nodes.json 的池子（只留活的、按延迟排序、最多 keep 条）。 */
export function pickAlive(results, keep = 6) {
  const seen = new Set();
  return results
    .filter((r) => r.ok)
    .sort((a, b) => a.ms - b.ms)
    .filter((r) => (seen.has(r.ip) ? false : (seen.add(r.ip), true)))
    .slice(0, keep)
    .map((r) => ({ ip: r.ip, sni: r.sni, ...(r.sni === 'cdn' && r.sniValue ? { sniValue: r.sniValue } : {}) }));
}
