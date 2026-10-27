// 检测验证：从本机**经过自己的代理**真的走一遍，而不是只检查「端口在听」。
//
// 为什么必须这样验：
//  - 端口在听 ≠ 域名能通。上游节点全挂时端口照样在听，用户看到的就是浏览器转圈。
//  - 这条路径同时覆盖了整条链：我们的叶证书（客户端用自造 CA 校验，rejectUnauthorized
//    为 true ⇒ 顺便证明 CA 装对了）、引擎的 SNI 判定、节点竞速、上游 TLS 握手、真实响应。
//  - 它还能验出「hosts 生效」之外的东西：即使 hosts 没写对，这里也直接打 127.0.0.2，
//    所以失败一定出在链路上，不会和 hosts 问题混在一起。
//
// 用 GET 而不是 HEAD：部分 CDN/防护对 HEAD 直接断连，会把「能通」误判成「不通」。

import tls from 'node:tls';

const VERIFY_TIMEOUT = 15_000;
// 握手成功后再等响应头的时长。
// ★ 为什么给这么长：TLS 握手是**和本机引擎**完成的（引擎要先读到 SNI 才能决定要不要接管），
// 所以 secureConnect 只证明「引擎活着」，完全不证明上游通 —— 真正的信号只有状态码。
// 实测（活体 /verify）：github.com 要 6~22s、store/api.steampowered.com 也常过 6s，
// 6s 会把「慢但能用」误判成不通，智能修复就会对好域名反复换节点。
const STATUS_WAIT_MS = 20_000;

/**
 * 经代理验证一个域名。
 * @param {string} domain
 * @param {{listenHost: string, listenPort: number, caPem: string, timeoutMs?: number, path?: string}} opts
 * @returns {Promise<{domain: string, ok: boolean, status?: number|null, ms: number, error?: string, cipher?: string|null, note?: string}>}
 */
export function verifyDomain(domain, opts) {
  const { listenHost, listenPort, caPem, timeoutMs = VERIFY_TIMEOUT, path = '/' } = opts;
  const t0 = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    let sock = null;
    let timer = null;
    const done = (r) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { sock?.destroy(); } catch { /* noop */ }
      resolve({ domain, ms: Date.now() - t0, ...r });
    };

    try {
      sock = tls.connect({
        host: listenHost,
        port: listenPort,
        servername: domain,
        ca: caPem,
        rejectUnauthorized: true,   // ★ 客户端侧真校验：CA 没装对/叶证书不对就会在这里失败
        ALPNProtocols: ['http/1.1'],
      });
    } catch (e) {
      resolve({ domain, ok: false, ms: Date.now() - t0, error: `connect:${e?.message ?? e}` });
      return;
    }

    timer = setTimeout(() => done({ ok: false, error: `timeout ${timeoutMs}ms` }), timeoutMs);

    sock.once('secureConnect', () => {
      const cipher = (() => { try { return sock.getCipher()?.name ?? null; } catch { return null; } })();
      sock.write(
        `GET ${path} HTTP/1.1\r\n`
        + `Host: ${domain}\r\n`
        + 'User-Agent: dsh-accelerator-verify/1.0\r\n'
        + 'Accept: */*\r\n'
        + 'Connection: close\r\n\r\n',
      );
      // 握手成功已经证明「客户端→引擎→上游」这条 TLS 通了；再给响应头一点时间：
      // 拿到状态码才能区分「真的转发出内容」和「通但上游是坏的」（实测 302 会回 502）。
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => done({ ok: true, status: null, cipher, note: 'handshake-only' }), STATUS_WAIT_MS);
    });

    let buf = '';
    sock.on('data', (chunk) => {
      if (settled) return;
      buf += chunk.toString('latin1');
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(buf);
      if (m) {
        let cipher = null;
        try { cipher = sock.getCipher()?.name ?? null; } catch { /* noop */ }
        done({ ok: true, status: Number(m[1]), cipher });
      }
    });
    sock.once('error', (e) => done({ ok: false, error: e?.code ? `${e.code}: ${e.message}` : String(e?.message ?? e) }));
    sock.once('close', () => done({ ok: false, error: 'closed before response' }));
  });
}

/** 一个验证结果算不算「这个域名其实不通」。握手通但 5xx / 没响应，都算需要修复。 */
export function isBadResult(r) {
  if (!r || r.ok !== true) return true;
  if (r.note === 'handshake-only') return true;
  if (typeof r.status === 'number' && r.status >= 500) return true;
  return false;
}

/**
 * 并发验证一组域名。
 * @param {string[]} domains
 * @param {{listenHost: string, listenPort: number, caPem: string, timeoutMs?: number}} opts
 * @param {{concurrency?: number, onResult?: (r: any) => void}} [run]
 * @returns {Promise<Array<any>>}
 */
export async function verifyAll(domains, opts, run = {}) {
  const list = Array.isArray(domains) ? domains.filter((d) => typeof d === 'string' && d && !d.includes('*')) : [];
  const concurrency = Math.max(1, Math.min(8, run.concurrency ?? 4));
  const out = new Array(list.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, list.length || 1) }, async () => {
    for (;;) {
      const i = cursor;
      cursor += 1;
      if (i >= list.length) return;
      const r = await verifyDomain(list[i], opts);
      out[i] = r;
      try { run.onResult?.(r); } catch { /* 回调里的错不该影响验证 */ }
    }
  });
  await Promise.all(workers);
  return out.filter(Boolean);
}
