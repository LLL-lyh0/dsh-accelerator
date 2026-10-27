// A/B 对照：同一个域名，「直连最优 IP」 vs 「经本机加速器」。
//
// 为什么需要它：`live-verify.mjs` 只能证明「经加速器能拿到 HTTP 状态码」，
// 不能回答用户真正关心的那句「**加速器到底有没有用**」。
// 这里两侧用同一套 HTTP 请求（GET / + Connection: close），只换通路：
//   直连   —— DoH 解析出 IP 后**按 IP 直连**（绕开 hosts），真 SNI，多个 IP 竞速取最快；
//   加速器 —— 连 127.0.0.2:443（hosts 把我们指到这里），用插件的 CA 校验，tls 里带真 SNI。
// 判读：
//   直连全挂 + 加速器通        → 「不可达 → 可用」（这是加速器的核心价值）
//   两边都通，加速器更快       → 「快 N 倍」
//   两边都通，加速器更慢       → 「慢 N 倍」（诚实地报出来，慢不该说成有效）
//
// 用法：node test/live-ab.mjs [域名…]
// 退出码：加速器侧全部可用 → 0；有任何受管域名经加速器失败 → 1。

import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { resolveA } from '../lib/dns-and-pid.mjs';

const STORAGE = path.join(os.homedir(), '.dsh', 'storages', 'dsh-accelerator');
const ACCEL = { host: '127.0.0.2', port: 443 };

const DEFAULT_TARGETS = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'steamcommunity.com',
  'store.steampowered.com',
  'api.steampowered.com',
  'huggingface.co',
  'opencode.ai',
  'openrouter.ai',
];

const TIMEOUT_MS = Number(process.env.AB_TIMEOUT_MS || 9000);
const MAX_IPS = Number(process.env.AB_MAX_IPS || 6);

function firstLine(buf) {
  return buf.toString('latin1').split('\r\n')[0] || 'empty';
}

/** 连某个 IP 上的 443，用真 SNI 完成 TLS 后发一次 GET /。 */
function probeIp(ip, host, timeoutMs = TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    const fin = (r) => {
      if (done) return;
      done = true;
      resolve({ ...r, ip, ms: Date.now() - t0 });
    };
    const sock = net.connect({ host: ip, port: 443 });
    sock.setTimeout(timeoutMs, () => { try { sock.destroy(); } catch { /* 忽略 */ } fin({ ok: false, why: 'tcp:timeout' }); });
    sock.on('error', (e) => fin({ ok: false, why: `tcp:${e.code || e.message}` }));
    sock.on('connect', () => {
      // 交付给 tls.connect 之后**绝不能再 destroy 这个 raw socket**（会让 Node 段错误）。
      sock.setTimeout(0);
      const c = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
      let cdone = false;
      const cfin = (r) => {
        if (cdone) return;
        cdone = true;
        try { c.destroy(); } catch { /* 忽略 */ }
        fin(r);
      };
      c.setTimeout(timeoutMs, () => cfin({ ok: false, why: 'tls:timeout' }));
      c.on('error', (e) => cfin({ ok: false, why: `tls:${e.code || e.message}` }));
      c.on('secureConnect', () => {
        c.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-acc-ab\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
        let buf = Buffer.alloc(0);
        c.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        c.on('end', () => cfin({ ok: true, status: firstLine(buf), bytes: buf.length, peerCN: c.getPeerCertificate()?.subject?.CN ?? null }));
      });
    });
  });
}

/** 经本机加速器（hosts 把我们指到 127.0.0.2:443），用插件 CA **严格校验**。 */
function probeViaAccel(host, caPem, timeoutMs = TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    const fin = (r) => {
      if (done) return;
      done = true;
      resolve({ ...r, ms: Date.now() - t0 });
    };
    const c = tls.connect({
      host: ACCEL.host, port: ACCEL.port, servername: host,
      ca: caPem, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'],
    });
    c.setTimeout(timeoutMs, () => { try { c.destroy(); } catch { /* 忽略 */ } fin({ ok: false, why: 'tls:timeout' }); });
    c.on('error', (e) => fin({ ok: false, why: `tls:${e.code || e.message}` }));
    c.on('secureConnect', () => {
      c.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-acc-ab\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
      let buf = Buffer.alloc(0);
      c.on('data', (d) => { buf = Buffer.concat([buf, d]); });
      c.on('end', () => fin({
        ok: true,
        status: firstLine(buf),
        bytes: buf.length,
        peerCN: c.getPeerCertificate()?.subject?.CN ?? null,
        authorized: c.authorized === true,
      }));
    });
  });
}

/** 直接（不经加速器）取「最快的那个 IP」：多 IP 并发，谁先成功用谁。 */
async function bestDirect(host) {
  const ips = await resolveA(host).catch(() => []);
  const list = ips.slice(0, MAX_IPS);
  if (list.length === 0) return { ok: false, why: 'DoH 没解析出 IP', tried: 0, results: [] };
  const settled = await Promise.all(list.map((ip) => probeIp(ip, host)));
  const okOnes = settled.filter((r) => r.ok).sort((a, b) => a.ms - b.ms);
  return {
    ok: okOnes.length > 0,
    best: okOnes[0],
    tried: list.length,
    alive: okOnes.length,
    why: okOnes.length ? undefined : (settled[0]?.why ?? 'unknown'),
    results: settled,
  };
}

const targets = process.argv.length > 2 ? process.argv.slice(2) : DEFAULT_TARGETS;
const caPem = await fs.readFile(path.join(STORAGE, 'ca.pem'), 'utf8');

console.log(`加速器入口 ${ACCEL.host}:${ACCEL.port} ｜ 直连对照 = DoH 解析后按 IP 直连（最多 ${MAX_IPS} 个，单次 ${TIMEOUT_MS}ms）\n`);
console.log('域名'.padEnd(26) + '直连最优'.padEnd(30) + '经加速器'.padEnd(30) + '结论');
console.log('-'.repeat(118));

const rows = [];
for (const host of targets) {
  const [direct, accel] = await Promise.all([
    bestDirect(host),
    probeViaAccel(host, caPem),
  ]);
  const dTxt = direct.ok
    ? `${direct.best.status.replace('HTTP/1.1 ', '')} ${direct.best.ms}ms (${direct.alive}/${direct.tried} IP)`
    : `全失败 (${direct.tried} IP: ${direct.why})`;
  const aTxt = accel.ok
    ? `${accel.status.replace('HTTP/1.1 ', '')} ${accel.ms}ms [${accel.peerCN}]`
    : `失败 (${accel.why})`;

  let verdict;
  if (accel.ok && !direct.ok) verdict = '✅ 不可达 → 可用';
  else if (accel.ok && direct.ok) {
    const ratio = direct.best.ms / accel.ms;
    verdict = ratio >= 1.15 ? `✅ 快 ${ratio.toFixed(2)}×` : ratio <= 0.87 ? `⚠️ 慢 ${(1 / ratio).toFixed(2)}×` : '≈ 持平';
  } else verdict = '❌ 经加速器也不通';

  rows.push({ host, direct, accel, verdict });
  console.log(host.padEnd(26) + dTxt.padEnd(30) + aTxt.padEnd(30) + verdict);
}

const bad = rows.filter((r) => !r.accel.ok);
const mitm = rows.filter((r) => r.accel.ok && String(r.accel.peerCN).includes('DSH'));
const directDead = rows.filter((r) => !r.direct.ok && r.accel.ok);

console.log('');
console.log(`经加速器可用：${rows.length - bad.length}/${rows.length}`
  + ` ｜ 被本机 MITM（看到的是插件叶证书）：${mitm.length}/${rows.length - bad.length}`
  + ` ｜ 直连不可达但加速器可用：${directDead.length}`);
if (bad.length) console.log(`经加速器失败：${bad.map((r) => `${r.host}(${r.accel.why})`).join(', ')}`);
if (mitm.length !== rows.length - bad.length) console.log('⚠ 有域名经加速器通了但证书不是插件叶证书 —— 说明没被本机接管。');

process.exit(bad.length === 0 ? 0 : 1);
