// 引擎自检：真的起监听、真的用我们的 CA 做客户端校验、真的走完整链路。
// 不碰 hosts、不装 CA 进系统存储 —— 只验证引擎本身能不能把请求送到真实上游。
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Accelerator } from './accelerator.mjs';
import { parseClientHello, parseConnect, matchDomain } from './sni.mjs';

let fail = 0;
const check = (name, cond, extra = '') => {
  const ok = !!cond;
  if (!ok) fail += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

// ── 纯函数单测 ──
check('matchDomain 精确', matchDomain('github.com', ['github.com']));
check('matchDomain 通配', matchDomain('api.github.com', ['*.github.com']));
check('matchDomain 通配不跨级', !matchDomain('github.com', ['*.github.com']));
check('matchDomain 不误伤', !matchDomain('notgithub.com', ['github.com']));
check('parseConnect 正常', parseConnect(Buffer.from('CONNECT github.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'))?.host === 'github.com');
check('parseConnect 无端口', parseConnect(Buffer.from('CONNECT github.com HTTP/1.1\r\n\r\n'))?.port === 443);
check('parseConnect 非 CONNECT', parseConnect(Buffer.from('GET / HTTP/1.1\r\n\r\n'))?.method === 'other');
check('parseClientHello 不完整时安全返回', parseClientHello(Buffer.alloc(3)).complete === false);

// ── 集成：起引擎 → 客户端用自造 CA 校验 → 拿到真实内容 ──
const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-acc-selftest-'));
const acc = new Accelerator({ dir: path.join(tmp, 'store'), logger: { info() {}, warn() {} } });
await acc.init();
await acc.updateConfig({ listenHost: '127.0.0.2', listenPort: 18443, installCaOnEnable: false });
await acc.engine.start();
check('引擎已监听', acc.engine.listening, `${acc.config.listenHost}:${acc.config.listenPort}`);

const caPem = acc.authority.certPem;

function fetchVia(host, pathName = '/', timeoutMs = 20000) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const raw = net.connect({ host: '127.0.0.2', port: 18443 });
    raw.on('error', (e) => resolve({ ok: false, why: 'tcp ' + e.code, ms: Date.now() - t0 }));
    raw.setTimeout(timeoutMs, () => { raw.destroy(); resolve({ ok: false, why: 'timeout', ms: timeoutMs }); });
    raw.on('connect', () => {
      const c = tls.connect({ socket: raw, servername: host, ca: caPem });
      c.on('error', (e) => resolve({ ok: false, why: 'tls ' + (e.code || e.message), ms: Date.now() - t0 }));
      c.on('secureConnect', () => {
        const auth = c.authorized;
        c.write(`GET ${pathName} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-acc-selftest\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
        let buf = Buffer.alloc(0);
        c.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        c.on('end', () => {
          const text = buf.toString('latin1');
          resolve({
            ok: true, authorized: auth,
            status: text.split('\r\n')[0] || 'empty',
            ms: Date.now() - t0, bytes: buf.length,
          });
        });
      });
    });
  });
}

const targets = [
  ['github.com', '/'],
  ['api.github.com', '/'],
  ['opencode.ai', '/'],
  ['openrouter.ai', '/'],
  ['steamcommunity.com', '/'],
];
const results = [];
for (const [host, p] of targets) {
  const r = await fetchVia(host, p);
  results.push({ host, ...r });
  console.log(`  ${host.padEnd(24)} ${r.ok ? `${String(r.status).padEnd(26)} ${String(r.ms).padStart(5)}ms ${String(r.bytes).padStart(7)}b authorized=${r.authorized}` : `FAIL ${r.why} ${r.ms}ms`}`);
}

check('客户端的 TLS 用我们的 CA 校验通过', results.some((r) => r.ok && r.authorized === true));
const okCount = results.filter((r) => r.ok && r.status.includes('200')).length;
check('至少 3 个目标真实拿到 200', okCount >= 3, `${okCount}/${results.length}`);
check('接管记录有内容', acc.decisions.length > 0, `${acc.decisions.length} 条`);

await acc.engine.stop();
await fs.rm(tmp, { recursive: true, force: true });

console.log(`\n${fail === 0 ? 'ALL PASS' : fail + ' FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
