// 对**正在运行**的引擎做端到端验证（不启动新引擎、不改 hosts、不装证书）。
//
// 用途：调整 `lib/verify.mjs` 的等待策略后，不用重启 DSH 也能立刻看真实结果 ——
// 直接拿 storages 里的 CA 当信任锚，按节点池里的域名逐个打 127.0.0.2:<port>。
//
//   node test/live-verify.mjs [host:port] [域名域名…]
//
// 期望：每个域名都给出 HTTP 状态码；`handshake-only` 表示 20s 内没等到响应头（上游慢或不通）。

import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { verifyAll, isBadResult } from '../lib/verify.mjs';

const STORE = join(homedir(), '.dsh', 'storages', 'dsh-accelerator');
const [target = '127.0.0.2:443', ...rest] = process.argv.slice(2);
const [listenHost, listenPortRaw] = target.split(':');
const listenPort = Number(listenPortRaw || 443);

const caPem = await readFile(join(STORE, 'ca.pem'), 'utf8');
const nodes = JSON.parse(await readFile(join(STORE, 'nodes.json'), 'utf8'));
const domains = rest.length > 0 ? rest : Object.keys(nodes).filter((d) => !d.includes('*'));

const listening = await new Promise((resolve) => {
  const s = net.connect({ host: listenHost, port: listenPort });
  s.setTimeout(1500);
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('timeout', () => { s.destroy(); resolve(false); });
  s.once('error', () => resolve(false));
});
if (!listening) {
  console.log(`SKIP 引擎没在 ${listenHost}:${listenPort} 监听（先启动加速再跑）`);
  process.exit(0);
}

console.log(`target ${listenHost}:${listenPort}  域名 ${domains.length} 个\n`);
const t0 = Date.now();
const results = await verifyAll(domains, { listenHost, listenPort, caPem }, { concurrency: 6 });
const bad = results.filter(isBadResult);

for (const r of results) {
  const tag = isBadResult(r) ? 'BAD ' : 'OK  ';
  const detail = typeof r.status === 'number' ? `HTTP ${r.status}`
    : r.note === 'handshake-only' ? '无响应(handshake-only)'
      : r.error ?? '-';
  console.log(`${tag} ${r.domain.padEnd(26)} ${detail.padEnd(24)} ${String(r.ms).padStart(6)}ms`);
}
console.log(`\n${results.length - bad.length}/${results.length} 通过，总耗时 ${Date.now() - t0}ms`);
process.exit(bad.length === 0 ? 0 : 1);
