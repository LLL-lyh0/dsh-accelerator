// 「每域名上游覆盖 + 池子全挂回退上游」两条路径的端到端自检。
//
// 背景（itch.io 这类域名）：直连被 SNI 整段阻断 —— 同一台 Fastly 边缘，
// SNI=fastly.com/example.com 都能 301，SNI=itch.io 一律 RST ⇒ RST 跟着 SNI 走、
// 不跟着 IP 走，换任何 IP 都无解。唯一的真解是经一个外部 HTTP/SOCKS5 上游。
//
// 本自检用一个**本地最小 SOCKS5 服务器**当上游（测试范围内忽略请求的 target，
// 一律转发到本地目标 TLS 服务器），验证四种语义：
//   A) upstreams[host]（每域名覆盖）→ 完全经上游，不选 IP；
//   B) 全局 upstream + 池子全挂 → 自动回退上游（upstreamFallback 默认 true）；
//   C) 没配上游 + 池子全挂 → 必须失败（不能凭空造通路）；
//   D) upstreamFallback:false → 即使配了全局上游也不回退。

import net from 'node:net';
import tls from 'node:tls';
import { Engine } from '../lib/engine.mjs';
import { createAuthority, issueLeaf } from '../lib/certs.mjs';

let passed = 0;
let failed = 0;
function check(label, ok, detail = '') {
  if (ok) { passed += 1; console.log(`[PASS] ${label}${detail ? ` —— ${detail}` : ''}`); }
  else { failed += 1; console.log(`[FAIL] ${label}${detail ? ` —— ${detail}` : ''}`); }
}

/** 本地目标 TLS 服务器：对任何请求回 200（带 X-Upstream 标记，证明流真的经过了它）。 */
function startTargetTls(leaf) {
  return new Promise((resolve) => {
    const server = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (sock) => {
      let body = '';
      sock.on('data', (d) => {
        body += d.toString('latin1');
        if (body.includes('\r\n\r\n')) {
          sock.write('HTTP/1.1 200 OK\r\nX-Upstream: local-test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi');
          sock.end();
        }
      });
      sock.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

/** 本地最小 SOCKS5 上游：greeting → CONNECT（按名/按 IP 都认）→ 一律转发到本地目标。 */
function startFakeSocks5(targetPort) {
  return new Promise((resolve) => {
    let hits = 0;
    const server = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      let greetingDone = false;
      const ondata = (d) => {
        buf = Buffer.concat([buf, d]);
        // ── 阶段 0：greeting（VER NMETHODS METHODS…）——按 NMETHODS 消费整段，
        // 否则残留的第三个字节会污染下一帧的 VER 判定（实测：client 发 [05 01 00]，
        // 只消费 2 字节会让 CONNECT 前面多一个 [00]，被当成 ver=0 destroy）。
        if (!greetingDone) {
          if (buf.length < 2) return;
          const nmethods = buf[1];
          if (buf.length < 2 + nmethods) return;
          buf = buf.subarray(2 + nmethods);
          greetingDone = true;
          sock.write(Buffer.from([0x05, 0x00]));       // 无认证
        }
        // ── 阶段 1：CONNECT（VER CMD RSV ATYP DST.ADDR DST.PORT）──
        if (buf.length < 5) return;
        const ver = buf[0];
        const cmd = buf[1];
        const atyp = buf[3];
        if (ver !== 5 || cmd !== 1) { sock.destroy(); return; }
        let need = 0;
        if (atyp === 1) need = 10;                       // IPv4
        else if (atyp === 3) need = 5 + buf[4] + 2;      // 按名：5 + LEN + PORT
        else if (atyp === 4) need = 22;                  // IPv6
        else { sock.destroy(); return; }
        if (buf.length < need) return;
        buf = buf.subarray(need);
        sock.removeListener('data', ondata);
        hits += 1;
        const up = net.connect({ host: '127.0.0.1', port: targetPort });
        up.on('connect', () => {
          // 成功应答：VER REP RSV ATYP(1) BND.ADDR(4) BND.PORT(2)
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          sock.pipe(up);
          up.pipe(sock);
        });
        up.on('error', () => sock.destroy());
      };
      sock.on('data', ondata);
      sock.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, hits: () => hits }));
  });
}

/** 经引擎的 TLS 客户端：connect → GET / → 收首行。 */
function clientRequest(port, servername) {
  return new Promise((resolve) => {
    const s = tls.connect({
      host: '127.0.0.2', port, servername,
      rejectUnauthorized: false, ALPNProtocols: ['http/1.1'], timeout: 20000,
    }, () => {
      s.write(`GET / HTTP/1.1\r\nHost: ${servername}\r\nConnection: close\r\n\r\n`);
    });
    let body = '';
    s.on('data', (d) => { body += d.toString('latin1'); });
    s.on('end', () => resolve({ body }));
    s.on('error', (e) => resolve({ error: e.code || e.message }));
    s.on('timeout', () => { s.destroy(); resolve({ error: 'timeout' }); });
  });
}

const DEAD_IP = '192.0.2.1'; // TEST-NET-1，保证不可路由
const HOST = 'upstream-test.invalid';

// 目标服务器与引擎各用一张现签证书（客户端 rejectUnauthorized:false，不需要信任）
const targetLeaf = issueLeaf(createAuthority(30), [HOST], 30);
const { server: targetServer, port: targetPort } = await startTargetTls(targetLeaf);
const { server: socksServer, port: socksPort, hits } = await startFakeSocks5(targetPort);

const cfg = {
  enabled: true,
  listenHost: '127.0.0.2',
  listenPort: 0,           // 下面起引擎时随机
  takeover: 'hosts',       // 不碰系统代理
  installCaOnEnable: false,
  upstream: { mode: 'direct', host: '', port: 0, username: '', password: '' },
  upstreams: {},
  upstreamFallback: true,
  enforce: [],
  bypass: [],
  domainGroups: {},
};
const nodes = { [HOST]: [{ ip: DEAD_IP, sni: 'real' }] };
// secureContext 需要一张覆盖 HOST 的叶证书
const leaf = issueLeaf(createAuthority(30), [HOST], 30);
const engine = new Engine({
  getConfig: () => cfg,
  getNodes: () => nodes,
  getLeaf: () => leaf,       // secureContext / SNICallback 都用它
  getPac: () => '',
  getCrl: () => null,
});

// 引擎的 TLS 监听（直连入口）—— 换个非常用端口避免与活体冲突
const enginePort = 18901;
await new Promise((resolve, reject) => {
  engine.server = tls.createServer({
    cert: leaf.certPem,
    key: leaf.keyPem,
    SNICallback: (servername, cb) => cb(null, tls.createSecureContext({ cert: leaf.certPem, key: leaf.keyPem })),
  }, (socket) => engine.onConnection(socket));
  engine.server.on('tlsClientError', () => {});
  engine.server.once('error', reject);
  engine.server.listen(enginePort, '127.0.0.2', () => resolve());
});
check('引擎已监听 127.0.0.2:18901', engine.listening === true);
engine.on('decision', (d) => { if (process.env.DSH_ACC_DEBUG) console.log('  [decision]', JSON.stringify(d)); });
engine.on('exhausted', (d) => { if (process.env.DSH_ACC_DEBUG) console.log('  [exhausted]', JSON.stringify(d)); });

// ── A) 每域名上游覆盖：完全经上游，不选 IP ──
cfg.upstreams = { [HOST]: { mode: 'socks5', host: '127.0.0.1', port: socksPort } };
cfg.upstream = { mode: 'direct', host: '', port: 0 };
{
  const r = await clientRequest(enginePort, HOST);
  check('A) upstreams[host] 覆盖生效：经 SOCKS5 上游拿到 200',
    typeof r.body === 'string' && r.body.startsWith('HTTP/1.1 200'),
    `resp=${(r.body || r.error || '').split('\r\n')[0]}｜上游命中 ${hits()} 次`);
  check('A) 流真的经过了本地目标服务器（X-Upstream: local-test）',
    typeof r.body === 'string' && r.body.includes('X-Upstream: local-test'));
}

// ── B) 全局 upstream + 池子全挂 → 自动回退上游 ──
cfg.upstreams = {};
cfg.upstream = { mode: 'socks5', host: '127.0.0.1', port: socksPort };
cfg.upstreamFallback = true;
{
  const before = hits();
  const r = await clientRequest(enginePort, HOST);
  check('B) 池子全挂时回退到全局 upstream：拿到 200',
    typeof r.body === 'string' && r.body.startsWith('HTTP/1.1 200'),
    `resp=${(r.body || r.error || '').split('\r\n')[0]}｜上游新增 ${hits() - before} 次命中`);
}

// ── C) 没配上游 + 池子全挂 → 必须失败（不能凭空造通路） ──
cfg.upstream = { mode: 'direct', host: '', port: 0 };
{
  const r = await clientRequest(enginePort, HOST);
  // 引擎销毁连接后客户端走 'end'：要么空 body，要么非 200 —— 都算「没拿到内容」
  const body = typeof r.body === 'string' ? r.body : '';
  check('C) 无上游时直连池全挂 → 拿不到内容（不假成功）',
    !body.startsWith('HTTP/1.1 200'), `resp=${body.split('\r\n')[0] || '(空)'}｜error=${r.error || '-'}`);
}

// ── D) upstreamFallback:false → 即使配了全局上游也不回退 ──
cfg.upstream = { mode: 'socks5', host: '127.0.0.1', port: socksPort };
cfg.upstreamFallback = false;
{
  const before = hits();
  const r = await clientRequest(enginePort, HOST);
  const body = typeof r.body === 'string' ? r.body : '';
  check('D) upstreamFallback=false 时不再回退上游',
    !body.startsWith('HTTP/1.1 200'), `resp=${body.split('\r\n')[0] || '(空)'}｜error=${r.error || '-'}｜上游新增 ${hits() - before} 次命中（应为 0）`);
}

engine.server.close();
socksServer.close();
targetServer.close();

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
