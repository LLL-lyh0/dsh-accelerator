// 代理模式自检：真的起 HTTP 代理监听，真的走 CONNECT → 服务端 TLS 升级 → 节点竞速 → 真实内容。
//
// 三条必须证明的事（hosts 被别家加速器改成只读之后，这条路径是唯一还能接管流量的办法）：
//   1) 受管域名经 `CONNECT` 会被 MITM，且客户端用我们的 CA 能验过（authorized=true）。
//   2) 非受管域名经 `CONNECT` 是**盲隧道**（客户端看到的上游证书不是我们的 —— 没被解密）。
//   3) `GET /proxy.pac` 返回可用的 PAC，且只把受管域名指向本机。
//
// 不碰 hosts、不装 CA 进系统存储、不改注册表。

import tls from 'node:tls';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Accelerator } from './accelerator.mjs';
import { buildPac, pacRules, parseRegistryQuery, pacUrlFor } from './system-proxy.mjs';
import { parseRequestLine, stripHopByHop } from './proxy.mjs';

let fail = 0;
const check = (name, cond, extra = '') => {
  const ok = !!cond;
  if (!ok) fail += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

// ── 1. 纯函数（不联网） ──
{
  const rules = pacRules(['github.com', '*.githubusercontent.com', 'github.com', ' *.GitHub.com ']);
  check('pacRules 精确去重且小写', JSON.stringify(rules.exact) === '["github.com"]', JSON.stringify(rules.exact));
  // 带空格的 `*.GitHub.com` 会被归一成后缀 —— 用户手写 nodes.json 时很常见，不能漏。
  check('pacRules 通配转后缀并归一化空白/大小写',
    JSON.stringify(rules.suffixes) === '[".github.com",".githubusercontent.com"]', JSON.stringify(rules.suffixes));

  const pac = buildPac(['github.com', '*.githubusercontent.com'], '127.0.0.2', 8843);
  check('PAC 含 FindProxyForURL', pac.includes('function FindProxyForURL'));
  check('PAC 指向本机代理', pac.includes('PROXY 127.0.0.2:8843; DIRECT'));
  check('PAC 同时列出精确域名与后缀', pac.includes('"github.com"') && pac.includes('".githubusercontent.com"'));
  check('0.0.0.0 会被改写成回环地址', buildPac(['a.com'], '0.0.0.0', 8843).includes('PROXY 127.0.0.1:8843'));
  check('pacUrlFor 拼出代理自己的路径', pacUrlFor('127.0.0.2', 8843) === 'http://127.0.0.2:8843/proxy.pac');

  const reg = parseRegistryQuery([
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
    '    ProxyEnable    REG_DWORD    0x1',
    '    ProxyServer    REG_SZ    127.0.0.1:10808',
    '    AutoConfigURL    REG_SZ    ',
    '    ProxyOverride    REG_SZ    <local>',
  ].join('\r\n'));
  check('解析 REG_DWORD 十六进制', reg.ProxyEnable?.value === 1, JSON.stringify(reg.ProxyEnable));
  check('解析 REG_SZ', reg.ProxyServer?.value === '127.0.0.1:10808');
  check('空的 REG_SZ 视为没设（否则还原时会写回一个空值）', reg.AutoConfigURL === undefined);
  check('正则不会把 key 路径行当值', !reg.HKEY_CURRENT_USER);

  const cleaned = stripHopByHop('GET http://a.com/ HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: a.com\r\nProxy-Authorization: Basic x');
  check('剥离 Proxy-Connection', !cleaned.includes('Proxy-Connection'));
  check('剥离 Proxy-Authorization', !cleaned.includes('Proxy-Authorization'));
  check('保留 Host 与请求行', cleaned.includes('Host: a.com') && cleaned.startsWith('GET http://a.com/ HTTP/1.1'));
  check('解析请求行（绝对形式）', parseRequestLine('GET http://a.com/x HTTP/1.1\r\nHost: a')?.target === 'http://a.com/x');
  check('解析请求行（CONNECT）', parseRequestLine('CONNECT a.com:443 HTTP/1.1')?.method === 'CONNECT');
  check('坏请求行返回 null', parseRequestLine('GARBAGE') === null);
}

// ── 2. 起引擎 + 代理监听 ──
const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-acc-proxy-'));
const acc = new Accelerator({ dir: path.join(tmp, 'store'), logger: { info() {}, warn() {} } });
await acc.init();
// enabled:false 是刻意的：updateConfig 在 enabled 且接管方式变化时会真的去改系统代理，
// 自检绝不能碰注册表。这里改成直接手工起监听。
await acc.updateConfig({
  enabled: false, takeover: 'hosts',
  listenHost: '127.0.0.2', listenPort: 18444, installCaOnEnable: false,
  proxyHost: '127.0.0.2', proxyPort: 18843,
});
await acc.engine.start();
await acc.engine.startProxy();
check('TLS 监听已起', acc.engine.listening, `${acc.config.listenHost}:${acc.config.listenPort}`);
check('代理监听已起', acc.engine.proxyListening, `${acc.config.proxyHost}:${acc.config.proxyPort}`);

const caPem = acc.authority.certPem;

/** 经代理 CONNECT 到 host:port，再做 TLS（ca 给我们的 CA 就能验 MITM；给 undefined 则不验）。 */
function connectViaProxy(host, port = 443, { ca, servername, timeoutMs = 25000 } = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const req = http.request({
      host: '127.0.0.2', port: 18843, method: 'CONNECT', path: `${host}:${port}`, agent: false,
      headers: { Host: `${host}:${port}` },
    });
    req.on('error', (e) => resolve({ ok: false, why: 'proxy ' + (e.code || e.message), ms: Date.now() - t0 }));
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); resolve({ ok: false, why: 'HTTP ' + res.statusCode }); return; }
      const c = tls.connect({
        socket,
        servername: servername ?? host,
        ...(ca ? { ca } : { rejectUnauthorized: false }),
      });
      const done = (r) => { c.destroy(); resolve({ ...r, ms: Date.now() - t0 }); };
      c.on('error', (e) => done({ ok: false, why: 'tls ' + (e.code || e.message) }));
      c.on('secureConnect', () => {
        const info = { authorized: c.authorized, peerCN: c.getPeerCertificate()?.subject?.CN ?? null };
        c.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-acc-proxy-selftest\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
        let buf = Buffer.alloc(0);
        c.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        c.on('end', () => done({
          ...info, ok: true,
          status: buf.toString('latin1').split('\r\n')[0] || 'empty',
          bytes: buf.length,
        }));
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ ok: false, why: 'timeout', ms: timeoutMs }); });
    req.end();
  });
}

// 2a) 受管域名 → MITM，客户端用自造 CA 能验过
const gh = await connectViaProxy('github.com', 443, { ca: caPem });
check('受管域名经代理被 MITM 且 CA 校验通过', gh.ok && gh.authorized === true, JSON.stringify(gh));

// 2b) 非受管域名 → 盲隧道。
// 必须用**独立进程**客户端：同进程时 decide() 的「自检通路放行」（pid === process.pid）会把它
// 当成受管连接走 MITM，于是永远测不出盲隧道。真实用户程序也都是独立进程。
const CHILD = fileURLToPath(new URL('../test/proxy-client-child.mjs', import.meta.url));
function runChild(target) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CHILD, '18843', target], { timeout: 60000, windowsHide: true }, (err, stdout) => {
      const text = String(stdout || '').trim().split('\n').pop() || '';
      if (text === '') { resolve({ ok: false, why: err ? String(err.message || err) : 'no output' }); return; }
      try { resolve(JSON.parse(text)); } catch { resolve({ ok: false, why: 'bad json: ' + text.slice(0, 120) }); }
    });
  });
}
const bdTries = [];
let bd = null;
for (const target of ['www.baidu.com', 'www.bing.com', 'www.qq.com']) {
  const r = await runChild(target);
  bdTries.push({ target, ...r });
  if (r.ok === true && typeof r.peerCN === 'string' && !String(r.peerCN).includes('DSH')) { bd = r; break; }
}
check('非受管域名是盲隧道（独立进程客户端，未 MITM）', bd !== null, JSON.stringify(bd ?? bdTries));

// 2c) PAC 端点
const pac = await new Promise((resolve) => {
  http.get({ host: '127.0.0.2', port: 18843, path: '/proxy.pac' }, (res) => {
    let body = '';
    res.setEncoding('utf8');
    res.on('data', (d) => { body += d; });
    res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], body }));
  }).on('error', (e) => resolve({ status: 0, body: String(e.message) }));
});
check('PAC 返回 200', pac.status === 200, String(pac.status));
check('PAC Content-Type 正确', String(pac.type).includes('proxy-autoconfig'), String(pac.type));
check('PAC 内容是脚本且列出受管域名', pac.body.includes('FindProxyForURL') && pac.body.includes('github.com'));

// 2d) 未知路径 → 明确的错误，而不是静静挂着
const bad = await new Promise((resolve) => {
  http.get({ host: '127.0.0.2', port: 18843, path: '/nope' }, (res) => {
    res.resume();
    resolve(res.statusCode);
  }).on('error', () => resolve(0));
});
check('未知路径回 404', bad === 404, String(bad));

console.log(`\n${fail === 0 ? 'ALL PASS' : fail + ' FAILED'}`);
await acc.engine.stop();
await fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
process.exit(fail === 0 ? 0 : 1);
