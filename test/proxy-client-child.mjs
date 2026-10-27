// 代理自检用的「真实外部客户端」：**独立进程**，这样才能走通按进程粒度判定。
//
// 为什么必须独立进程：engine.decide() 有一条「自己进程发的连接永远放行」的规则（自检通路），
// 在同一个进程里连代理，永远会被当成受管连接 —— 测不出「非受管域名走盲隧道」。
//
// 用法：node test/proxy-client-child.mjs <proxyPort> <host> [servername] [caFile]
//   caFile 给了就用它当信任锚（rejectUnauthorized:true）—— 这是「证书链真的对」的硬证据；
//   不给就用系统信任库（rejectUnauthorized:false，authorized 字段仍反映系统库能不能验过）。
// 输出：一行 JSON {ok, peerCN, peerIssuer, authorized, status, bytes, why}

import tls from 'node:tls';
import http from 'node:http';
import fs from 'node:fs';

const [, , proxyPortArg, host, servernameArg, caFileArg] = process.argv;
const proxyPort = Number(proxyPortArg);
const servername = servernameArg ?? host;

function run() {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const done = (r) => resolve({ ...r, ms: Date.now() - t0 });
    const req = http.request({
      host: '127.0.0.2', port: proxyPort, method: 'CONNECT', path: `${host}:443`, agent: false,
      headers: { Host: `${host}:443` },
    });
    req.on('error', (e) => done({ ok: false, why: 'proxy ' + (e.code || e.message) }));
    req.setTimeout(20000, () => { req.destroy(); done({ ok: false, why: 'proxy timeout' }); });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); done({ ok: false, why: 'HTTP ' + res.statusCode }); return; }
      const tlsOpts = { socket, servername };
      if (caFileArg) {
        tlsOpts.ca = fs.readFileSync(caFileArg);
        tlsOpts.rejectUnauthorized = true;
      } else {
        tlsOpts.rejectUnauthorized = false;
      }
      const c = tls.connect(tlsOpts);
      const finish = (r) => { c.destroy(); done(r); };
      c.setTimeout(20000, () => finish({ ok: false, why: 'tls timeout' }));
      c.on('error', (e) => finish({ ok: false, why: 'tls ' + (e.code || e.message) }));
      c.on('secureConnect', () => {
        const cert = c.getPeerCertificate() ?? {};
        const info = {
          peerCN: cert.subject?.CN ?? null,
          peerIssuer: cert.issuer?.CN ?? null,
          // rejectUnauthorized:false 时 authorized 仍反映「用系统信任库能不能验过」——
          // 受管域名（我们的叶证书）要 true，说明 CA 已正确装进用户 Root 库。
          authorized: c.authorized === true,
        };
        c.write(`GET / HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: dsh-acc-proxy-child\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
        let buf = Buffer.alloc(0);
        c.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        c.on('end', () => finish({
          ok: true, ...info,
          status: buf.toString('latin1').split('\r\n')[0] || 'empty',
          bytes: buf.length,
        }));
      });
    });
    req.end();
  });
}

process.stdout.write(JSON.stringify(await run()) + '\n');
process.exit(0);
