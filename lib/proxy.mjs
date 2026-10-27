// HTTP 代理协议层（系统代理 / PAC 模式的入口）。
//
// 为什么不是「hosts 引过来 + TLS 直连」：hosts 被别家提权加速器改成只读后就没法引流量了，
// 而 PAC/系统代理只需要认一个本机 HTTP 代理端口，注册表是每用户可写的 ⇒ 标准用户也能接管。
//
// 三条分流（都不改 body、不看加密内容）：
//   1. `CONNECT host:443` 且 decide 为真 → 交给 engine.intercept()：把这条已连上的 socket
//      升级成服务端 TLS，再用与 hosts 模式完全相同的「节点竞速 + 字节中继」。
//   2. `CONNECT` 但 decide 为假 → **盲隧道**转发（绝不能销毁：这是用户自己的正常流量）。
//   3. 明文 `GET http://…` → 同样盲转发；`GET /proxy.pac` 返回 PAC 脚本。
//
// 只有第 1 条会做 MITM，所以「不在受管域名里的流量」永远只是被转发，不会被解密。

import { parseHostPort } from './sni.mjs';

const HEADER_TIMEOUT_MS = 10_000;
const MAX_HEADER_BYTES = 16 * 1024;
const PAC_PATH = '/proxy.pac';
const CRL_PATH = '/dsh-accelerator.crl';

const DBG = process.env.DSH_ACC_DEBUG ? (s) => process.stderr.write(`[proxy] ${s}\n`) : () => {};

function status(res, code, text, extraHeaders = {}) {
  const body = Buffer.isBuffer(text) ? text : Buffer.from(text ?? '', 'utf8');
  const reason = code === 200 ? 'OK' : code === 400 ? 'Bad Request' : code === 404 ? 'Not Found' : 'Error';
  const lines = [
    `HTTP/1.1 ${code} ${reason}`,
    `Content-Length: ${body.length}`,
    'Connection: close',
  ];
  for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`);
  // 头 + 体必须一起发：只发头的话 Content-Length 会挂着，客户端会一直等 body（实测就是「PAC 请求永远不返回」）。
  return Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), body]);
}

function parseRequestLine(head) {
  const line = head.split('\r\n', 1)[0] ?? '';
  const m = /^([A-Z]+)[ \t]+(\S+)[ \t]+HTTP\/1\.[01]$/.exec(line);
  if (!m) return null;
  return { method: m[1], target: m[2] };
}

/** 去掉逐跳代理头（转发时必须剥掉，否则上游会看到本机代理的存在）。 */
function stripHopByHop(head) {
  const [requestLine, ...rest] = head.split('\r\n');
  const kept = rest.filter((l) => {
    const name = l.split(':', 1)[0].trim().toLowerCase();
    return name !== 'proxy-connection' && name !== 'proxy-authorization';
  });
  return [requestLine, ...kept].join('\r\n');
}

/**
 * 接一条代理连接：先把请求头读完，再分流。
 * 读头期间 socket 是暂停的，读完立刻 pause() 并把多余的字节 unshift 回去，不让字节漏给下一个消费者。
 */
export function handleProxyConnection(engine, socket) {
  engine.stats.proxied += 1;
  engine.sockets.add(socket);
  socket.once('close', () => engine.sockets.delete(socket));
  socket.on('error', () => { /* 客户端断开 */ });

  const clientPort = socket.remotePort;
  let buf = Buffer.alloc(0);
  let settled = false;

  const timer = setTimeout(() => {
    if (settled) return;
    settled = true;
    socket.destroy();
  }, HEADER_TIMEOUT_MS);

  const onData = (chunk) => {
    if (settled) return;
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > MAX_HEADER_BYTES) {
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      return;
    }
    const idx = buf.indexOf('\r\n\r\n');
    if (idx < 0) return;
    settled = true;
    clearTimeout(timer);
    socket.removeListener('data', onData);
    const head = buf.subarray(0, idx).toString('latin1');
    const tail = buf.subarray(idx + 4);
    socket.pause();
    DBG(`head ${clientPort}: ${head.split('\r\n', 1)[0]}`);
    route(engine, socket, head, Buffer.from(tail), clientPort).catch((e) => {
      DBG(`route fail: ${e && e.message}`);
      socket.destroy();
    });
  };

  socket.on('data', onData);
}

async function route(engine, socket, head, tail, clientPort) {
  const parsed = parseRequestLine(head);
  if (!parsed) {
    socket.end(status(socket, 400, 'bad request line'));
    return;
  }
  const cfg = engine.deps.getConfig();

  if (parsed.method === 'CONNECT') {
    const { host, port } = parseHostPort(parsed.target, 443);
    if (!host) {
      socket.end(status(socket, 400, 'bad CONNECT target'));
      return;
    }
    socket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: dsh-accelerator\r\n\r\n');

    const { pid, procName } = await engine.attribute(clientPort, cfg.proxyPort);
    const allowed = engine.decide(host, procName, cfg, pid);
    DBG(`CONNECT ${host}:${port} allowed=${allowed} pid=${pid} proc=${procName}`);

    if (allowed && Number(port) === 443) {
      if (tail.length) socket.unshift(tail);
      engine.intercept(socket, host, { pid, procName });
      return;
    }

    // 不接管 —— 盲隧道。**这里绝不能 destroy**：PAC 只把受管域名交给我们，
    // 但用户也可能把整个系统代理设成我们；销毁等于把正常流量掐断。
    engine.stats.bypassed += 1;
    engine.emit('decision', { host, pid, procName, allowed: false, via: 'proxy' });
    await engine.blindTunnel(socket, host, Number(port) || 443, tail);
    return;
  }

  // ── 明文 HTTP ──
  const urlPath = parsed.target;
  if (urlPath.split('?', 1)[0] === PAC_PATH) {
    const pac = engine.pacText();
    socket.end(status(socket, 200, pac, { 'Content-Type': 'application/x-ns-proxy-autoconfig' }));
    return;
  }

  // CRL：叶证书的 CRL 分发点指向这里。Schannel 系客户端（curl/git/WinHTTP）会来取，
  // 取不到就以 CRYPT_E_NO_REVOCATION_CHECK 拒握手 —— 所以这个分支在 hosts 模式下也要在。
  if (urlPath.split('?', 1)[0] === CRL_PATH) {
    const der = engine.crlBytes();
    DBG(`CRL hit ${urlPath} bytes=${der ? der.length : 0}`);
    if (!der || !der.length) {
      socket.end(status(socket, 404, 'no crl'));
      return;
    }
    socket.end(status(socket, 200, der, { 'Content-Type': 'application/pkix-crl' }));
    return;
  }

  // 绝对形式 `GET http://host/path` → 原样转发（明文 HTTP，不 MITM、不改 body）
  const abs = /^http:\/\/([^/\s]+)(\/\S*)?$/i.exec(urlPath);
  if (abs) {
    DBG(`absolute-form -> blind tunnel ${abs[1]} (path ${abs[2] || '/'})`);
    const { host, port } = parseHostPort(abs[1], 80);
    const rewritten = stripHopByHop(head).replace(/^([A-Z]+)[ \t]+\S+([ \t]+HTTP\/1\.[01])$/, `$1 ${abs[2] || '/'}$2`);
    const { pid, procName } = await engine.attribute(clientPort, cfg.proxyPort);
    engine.emit('decision', { host, pid, procName, allowed: false, via: 'proxy-plain' });
    await engine.blindTunnel(socket, host, port, Buffer.concat([Buffer.from(`${rewritten}\r\n\r\n`, 'latin1'), tail]));
    return;
  }

  DBG(`plain 404 target=${urlPath}`);
  socket.end(status(socket, 404, 'dsh-accelerator proxy: only CONNECT / absolute-form / /proxy.pac / /dsh-accelerator.crl'));
}

export { PAC_PATH, CRL_PATH, parseRequestLine, stripHopByHop };
