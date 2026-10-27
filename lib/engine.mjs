// 本地 MITM 加速引擎。
//
// 链路：客户端 --TLS(我们的叶证书)--> 本引擎 --TLS(上游，SNI 可消隐)--> 真实 IP
// 中间是**纯字节中继**（不解析 HTTP），所以 h1/h2、WebSocket、SSE 全都自然工作。
//
// 三个关键设计（全部来自实测）：
//  1) 上游地址只能来自 nodes.json / DoH，绝不能用系统 DNS（hosts 被改过，会连回自己）。
//  2) 每个节点带 sni 策略：real / none / cdn。Akamai、CloudFront 系发真 SNI 必被 RST，
//     不发 SNI 反而 200 —— 这是绕过阻断的核心。
//  3) 一条连接失败就换下一条**并行尝试**，谁先握手成功用谁（不是串行超时）。

import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { parseClientHello, matchDomain } from './sni.mjs';
import { resolveA, attributePid, lookupProcessNames } from './dns-and-pid.mjs';
import { NodeHealth } from './health.mjs';
import { handleProxyConnection } from './proxy.mjs';

const UPSTREAM_PORT = 443;
const HANDSHAKE_TIMEOUT = 8000;
const FIRST_BYTE_WAIT = 2500;   // 竞速时等「首个应用层字节」的时长

/**
 * 建立到上游的原始 TCP socket；若配置了外部上游代理（http/socks5），先穿过去。
 * ★ 所有权规则：resolve 之后**必须摘掉所有失败监听**。之前没摘 ——
 *   abort/timeout/error 会在连接交出后回来 destroy 掉它（winner 的上游被自己销毁，
 *   下游 pipe 到一个正在销毁的 TLS socket 直接 segfault）。
 * @returns {Promise<net.Socket>}
 */
function connectVia(upstream, host, port, signal) {
  const direct = !upstream || upstream.mode === 'direct' || !upstream.host;
  const target = direct ? { host, port } : { host: upstream.host, port: upstream.port };

  return new Promise((resolve, reject) => {
    const sock = net.connect({ ...target, timeout: HANDSHAKE_TIMEOUT });
    let handedOff = false;
    const fail = (e) => {
      if (handedOff) return;
      handedOff = true;
      detach();
      sock.destroy();
      reject(e instanceof Error ? e : new Error(String(e)));
    };
    const onAbort = () => fail(new Error('aborted'));
    const onSuccess = () => {
      if (handedOff) return;
      handedOff = true;
      detach();
      sock.setTimeout(0);        // 解除空闲超时：交出后由调用方管生命周期
      resolve(sock);
    };
    function detach() {
      sock.removeListener('error', fail);
      sock.removeListener('timeout', () => fail(new Error('tcp timeout')));
      sock.removeListener('connect', onSuccess);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
    sock.once('error', fail);
    sock.once('timeout', () => fail(new Error('tcp timeout')));
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    if (direct) {
      sock.once('connect', onSuccess);
    } else if (upstream.mode === 'socks5') {
      sock.once('connect', () => {
        socks5Handshake(sock, host, port, upstream).then(onSuccess, fail);
      });
    } else {
      // HTTP CONNECT
      sock.once('connect', () => {
        const auth = upstream.username
          ? `Proxy-Authorization: Basic ${Buffer.from(`${upstream.username}:${upstream.password ?? ''}`).toString('base64')}\r\n`
          : '';
        sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
        let buf = Buffer.alloc(0);
        const onData = (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          const idx = buf.indexOf('\r\n\r\n');
          if (idx < 0) return;
          sock.removeListener('data', onData);
          const head = buf.toString('latin1', 0, idx);
          if (!/^HTTP\/1\.[01] 200/.test(head)) { fail(new Error(`proxy refused: ${head.split('\r\n')[0]}`)); return; }
          if (buf.length > idx + 4) {
            // 代理在响应头后面就推了数据（不该发生，但别丢）：先转交给下游
            const rest = buf.subarray(idx + 4);
            setImmediate(() => sock.emit('data', rest));
          }
          onSuccess();
        };
        sock.on('data', onData);
      });
    }
  });
}

/** SOCKS5 无认证 / 用户名密码认证，只做 CONNECT。 */
function socks5Handshake(sock, host, port, upstream) {
  return new Promise((resolve, reject) => {
    const methods = upstream.username ? [0x00, 0x02] : [0x00];
    sock.write(Buffer.from([0x05, methods.length, ...methods]));
    let step = 0;
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (step === 0) {
        if (buf.length < 2) return;
        if (buf[1] === 0xff) { cleanup(); reject(new Error('socks5: no acceptable auth')); return; }
        const method = buf[1];
        buf = buf.subarray(2);
        if (method === 0x02) {
          const u = Buffer.from(upstream.username, 'utf8');
          const p = Buffer.from(upstream.password ?? '', 'utf8');
          sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
          step = 1;
          return;
        }
        step = 2;
        sendConnect();
        return;
      }
      if (step === 1) {
        if (buf.length < 2) return;
        if (buf[1] !== 0x00) { cleanup(); reject(new Error('socks5: auth failed')); return; }
        buf = buf.subarray(2);
        step = 2;
        sendConnect();
        return;
      }
      if (step === 2) {
        if (buf.length < 10) return;
        if (buf[1] !== 0x00) { cleanup(); reject(new Error(`socks5: connect failed rep=${buf[1]}`)); return; }
        cleanup();
        resolve();
      }
    };
    const cleanup = () => sock.removeListener('data', onData);
    function sendConnect() {
      const h = Buffer.from(host, 'utf8');
      const req = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h,
        Buffer.from([(port >> 8) & 0xff, port & 0xff]),
      ]);
      sock.write(req);
    }
    sock.on('data', onData);
    sock.once('error', (e) => { cleanup(); reject(e); });
  });
}

/** 把节点策略翻译成 tls.connect 的参数。 */
function tlsOptionsFor(node, host) {
  if (node.sni === 'none') {
    // 完全不发 SNI 扩展 —— Node 在 servername 为 undefined 时不会发。
    return { servername: undefined };
  }
  if (node.sni === 'cdn') {
    return { servername: node.sniValue || host };
  }
  return { servername: host };
}

/**
 * 对一个候选节点做「TCP → TLS 握手」的尝试。
 *
 * ★ 千万不要在这里等「上游首字节」来判定存活：TLS 1.3 握手刚完成就会推
 * NewSessionTicket，那会被误当成应用层数据；把它写回客户端那条 TLS 流里，
 * 等于往加密通道塞别的连接的记录，客户端会立刻断开（实测表现为 authorized=true 但 bytes=0）。
 *
 * 存活判定改为「握手成功 = 候选可用」，真实可用性由 NodeHealth 事后用结果反馈修正。
 */
function tryNode(node, host, upstream, signal) {
  const DBG = process.env.DSH_ACC_DEBUG ? (s) => process.stderr.write(`[try ${node?.ip}/${node?.sni}] ${s}\n`) : () => {};
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err, sock) => {
      if (settled) { if (sock) sock.destroy(); return; }
      settled = true;
      if (err) { DBG(`fail ${err && err.message}`); if (sock) sock.destroy(); reject(err); return; }
      DBG('handshake ok');
      resolve({ sock, node });
    };

    connectVia(upstream, node.ip, UPSTREAM_PORT, signal).then((raw) => {
      DBG('tcp ok');
      if (settled) { raw.destroy(); return; }
      const t = tls.connect({
        socket: raw,
        ...tlsOptionsFor(node, host),
        // 消隐 SNI / 换 CDN 名时上游给的是通用证书，无法按域名校验；这里刻意不校验。
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1'],
      });
      const timer = setTimeout(() => done(new Error(`tls timeout ${node.ip}`), t), HANDSHAKE_TIMEOUT);
      t.once('error', (e) => { clearTimeout(timer); done(e, t); });
      t.once('secureConnect', () => { clearTimeout(timer); done(null, t); });
    }).catch((e) => done(e));
  });
}

/**
 * 加速引擎。
 * 事件：`decision` {host, pid, allowed, node, ms} / `error`
 */
export class Engine extends EventEmitter {
  constructor(deps) {
    super();
    /** @type {{getConfig: () => any, getNodes: () => any, getLeaf: () => any, getPac?: () => string, getCrl?: () => Buffer|null}} */
    this.deps = deps;
    this.server = null;
    this.proxyServer = null;
    this.sockets = new Set();
    this.stats = { connections: 0, accelerated: 0, bypassed: 0, failed: 0, proxied: 0, tunneled: 0 };
    this.pidNames = new Map();
    this.health = new NodeHealth();
    this.leafCache = { certPem: null, ctx: null };
  }

  get listening() { return Boolean(this.server?.listening); }

  get proxyListening() { return Boolean(this.proxyServer?.listening); }

  /** 单张多 SAN 叶证书 → 一个 SecureContext（换证书时重建）。 */
  secureContext() {
    const leaf = this.deps.getLeaf();
    if (!leaf) throw new Error('leaf certificate not ready');
    if (this.leafCache.certPem !== leaf.certPem || !this.leafCache.ctx) {
      this.leafCache = { certPem: leaf.certPem, ctx: tls.createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }) };
    }
    return this.leafCache.ctx;
  }

  async start() {
    if (this.server) return;
    const cfg = this.deps.getConfig();
    const leaf = this.deps.getLeaf();

    this.server = tls.createServer({
      cert: leaf.certPem,
      key: leaf.keyPem,
      SNICallback: (servername, cb) => {
        // 单张多 SAN 叶证书覆盖全部受管域名，这里不需要按域名换证书。
        cb(null, tls.createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }));
      },
    }, (socket) => this.onConnection(socket));

    this.server.on('tlsClientError', () => { /* 客户端在握手阶段断开是常态，忽略 */ });
    this.server.on('error', (e) => this.emit('error', e));

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(cfg.listenPort, cfg.listenHost, () => {
        this.server.removeListener('error', reject);
        resolve();
      });
    });
  }

  /**
   * HTTP 代理监听（系统代理 / PAC 模式的入口）。
   *
   * 与 443 那条「直连 TLS」监听的区别：这条**先收明文 HTTP**，看到 `CONNECT host:443`
   * 回一个 200，再把这条已经连上的 socket 升级成服务端 TLS（`new tls.TLSSocket(sock, {isServer:true})`
   * —— 实测可行，且单张多 SAN 证书下不需要 SNICallback）。
   *
   * 这样系统代理/PAC 只需要认「一个 HTTP 代理端口」，不必依赖 hosts 可写。
   */
  async startProxy() {
    if (this.proxyServer) return;
    const cfg = this.deps.getConfig();
    const port = cfg.proxyPort;
    this.proxyServer = net.createServer((socket) => this.onProxyConnection(socket));
    this.proxyServer.on('error', (e) => this.emit('error', e));
    await new Promise((resolve, reject) => {
      this.proxyServer.once('error', reject);
      this.proxyServer.listen(port, cfg.proxyHost || '127.0.0.2', () => {
        this.proxyServer.removeListener('error', reject);
        resolve();
      });
    });
  }

  async stop() {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    if (this.server) {
      const srv = this.server;
      this.server = null;
      await new Promise((r) => srv.close(() => r()));
    }
    if (this.proxyServer) {
      const srv = this.proxyServer;
      this.proxyServer = null;
      await new Promise((r) => srv.close(() => r()));
    }
  }

  /** 反查这条连接属于哪个进程。hosts 模式按 listenPort 反查，代理模式按 proxyPort。 */
  async attribute(clientPort, portForPid) {
    let pid = null;
    try {
      pid = await attributePid(clientPort, portForPid, this.pidNames);
    } catch { /* 拿不到 pid 就按「未知」处理 */ }
    let procName = null;
    if (pid && !this.pidNames.get(pid)) {
      const names = await lookupProcessNames([pid]).catch(() => new Map());
      for (const [p, v] of names) this.pidNames.set(p, v);
      const hit = names.get(pid);
      if (hit) procName = (hit.name || '').toLowerCase();
    } else if (pid) {
      const hit = this.pidNames.get(pid);
      if (hit && typeof hit === 'object') procName = (hit.name || '').toLowerCase();
    }
    return { pid, procName };
  }

  async onConnection(socket) {
    this.stats.connections += 1;
    const DBG = process.env.DSH_ACC_DEBUG ? (s) => process.stderr.write(`[dbg] ${s}\n`) : () => {};
    DBG(`conn#${this.stats.connections} accepted sni=${socket.servername} rport=${socket.remotePort}`);
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
    socket.on('error', () => { /* 客户端断开 */ });
    const host = socket.servername ? socket.servername.toLowerCase() : null;
    const clientPort = socket.remotePort;
    const cfg = this.deps.getConfig();

    if (!host) { socket.destroy(); this.stats.failed += 1; return; }

    // ── 按软件粒度判定（m00192 需求 1/2） ──
    const { pid, procName } = await this.attribute(clientPort, cfg.listenPort);
    DBG(`pid=${pid} procName=${procName}`);

    const allowed = this.decide(host, procName, cfg, pid);
    DBG(`decide=${allowed}`);
    if (!allowed) {
      // hosts 模式下必须销毁：客户端是被 hosts 指过来的，
      // 放行它也无法直连到真实服务器（本机 443 上并没有那个站点）。
      this.stats.bypassed += 1;
      this.emit('decision', { host, pid, procName, allowed: false, via: 'hosts' });
      socket.destroy();
      return;
    }
    await this.connectThroughPool(socket, host, { pid, procName, via: 'hosts' });
  }

  /** 代理监听上的连接：交给 lib/proxy.mjs 处理协议（CONNECT / 明文 / PAC）。 */
  onProxyConnection(socket) {
    handleProxyConnection(this, socket);
  }

  /** PAC 脚本文本（由 accelerator 依当前配置生成）。 */
  pacText() {
    try {
      return typeof this.deps.getPac === 'function' ? String(this.deps.getPac() ?? '') : '';
    } catch { return ''; }
  }

  /** 当前 CRL（DER）。Schannel 系客户端会来 /dsh-accelerator.crl 取它。 */
  crlBytes() {
    try {
      const der = typeof this.deps.getCrl === 'function' ? this.deps.getCrl() : null;
      return Buffer.isBuffer(der) ? der : null;
    } catch { return null; }
  }

  /**
   * 把一条已经完成 HTTP CONNECT 握手的明文 socket 升级成服务端 TLS，
   * 然后走与 hosts 模式**完全相同**的竞速 + 中继路径。
   *
   * 实测要点：`new tls.TLSSocket(sock, {isServer:true, secureContext})` 可行
   * （另一条等价路径是 `sharedTlsServer.emit('connection', sock)`，但会共享状态）；
   * 且 TLSSocket 上 `secure` / `secureConnect` / `secureConnection` **都不触发**，
   * 所以不能等握手事件 —— 立即挂 pipe，未读期间流是暂停缓冲的，不会丢数据。
   */
  intercept(rawSocket, host, meta = {}) {
    const tlsSocket = new tls.TLSSocket(rawSocket, { isServer: true, secureContext: this.secureContext() });
    this.sockets.add(tlsSocket);
    tlsSocket.once('close', () => this.sockets.delete(tlsSocket));
    tlsSocket.on('error', () => { /* 客户端在握手阶段断开是常态 */ });
    this.connectThroughPool(tlsSocket, host, { ...meta, via: 'proxy-connect' }).catch(() => tlsSocket.destroy());
  }

  /**
   * 盲隧道：只做字节转发，不做 MITM、不改写内容。
   * 解析优先走 DoH —— hosts 可能被别家加速器写成 127.0.0.1，直连会自环。
   */
  async blindTunnel(socket, host, port, initial) {
    const DBG = process.env.DSH_ACC_DEBUG ? (s) => process.stderr.write(`[tunnel] ${s}\n`) : () => {};
    const ips = await resolveA(host).catch(() => []);
    const targets = [...new Set([...ips, host])];
    DBG(`blind ${host}:${port} targets=${targets.join(',')}`);
    let upstream = null;
    let lastErr = null;
    for (const ip of targets) {
      try {
        upstream = await new Promise((resolve, reject) => {
          const s = net.connect({ host: ip, port, timeout: 8000 });
          const onErr = (e) => { s.destroy(); reject(e); };
          s.once('error', onErr);
          s.once('timeout', () => onErr(new Error('tunnel timeout')));
          s.once('connect', () => { s.removeListener('error', onErr); resolve(s); });
        });
        DBG(`blind ok via ${ip}`);
        break;
      } catch (e) { lastErr = e; DBG(`blind attempt ${ip} failed: ${e && e.message}`); upstream = null; }
    }
    if (!upstream) {
      DBG(`tunnel fail ${host}:${port} ${lastErr && lastErr.message}`);
      this.stats.failed += 1;
      socket.destroy();
      return;
    }
    const finish = () => { socket.destroy(); upstream.destroy(); };
    socket.on('error', finish);
    upstream.on('error', finish);
    socket.on('close', finish);
    upstream.on('close', finish);
    if (initial && initial.length) upstream.write(initial);
    socket.pipe(upstream);
    upstream.pipe(socket);
    this.stats.tunneled += 1;
  }

  /** 竞速选节点并把两个流对接起来。两条入口（hosts 直连 / 代理 CONNECT）共用。 */
  async connectThroughPool(socket, host, meta = {}) {
    const DBG = process.env.DSH_ACC_DEBUG ? (s) => process.stderr.write(`[dbg] ${s}\n`) : () => {};
    const cfg = this.deps.getConfig();
    const { pid = null, procName = null, via = 'hosts' } = meta;

    // ── 选节点并竞速 ──
    const t0 = Date.now();
    const nodes = this.candidatesFor(host);
    if (nodes.length === 0) {
      this.stats.failed += 1;
      this.health.noteHostFailure(host, 'no-candidate');
      this.emit('decision', { host, pid, procName, allowed: true, node: null, reason: 'no-candidate', via });
      this.emit('exhausted', { host, reason: 'no-candidate' });
      socket.destroy();
      return false;
    }

    let upstreamSock = null;
    let usedNode = null;
    try {
      DBG(`raceNodes(${nodes.length})…`);
      const winner = await this.raceNodes(nodes, host, cfg.upstream);
      DBG(`race winner=${winner.node.ip}:${winner.node.sni}`);
      upstreamSock = winner.sock;
      usedNode = winner.node;
    } catch (e) {
      DBG(`race fail: ${e && e.message}`);
      this.stats.failed += 1;
      const reason = String(e && e.message);
      this.health.noteHostFailure(host, reason);
      this.emit('decision', { host, pid, procName, allowed: true, node: null, reason, via });
      // 智能加速的触发点：整个池子对这个域名都不通了 → 交给 SmartController 换节点/补池。
      this.emit('exhausted', { host, reason });
      socket.destroy();
      return false;
    }

    this.health.noteHostOk(host);
    this.stats.accelerated += 1;
    this.emit('decision', { host, pid, procName, allowed: true, node: usedNode, ms: Date.now() - t0, via });

    // ── 双向字节中继 ──
    // 上游 socket 此时处于 paused 状态（tryNode 里 await 期间不会有 data 事件被消费），
    // 先挂好两边的管道再 resume，避免丢包。
    const finish = () => {
      socket.destroy();
      if (upstreamSock) upstreamSock.destroy();
    };
    socket.on('error', finish);
    upstreamSock.on('error', finish);
    socket.on('close', finish);
    upstreamSock.on('close', finish);

    socket.pipe(upstreamSock);
    upstreamSock.pipe(socket);
    return true;
  }

  /** 综合 hosts 域名组开关、bypass 名单，决定这条连接是否接管。 */
  decide(host, procName, cfg, pid = null) {
    // 0) 自检连接（插件进程自己发的验证请求）永远放行。
    //    否则用户把 node / DSH 进程写进 bypass 时，验证会被自己拒掉，
    //    智能加速就会误判「这个域名不通」并无限空转。
    if (pid && pid === process.pid) return true;

    // 1) 显式 bypass 的进程一律不接管
    if (procName && (cfg.bypass || []).some((p) => String(p).toLowerCase() === procName)) return false;

    // 2) enforce 里的进程强制接管（即使域名不在组里，也交给上游竞速）
    if (procName && (cfg.enforce || []).some((p) => String(p).toLowerCase() === procName)) return true;

    // 3) 域名组开关：任何一条通配命中的组被关掉，就不接管
    const groups = this.deps.getNodes();
    for (const pattern of Object.keys(groups)) {
      if (!matchDomain(host, [pattern])) continue;
      const key = pattern;
      if (cfg.domainGroups && cfg.domainGroups[key] === false) return false;
      return true;
    }
    // 4) 不在受管域名里 —— 不接管（让客户端直连，避免把无关流量全 MITM）
    return false;
  }

  /** 候选节点：nodes.json 里的优先，其次 DoH 兜底。 */
  candidatesFor(host) {
    const groups = this.deps.getNodes();
    const list = [];
    for (const pattern of Object.keys(groups)) {
      if (!matchDomain(host, [pattern])) continue;
      for (const n of groups[pattern] || []) {
        if (n && typeof n.ip === 'string') list.push({ ip: n.ip, sni: n.sni || 'real', sniValue: n.sniValue });
      }
    }
    // 去重（同一 IP 只留第一个策略）
    const seen = new Set();
    return list.filter((n) => (seen.has(n.ip) ? false : (seen.add(n.ip), true)));
  }

  /**
   * 并行竞速：所有候选同时开跑，**谁先完成 TLS 握手谁赢**（不再等上游应用层数据 ——
   * TLS 1.3 的 NewSessionTicket 会被误判成首字节并污染客户端流）。
   * 串行会退化成「第一个节点超时 8s 才换下一个」，用户体感就是卡死。
   *
   * 结果会反馈给 NodeHealth：赢了的加分，输掉的扣分，下次优先快的。
   */
  async raceNodes(nodes, host, upstream) {
    // 按历史表现排序 —— 好节点先起跑，在同一轮竞速里就更容易赢
    const ordered = this.health.sortCandidates(host, nodes).slice(0, 6);
    const controller = new AbortController();
    try {
      return await this.raceList(ordered, host, upstream, controller.signal);
    } catch {
      controller.abort();
    }
    // 本地池全挂 → 现解析一次再试（「自配置」的一部分：不需要用户手工维护 IP）
    // 每个 DoH 出来的 IP 都同时试 real 和 none 两种 SNI 策略：Akamai/CloudFront 系
    // 发真 SNI 会被 RST、不发反而通，只试 real 等于白补一批节点。
    const ips = await resolveA(host).catch(() => []);
    const extra = [];
    for (const ip of ips.slice(0, 3)) {
      extra.push({ ip, sni: 'real' });
      extra.push({ ip, sni: 'none' });
    }
    if (extra.length === 0) throw new Error('no node and doh empty');
    return this.raceList(extra, host, upstream, new AbortController().signal);
  }

  /** 对一组节点竞速：第一个握手成功的赢，其余立刻销毁。 */
  raceList(nodes, host, upstream, signal) {
    return new Promise((resolve, reject) => {
      const total = nodes.length;
      if (total === 0) { reject(new Error('empty candidate list')); return; }
      const controller = new AbortController();
      if (signal) signal.addEventListener('abort', () => controller.abort(), { once: true });

      const won = [];
      let settled = false;
      let done = 0;
      let lastErr = null;

      for (const node of nodes) {
        tryNode(node, host, upstream, controller.signal).then((r) => {
          done += 1;
          if (settled) { r.sock.destroy(); return; }
          settled = true;
          this.health.record(host, r.node.ip, true);
          controller.abort();
          for (const s of won) s.destroy();     // 落败者的 socket 一律销毁
          won.length = 0;
          resolve(r);
        }).catch((e) => {
          done += 1;
          lastErr = e;
          this.health.record(host, node.ip, false);
          if (!settled && done === total) {
            settled = true;
            controller.abort();
            const msg = lastErr && lastErr.message ? lastErr.message : String(lastErr);
            reject(new Error(`all ${total} nodes failed: ${msg}`));
          }
        });
      }
    });
  }
}
