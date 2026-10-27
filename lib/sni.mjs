// 从 TLS ClientHello 里取出 SNI —— 这是「要接管哪个域名」的唯一信源。
//
// 为什么不用 hosts 记录列表做判定：hosts 只是把流量引导到 127.0.0.2 的手段，
// 真正决定接管与否的是客户端握手时声明的 SNI（Steamcommunity_302 也是这么干的，
// 实测它对「在证书 SAN 里但 hosts 没有」的域名同样接管）。

/**
 * @param {Buffer} buf 已收到的头部字节（至少 5 + 4 + 2 + 32 字节）
 * @returns {{ serverName?: string, complete: boolean }}
 */
export function parseClientHello(buf) {
  // TLS record: type(1)=0x16 handshake, version(2), length(2)
  if (buf.length < 6) return { complete: false };
  if (buf[0] !== 0x16) return { complete: false };

  // 一条 record 可能装不下整个 ClientHello（罕见但存在），这里只处理常见的单 record 情形。
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return { complete: false };

  let p = 5;
  if (buf[p] !== 0x01) return { complete: false }; // handshake type = client_hello
  p += 4; // type(1) + length(3)

  p += 2; // client_version
  p += 32; // random

  if (p >= buf.length) return { complete: false };
  const sidLen = buf[p];
  p += 1 + sidLen;

  if (p + 2 > buf.length) return { complete: false };
  const csLen = buf.readUInt16BE(p);
  p += 2 + csLen;

  if (p >= buf.length) return { complete: false };
  const cmLen = buf[p];
  p += 1 + cmLen;

  if (p + 2 > buf.length) return { complete: false };
  const extTotal = buf.readUInt16BE(p);
  p += 2;
  const extEnd = Math.min(buf.length, p + extTotal);

  while (p + 4 <= extEnd) {
    const type = buf.readUInt16BE(p);
    const size = buf.readUInt16BE(p + 2);
    p += 4;
    if (type === 0x0000) { // server_name
      if (p + 5 > buf.length) return { complete: true };
      const listLen = buf.readUInt16BE(p);
      let q = p + 2;
      const listEnd = Math.min(buf.length, q + listLen);
      while (q + 3 <= listEnd) {
        const nameType = buf[q];
        const nameLen = buf.readUInt16BE(q + 1);
        q += 3;
        if (nameType === 0) {
          if (q + nameLen > buf.length) return { complete: true };
          return { serverName: buf.toString('ascii', q, q + nameLen).toLowerCase(), complete: true };
        }
        q += nameLen;
      }
      return { complete: true };
    }
    p += size;
  }
  return { complete: true };
}

/** 解析 `CONNECT host:port HTTP/1.1` 的首行。 */
export function parseConnect(buf) {
  const text = buf.toString('latin1');
  const lineEnd = text.indexOf('\r\n');
  if (lineEnd < 0) return null;
  const line = text.slice(0, lineEnd);
  const m = /^CONNECT\s+([^:\s]+)(?::(\d+))?\s+HTTP\/1\.[01]$/i.exec(line);
  if (!m) return { method: 'other', line, headerEnd: text.indexOf('\r\n\r\n') };
  return {
    method: 'CONNECT',
    host: m[1].toLowerCase(),
    port: m[2] ? Number(m[2]) : 443,
    headerEnd: text.indexOf('\r\n\r\n'),
  };
}

/**
 * 解析 `host:port`（代理的 CONNECT 目标 / 绝对 URI 的 authority）。
 * 支持 IPv6 字面量 `[::1]:443`；没写端口就用 fallback。
 */
export function parseHostPort(target, fallbackPort = 443) {
  const raw = String(target ?? '').trim();
  if (raw === '') return { host: null, port: fallbackPort };
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  if (v6) return { host: v6[1].toLowerCase(), port: v6[2] ? Number(v6[2]) : fallbackPort };
  const idx = raw.lastIndexOf(':');
  if (idx < 0) return { host: raw.toLowerCase(), port: fallbackPort };
  const port = Number(raw.slice(idx + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return { host: raw.toLowerCase(), port: fallbackPort };
  return { host: raw.slice(0, idx).toLowerCase(), port };
}

/** 通配符匹配：`*.github.com` 命中 `api.github.com`，但不命中 `github.com`。 */
export function matchDomain(host, patterns) {
  const h = host.toLowerCase();
  for (const p of patterns) {
    const pat = String(p).toLowerCase();
    if (pat === h) return true;
    if (pat.startsWith('*.')) {
      const suffix = pat.slice(1); // ".github.com"
      if (h.endsWith(suffix)) return true;
    }
  }
  return false;
}
