// dsh-accelerator — 纯 Node 证书签发（零外部二进制）
//
// 本机没有 openssl，也不应该依赖 PowerShell。这里手写最小 DER 编码器，
// 生成一张 RSA-2048 的根 CA + 一张覆盖全部受管域名的多 SAN 叶证书。
//
// 与 Watt Toolkit / Steamcommunity_302 的关键差异：**私钥不放进证书存储**。
// 那两家的根证书 HasPrivateKey=True，任何同用户进程都能导出私钥伪造任意网站；
// 这里私钥只落在 storages 目录下的文件里（可选 DPAPI 加密，见 lib/secret.mjs）。

import crypto from 'node:crypto';

// ── 最小 DER 编码器 ─────────────────────────────────────────────────────────

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, body) { return Buffer.concat([Buffer.from([tag]), len(body.length), body]); }
const seq = (...xs) => tlv(0x30, Buffer.concat(xs));
const set = (...xs) => tlv(0x31, Buffer.concat(xs));
const explicit = (n, body) => tlv(0xa0 + n, body);
const int = (buf) => tlv(0x02, buf);
const octets = (buf) => tlv(0x04, buf);
const bits = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0]), buf]));
const nullV = () => Buffer.from([0x05, 0x00]);
const bool = (b) => tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const utcTime = (d) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z', 'ascii'));
const generalized = (d) => tlv(0x18, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z', 'ascii'));

function oid(str) {
  const p = str.split('.').map(Number);
  const out = [40 * p[0] + p[1]];
  for (const n of p.slice(2)) {
    const stack = [n & 0x7f];
    let v = n >>> 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>>= 7; }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}
function time(d) { return d.getUTCFullYear() < 2050 ? utcTime(d) : generalized(d); }

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  cn: '2.5.4.3',
  o: '2.5.4.10',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  san: '2.5.29.17',
  skid: '2.5.29.14',
  crlDp: '2.5.29.31',
  akid: '2.5.29.35',
  crlNumber: '2.5.29.20',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
};

function name(cn, o) {
  return seq(set(seq(oid(OID.o), utf8(o))), set(seq(oid(OID.cn), utf8(cn))));
}

function serial() {
  const b = crypto.randomBytes(8);
  b[0] &= 0x7f;
  if (b[0] === 0) b[0] = 1;
  return int(b);
}

function sanExtension(domains) {
  const entries = domains.map((d) => {
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(d);
    return isIp ? tlv(0x87, Buffer.from(d.split('.').map(Number))) : tlv(0x82, Buffer.from(d, 'ascii'));
  });
  return seq(oid(OID.san), octets(seq(...entries)));
}
function basicConstraints(ca) {
  return seq(oid(OID.basicConstraints), bool(true), octets(ca ? seq(bool(true)) : seq()));
}
function keyUsage(isCa) {
  // 与 openssl 输出一致的形式：CA = keyCertSign+cRLSign+digitalSignature(0x86)，
  // 叶证书 = digitalSignature+keyEncipherment(0xa0)
  const v = isCa ? 0x86 : 0xa0;
  return seq(oid(OID.keyUsage), bool(true), octets(tlv(0x03, Buffer.from([0x01, v]))));
}
function extKeyUsage() {
  return seq(oid(OID.extKeyUsage), octets(seq(oid(OID.serverAuth), oid(OID.clientAuth))));
}
function subjKeyId(spkiDer) {
  return seq(oid(OID.skid), octets(octets(crypto.createHash('sha1').update(spkiDer).digest())));
}

/**
 * CRL 分发点扩展（OID 2.5.29.31）。
 *
 * 为什么必须有它：Windows Schannel 默认要求「能确认吊销状态」，而本地自签 CA 的叶证书
 * 若没有 CDP，Schannel 会在握手阶段直接抛 `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` ——
 * 实测 curl.exe / git(schannel) / WinHTTP 全部被拒（Chrome/Edge 的 BoringSSL 与 Node 的
 * OpenSSL 不受影响，所以表现为「浏览器打得开、命令行报证书错」）。
 * 有了 CDP 并让该 URL 真的能取到 CRL，Schannel 就能完成链验证。
 *
 * DER 结构（RFC 5280）：
 *   CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
 *   DistributionPoint     ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, ... }
 *   DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
 *   GeneralName           ::= CHOICE { ... uniformResourceIdentifier [6] IA5String ... }
 * 全是 IMPLICIT 标签，于是嵌套成 A0( A0( 86(url) ) )。
 */
function crlDistributionPoint(url) {
  const generalName = tlv(0x86, Buffer.from(url, 'ascii'));   // [6] uniformResourceIdentifier
  const fullName = tlv(0xa0, generalName);                    // [0] fullName（GeneralNames）
  const dpName = tlv(0xa0, fullName);                         // [0] distributionPoint
  return seq(oid(OID.crlDp), octets(seq(seq(dpName))));
}

/** 授权密钥标识（OID 2.5.29.35）：[0] keyIdentifier = CA 公钥的 SHA-1。 */
function authKeyId(keyId) {
  return seq(oid(OID.akid), octets(seq(tlv(0x80, keyId))));
}

function tbs({ version, serialBuf, issuer, subject, notBefore, notAfter, pubKeyDer, exts }) {
  return seq(
    explicit(0, int(Buffer.from([version]))),
    serialBuf,
    seq(oid(OID.sha256WithRSA), nullV()),
    issuer,
    seq(time(notBefore), time(notAfter)),
    subject,
    pubKeyDer,
    explicit(3, seq(...exts)),
  );
}

function signCert(tbsDer, caPrivateKey) {
  return seq(tbsDer, seq(oid(OID.sha256WithRSA), nullV()), bits(crypto.sign('sha256', tbsDer, caPrivateKey)));
}

export function toPem(der, label) {
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

// ── 对外 API ────────────────────────────────────────────────────────────────

const CA_ORG = 'DSH Accelerator';
const CA_CN = 'DSH Accelerator Root CA';

/**
 * 生成根 CA（一个 profile 只做一次，之后从磁盘复用）。
 * @param {number} [days] 有效天数
 */
export function createAuthority(days = 3650) {
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spkiDer = keys.publicKey.export({ type: 'spki', format: 'der' });
  const subject = name(CA_CN, CA_ORG);
  const now = Date.now();
  const der = signCert(tbs({
    version: 2,
    serialBuf: serial(),
    issuer: subject,
    subject,
    notBefore: new Date(now - 864e5),
    notAfter: new Date(now + days * 864e5),
    pubKeyDer: spkiDer,
    exts: [basicConstraints(true), keyUsage(true), subjKeyId(spkiDer)],
  }), keys.privateKey);
  return {
    der,
    certPem: toPem(der, 'CERTIFICATE'),
    keyPem: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

/** 从磁盘上的 PEM 还原 CA（用于签发叶证书）。 */
export function loadAuthority(certPem, keyPem) {
  return { certPem, keyPem };
}

/** 把域名列表规范成 SAN 集合：去重、补上二级域的通配符。 */
export function buildSanList(domains) {
  const out = new Set();
  for (const raw of domains) {
    const d = String(raw).trim().toLowerCase().replace(/\.$/, '');
    if (!d || d.includes('*')) { if (d) out.add(d); continue; }
    out.add(d);
    const parts = d.split('.');
    // 只给「二级域」补一次通配，避免把 a.b.c.example.com 也放进去
    if (parts.length === 2) out.add(`*.${d}`);
  }
  return [...out];
}

/**
 * 签发覆盖 domains 的叶证书。域名集合变了就得重签 —— 纯 Node 几毫秒完成。
 * @param {{certPem: string, keyPem: string}} ca
 * @param {string[]} domains
 * @param {number} [days]
 * @param {{crlUrl?: string}} [opts] `crlUrl` 给了就写进 CRL 分发点（Schannel 需要，见 crlDistributionPoint）
 */
export function issueLeaf(ca, domains, days = 825, opts = {}) {
  // 从 CA 证书里取出 subject 的 DER —— 它就是叶证书的 issuer 字段
  const issuerDer = extractSubject(ca.certPem);
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spkiDer = keys.publicKey.export({ type: 'spki', format: 'der' });
  const san = buildSanList(domains);
  const now = Date.now();
  const exts = [basicConstraints(false), keyUsage(false), extKeyUsage(), sanExtension(san), subjKeyId(spkiDer)];
  if (typeof opts.crlUrl === 'string' && opts.crlUrl !== '') exts.push(crlDistributionPoint(opts.crlUrl));
  const der = signCert(tbs({
    version: 2,
    serialBuf: serial(),
    issuer: issuerDer,
    subject: name('DSH Accelerator Leaf', CA_ORG),
    notBefore: new Date(now - 864e5),
    notAfter: new Date(now + days * 864e5),
    pubKeyDer: spkiDer,
    exts,
  }), crypto.createPrivateKey(ca.keyPem));
  return {
    certPem: toPem(der, 'CERTIFICATE'),
    keyPem: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    san,
    der,
    crlUrl: typeof opts.crlUrl === 'string' && opts.crlUrl !== '' ? opts.crlUrl : null,
  };
}

/**
 * 生成（空的）证书吊销列表：CRL v2，`revokedCertificates` 直接省略（= 没有任何吊销）。
 *
 * 用途：给叶证书的 CDP 一个**真能取到的东西**。Schannel 拉不到 CRL 时会报
 * `CRYPT_E_NO_REVOCATION_CHECK`，等于白签；拉到一个合法的空 CRL 就算验证通过。
 * `nextUpdate` 之后客户端会认为 CRL 过期，所以接管期间由 accelerator 按期重签。
 *
 * DER 结构（RFC 5280）：
 *   CertificateList ::= SEQUENCE {
 *     tbsCertList  SEQUENCE { version INTEGER, signature AlgorithmIdentifier, issuer Name,
 *                             thisUpdate Time, nextUpdate Time, [revokedCertificates], [0] crlExtensions },
 *     signatureAlgorithm AlgorithmIdentifier,
 *     signatureValue BIT STRING }
 *
 * @param {{certPem: string, keyPem: string}} ca
 * @param {{days?: number, crlNumber?: number, keyId?: Buffer}} [opts]
 */
export function createCrl(ca, opts = {}) {
  const days = opts.days ?? 30;
  const now = Date.now();
  const thisUpdate = new Date(now - 60_000);          // 往回退一分钟，避开客户端时钟偏差
  const nextUpdate = new Date(now + days * 864e5);
  const issuerDer = extractSubject(ca.certPem);
  const spkiDer = crypto.createPublicKey(crypto.createPrivateKey(ca.keyPem)).export({ type: 'spki', format: 'der' });
  const keyId = opts.keyId ?? crypto.createHash('sha1').update(spkiDer).digest();
  const crlNumberExt = seq(oid(OID.crlNumber), octets(int(Buffer.from([opts.crlNumber ?? 1]))));
  const tbs = seq(
    int(Buffer.from([0x01])),                          // version = v2（CRL v2 的版本号是 1）
    seq(oid(OID.sha256WithRSA), nullV()),
    issuerDer,
    time(thisUpdate),
    time(nextUpdate),
    // ★ 必须是 [0]（TBSCertList 的 crlExtensions）——写成 explicit(3,…) 会得到 a3，
    // 那是「证书」的 TBSCertificate.extensions 标签。DER 能签、Node 能读，但 CryptoAPI
    // 解析不了：它下载到 CRL 后报 CRYPT_E_NO_MATCH，链状态停在 OFFLINE_REVOCATION。
    explicit(0, seq(authKeyId(keyId), crlNumberExt)),  // [0] crlExtensions
  );
  const der = seq(tbs, seq(oid(OID.sha256WithRSA), nullV()), bits(crypto.sign('sha256', tbs, crypto.createPrivateKey(ca.keyPem))));
  return { der, pem: toPem(der, 'X509 CRL'), thisUpdate, nextUpdate, days };
}

/**
 * 从证书 PEM 里抠出 subject 的 DER（作为下一级证书的 issuer 字段用）。
 * 走 ASN.1 顺序解析：Certificate → TBSCertificate → [version] serial sigAlg issuer。
 */
export function extractSubject(certPem) {
  const der = Buffer.from(
    certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''),
    'base64',
  );
  const cert = readTlv(der, 0);                       // Certificate SEQUENCE
  const tbs = readTlv(cert.body, 0);                  // TBSCertificate SEQUENCE
  let off = 0;
  const first = readTlv(tbs.body, off);
  if (first.tag === 0xa0) off = first.end;            // 跳过 [0] version
  const ser = readTlv(tbs.body, off); off = ser.end;  // serialNumber
  const sig = readTlv(tbs.body, off); off = sig.end;  // signature AlgorithmIdentifier
  const issuerOff = off;
  const issuer = readTlv(tbs.body, off);              // issuer Name
  // ★ 必须连同 tag+length 一起取（issuer 是完整的一个 Name TLV，不是它的 body）。
  // 只取 body 会让叶证书的 issuer 字段变成裸 SET，OpenSSL 报 ERR_OSSL_ASN1_WRONG_TAG。
  return tbs.body.subarray(issuerOff, issuer.end);
}

function readTlv(buf, off) {
  const tag = buf[off];
  let p = off + 1;
  let l = buf[p++];
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i += 1) l = (l << 8) | buf[p++];
  }
  const start = p;
  return { tag, start, end: start + l, body: buf.subarray(start, start + l) };
}

/** 证书指纹（大写十六进制，与 certutil 输出一致）。 */
export function thumbprint(der) {
  return crypto.createHash('sha1').update(der).digest('hex').toUpperCase();
}

/** 归一化 PEM（去掉首尾空白、统一换行），便于做内容比对。 */
export function normalizePem(pem) {
  return String(pem).replace(/\r\n/g, '\n').trim() + '\n';
}
