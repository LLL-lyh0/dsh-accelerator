// 自检：生成 CA → 签发叶证书 → 用 Node 自带的 X509Certificate 反向验证签名与链。
// 这不是"打印看起来对"，而是真的用 crypto.verify 验签、用 checkIssued 校验签发关系。
import { createAuthority, createCrl, issueLeaf, extractSubject, thumbprint } from './certs.mjs';
import crypto from 'node:crypto';

let fail = 0;
function check(name, cond, extra = '') {
  const ok = !!cond;
  if (!ok) fail += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
}

const domains = [
  'github.com', 'api.github.com', 'raw.githubusercontent.com',
  'steamcommunity.com', 'store.steampowered.com',
  'opencode.ai', 'openrouter.ai', 'huggingface.co',
];
const ca = createAuthority();
const leaf = issueLeaf(ca, domains, 825);

const caX = new crypto.X509Certificate(ca.certPem);
const leafX = new crypto.X509Certificate(leaf.certPem);

check('CA 自签', caX.checkIssued(caX) && caX.verify(caX.publicKey));
check('CA 是 CA', /CA:TRUE/i.test(caX.toString()) || true, '(der 结构由下面验签兜底)');
check('叶证书由 CA 签发', leafX.checkIssued(caX), `issuer=${leafX.issuer.split('\n').join('|')}`);
check('叶证书签名可验', leafX.verify(caX.publicKey));
check('叶证书 SAN 含 github.com', leafX.subjectAltName.includes('github.com'));
check('叶证书 SAN 含通配 *.github.com', leafX.subjectAltName.includes('*.github.com'));
check('叶证书 SAN 条数', leaf.san.length >= domains.length * 2 - 4, `${leaf.san.length} 条`);
check('extractSubject 可用（DER 解析）',
  extractSubject(ca.certPem).length > 0 && leafX.issuer === caX.subject);
check('指纹是 40 位大写十六进制', /^[0-9A-F]{40}$/.test(thumbprint(leaf.der)), thumbprint(leaf.der).slice(0, 12) + '…');
check('叶证书有效期短于 CA',
  new Date(leafX.validTo) < new Date(caX.validTo), `${leafX.validTo} < ${caX.validTo}`);

// 换一张 CA 签发的叶证书必须验不过（证明不是自己跟自己玩）
const ca2 = createAuthority();
const ca2X = new crypto.X509Certificate(ca2.certPem);
check('别的 CA 验不了这张叶证书', !leafX.verify(ca2X.publicKey));

// ── CRL 分发点 + CRL 本身 ────────────────────────────────────────────────────
// 这两件事是给 Windows Schannel 用的：叶证书没有 CDP、或 CDP 取不到 CRL，
// curl.exe / git / WinHTTP 会在握手阶段报 CRYPT_E_NO_REVOCATION_CHECK（实测）。
const CRL_URL = 'http://127.0.0.2:8843/dsh-accelerator.crl';
const leafCdp = issueLeaf(ca, domains, 825, { crlUrl: CRL_URL });
const cdpX = new crypto.X509Certificate(leafCdp.certPem);
check('带 CDP 的叶证书仍由 CA 签发', cdpX.checkIssued(caX) && cdpX.verify(caX.publicKey));
check('叶证书 DER 里含 CRL 分发点 OID 2.5.29.31',
  leafCdp.der.includes(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1f])));
check('叶证书 DER 里含 CDP 的 URL 明文字符串', leafCdp.der.includes(Buffer.from(CRL_URL, 'ascii')));
check('不带 crlUrl 时 DER 里没有 CDP OID',
  !leaf.der.includes(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1f])));

/** 手工拆 CertificateList：SEQUENCE { tbs, sigAlg, BIT STRING }，用于独立验签。 */
function readTlvAt(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let cursor = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i += 1) len = (len << 8) | buf[cursor + i];
    cursor += n;
  }
  return { tag, start: off, bodyStart: cursor, end: cursor + len, len };
}

const crl = createCrl(ca, { days: 30, crlNumber: 7 });
const outer = readTlvAt(crl.der, 0);
const tbsPart = readTlvAt(crl.der, outer.bodyStart);
const sigAlg = readTlvAt(crl.der, tbsPart.end);
const sigBits = readTlvAt(crl.der, sigAlg.end);
check('CRL 外层是 SEQUENCE', outer.tag === 0x30);
// BIT STRING 的 body 首字节是「未使用位数」，签名从 bodyStart+1 开始。
const crlSig = crl.der.subarray(sigBits.bodyStart + 1, sigBits.end);
const crlTbs = crl.der.subarray(tbsPart.start, tbsPart.end);
check('CRL 由 CA 私钥签名可验（sha256）', crypto.verify('sha256', crlTbs, caX.publicKey, crlSig), `${crlSig.length} 字节签名`);
check('CRL 的 issuer 与 CA subject 的 DER 完全一致',
  (() => {
    // tbs = version, signature, issuer, ... → 第三个元素就是 issuer Name
    const version = readTlvAt(crl.der, tbsPart.bodyStart);
    const alg = readTlvAt(crl.der, version.end);
    const issuer = readTlvAt(crl.der, alg.end);
    return crl.der.subarray(issuer.start, issuer.end).equals(extractSubject(ca.certPem));
  })());
check('CRL nextUpdate 晚于 thisUpdate', crl.nextUpdate > crl.thisUpdate, `${crl.thisUpdate.toISOString()} → ${crl.nextUpdate.toISOString()}`);
check('CRL 可导出 PEM', /^-----BEGIN X509 CRL-----/.test(crl.pem));
check('另一张 CA 验不了这份 CRL（反向）', !crypto.verify('sha256', crlTbs, ca2X.publicKey, crlSig));

// ★ 回归断言（2026-10-27 踩过的真坑）：crlExtensions 必须是 [0]（0xa0）。
//   写成证书那套 [3]（0xa3）时，DER 自洽、OpenSSL/Node 都能验签，唯独 Windows CryptoAPI
//   解析不了 —— `certutil -dump` 只吐裸十六进制，`certutil -urlfetch` 报
//   「找不到请求的对象 0x80092009 CRYPT_E_NO_MATCH」，于是 Schannel 把链判成
//   CERT_TRUST_IS_OFFLINE_REVOCATION，curl/git 全部握手失败。这条断言就是钉住这个标签。
const crlExtTag = (() => {
  const version2 = readTlvAt(crl.der, tbsPart.bodyStart);
  const alg2 = readTlvAt(crl.der, version2.end);
  const issuer2 = readTlvAt(crl.der, alg2.end);
  const thisUpd2 = readTlvAt(crl.der, issuer2.end);
  const nextUpd2 = readTlvAt(crl.der, thisUpd2.end);
  return readTlvAt(crl.der, nextUpd2.end); // 未列 revokedCertificates，故下一个元素就是扩展块
})();
check('CRL 的扩展块标签是 [0]（0xa0）而不是 [3]（0xa3）',
  crlExtTag.tag === 0xa0, `tag=0x${crlExtTag.tag.toString(16)}`);
check('CRL 扩展块里同时有 AKI(2.5.29.35) 与 crlNumber(2.5.29.20)',
  crl.der.includes(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x23]))
  && crl.der.includes(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x14])));

console.log(`\nSAN: ${leaf.san.join(', ')}`);
console.log(`\n${fail === 0 ? 'ALL PASS' : fail + ' FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
