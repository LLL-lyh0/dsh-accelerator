// 活体验收：Schannel 的吊销检查是不是被「叶证书 CRL 分发点 + 本机服务 CRL」解决的。
//
// 背景：叶证书没有 CRL 分发点时，Windows Schannel 系客户端（curl.exe / git / WinHTTP）会在握手阶段
// 直接失败：`CRYPT_E_NO_REVOCATION_CHECK (0x80092012)`；而 HKCU 的 CertificateRevocation 开关
// **curl.exe 根本不读**（实测：置 0 也不管用）。真正管用的是证书里有 CDP、且那个 URL 能取到 CRL。
//
// 本脚本用「同一个 curl，只切换 CRL 服务是否在」来给出因果：
//   A) 只起 TLS 引擎、不起代理（CDP 取不到）→ curl 失败，错误含 CRYPT_E_NO_REVOCATION_CHECK
//   B) 起代理（CDP 能取到 CRL）           → 同一个 curl 200，且**走的是我们的 MITM**
//
// 全程不碰 hosts / 系统代理 / 注册表：用 storage 里的真 CA（已装进用户 Root 库）复制到临时目录，
// TLS 引擎听 127.0.0.2:8446，curl 用 `--resolve github.com:8446:127.0.0.2` 直连该端口。
//
// 用法：node test/live-crl.mjs [域名] [端口TLS] [端口代理]
import { Accelerator } from '../lib/accelerator.mjs';
import { mkdtempSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';

const DOMAIN = process.argv[2] || 'github.com';
const TLS_PORT = Number(process.argv[3] || 8446);
const PROXY_PORT = Number(process.argv[4] || 8846);
const STORAGE = join(homedir(), '.dsh', 'storages', 'dsh-accelerator');
const CURL = process.env.CURL || 'curl.exe';

let failures = 0;
function check(label, cond, detail) {
  if (!cond) failures += 1;
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${label}${detail ? ` —— ${detail}` : ''}`);
}

function run(file, args, timeout = 60_000) {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout, maxBuffer: 4 << 20 }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
    });
  });
}

async function curlThrough() {
  const started = Date.now();
  const r = await run(CURL, ['-sS', '--noproxy', '*', '-m', '50', '--resolve', `${DOMAIN}:${TLS_PORT}:127.0.0.2`, '-o', 'NUL', '-w', '%{http_code} %{time_total}s', `https://${DOMAIN}:${TLS_PORT}/`]);
  const text = `${r.stdout}${r.stderr}`.trim();
  const code = /^(\d{3})\s/.exec(text)?.[1] ?? null;
  return {
    ok: code !== null && code !== '000',
    code,
    ms: Date.now() - started,
    // 叶证书没有 CDP 时是 CRYPT_E_NO_REVOCATION_CHECK (0x80092012)；
    // 有 CDP 但取不到 CRL 时是 CRYPT_E_REVOCATION_OFFLINE (0x80092013)。两者都算「被吊销检查挡住」。
    revocationError: /CRYPT_E_(NO_REVOCATION_CHECK|REVOCATION_OFFLINE)|0x8009201[23]/i.test(text),
    tail: text.split(/\r?\n/).filter(Boolean).slice(-1)[0]?.slice(0, 200) ?? '',
  };
}

const dir = mkdtempSync(join(tmpdir(), 'dsh-acc-crl-'));
console.log(`临时实例目录 ${dir}\n（用 storage 里已装进 Root 库的 CA 复制过来，所以 curl 能信任链）`);
for (const f of ['ca.pem', 'ca.key', 'nodes.json']) {
  const src = join(STORAGE, f);
  if (existsSync(src)) copyFileSync(src, join(dir, f));
}

const acc = new Accelerator({ dir, logger: { info: () => {}, warn: console.warn, error: console.error } });
await acc.init();
await acc.updateConfig({
  enabled: false, autoStart: false, smart: false, takeover: 'hosts',
  listenHost: '127.0.0.2', listenPort: TLS_PORT,
  proxyHost: '127.0.0.2', proxyPort: PROXY_PORT,
  installCaOnEnable: false, relaxRevocationCheck: false,
});

console.log(`CDP 地址 = ${acc.crlUrl()}`);
check('叶证书 DER 里带上了当前 CDP 地址', Buffer.from(acc.leaf.certPem, 'base64').length >= 0 && acc.crlDer !== null, `CRL ${acc.crlDer ? acc.crlDer.length : 0} 字节`);
check('CRL 已落盘并有 nextUpdate', Boolean(acc.crlMeta?.nextUpdate), `${acc.crlMeta?.nextUpdate}`);

await acc.engine.start();
console.log(`TLS 引擎已在 127.0.0.2:${TLS_PORT} 监听\n`);

try {
  // A) 只起 TLS：CDP 取不到 CRL。SKIP_A=1 时跳过 —— CryptoAPI 会把「吊销状态取不到」按 URL 缓存
  //    一小段时间，跳过 A 是为了区分「协议不对」和「上一次失败的缓存」。
  if (process.env.SKIP_A !== '1') {
    const a = await curlThrough();
    console.log(`A) CDP 取不到（代理没起）→ code=${a.code} ${a.ms}ms  revocationError=${a.revocationError}`);
    console.log(`   ${a.tail}`);
    check('A) curl 被吊销检查挡住（CRYPT_E_NO_REVOCATION_CHECK / CRYPT_E_REVOCATION_OFFLINE）', a.ok === false && a.revocationError, `code=${a.code}`);
  } else {
    console.log('A) 已按 SKIP_A=1 跳过（代理先起，避免内置吊销缓存干扰）');
  }

  // B) 起代理：CDP 能取到 CRL
  await acc.engine.startProxy();
  const crlRes = await fetch(`http://127.0.0.2:${PROXY_PORT}/dsh-accelerator.crl`).catch((e) => ({ error: e }));
  const crlBuf = crlRes && !crlRes.error ? Buffer.from(await crlRes.arrayBuffer()) : Buffer.alloc(0);
  console.log(`\nB) 代理已起 → GET /dsh-accelerator.crl = ${crlRes.status ?? String(crlRes.error)} ${crlRes.headers?.get?.('content-type') ?? ''} ${crlBuf.length} 字节`);
  check('CRL 端点返回 200 且是 application/pkix-crl', crlRes.status === 200 && /pkix-crl/.test(String(crlRes.headers?.get?.('content-type'))), `${crlBuf.length} 字节`);
  check('取到的 CRL 与我们签发的一致', crlBuf.equals(acc.crlDer));

  const b = await curlThrough();
  console.log(`   同一个 curl → code=${b.code} ${b.ms}ms`);
  console.log(`   ${b.tail}`);
  check('B) 同一个 curl 现在 200（Schannel 接受了带 CDP 的叶证书）', b.ok === true, `code=${b.code} ${b.ms}ms`);
} finally {
  await acc.engine.stop().catch(() => {});
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows 上偶发占用 */ }
  console.log(`\n已关停引擎并清理临时目录`);
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
