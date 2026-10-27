// 活体验收：Schannel 吊销检查开关（CertificateRevocation）。
//
// 背景（本机 2026-10-27 实测）：
//   我们给受管域名签的叶证书**没有 CRL / OCSP 分发点**，而 Windows Schannel 默认要求
//   「能确认吊销状态」。于是 curl.exe / git(schannel 后端) / WinHTTP 系客户端会在握手阶段
//   直接失败：`CRYPT_E_NO_REVOCATION_CHECK (0x80092012)`，而 Chrome/Edge(BoringSSL)、
//   Node(自带 OpenSSL) 完全不受影响 —— 这就是「浏览器能开、命令行报证书错」的根因。
//
// 本脚本用**因果对照**证明这件事，并证明我们的修法（接管期间把
// `HKCU\...\Internet Settings\CertificateRevocation` 置 0）真的解决了它：
//   A) 原样            → curl 失败，错误里带 CRYPT_E_NO_REVOCATION_CHECK
//   B) disableRevocation() → 同一个 curl 成功（走的是本机加速器的 MITM 叶证书）
//   C) restoreRevocation() → 失败复现，注册表值回到原样
//
// 全程只动 CertificateRevocation 一个值，且**必定还原**（失败也会在 finally 里还原）。
// 用法：node test/live-revocation.mjs [curlTarget]
import { readRevocation, disableRevocation, restoreRevocation } from '../lib/system-proxy.mjs';
import { execFile } from 'node:child_process';

const CURL = process.env.CURL || 'curl.exe';
const TARGET = process.argv[2] || 'https://github.com/';
const CURL_TIMEOUT_MS = 45_000;

function run(file, args, timeout = CURL_TIMEOUT_MS) {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout, maxBuffer: 4 << 20 }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
    });
  });
}

/** 裸跑 curl：不吃环境代理，禁用 curl 自己的证书库之外的任何特殊开关。 */
async function curlOnce(url) {
  const started = Date.now();
  const r = await run(CURL, ['-sS', '--noproxy', '*', '-m', '40', '-o', process.platform === 'win32' ? 'NUL' : '/dev/null', '-w', '%{http_code} %{time_total}s', url]);
  const text = `${r.stdout}${r.stderr}`.trim();
  const code = /^(\d{3})\s/.exec(text)?.[1] ?? null;
  return {
    ok: !r.error && code !== null && code !== '000',
    code,
    ms: Date.now() - started,
    noRevocationCheck: /CRYPT_E_NO_REVOCATION_CHECK|0x80092012|吊销/i.test(text),
    tail: text.split(/\r?\n/).filter(Boolean).slice(-2).join(' | ').slice(0, 220),
  };
}

let failures = 0;
function check(label, cond, detail) {
  const mark = cond ? 'PASS' : 'FAIL';
  if (!cond) failures += 1;
  console.log(`[${mark}] ${label}${detail ? ` —— ${detail}` : ''}`);
}

const before = await readRevocation();
console.log(`CertificateRevocation 原值 = ${before ? before.value : '(不存在)'}`);
console.log(`目标 = ${TARGET}\n`);

let saved = null;
let restored = false;
try {
  // A) 原样（吊销检查开着）
  const a = await curlOnce(TARGET);
  console.log(`A) 原样        → code=${a.code} ${a.ms}ms  noRevocationCheck=${a.noRevocationCheck}`);
  console.log(`   ${a.tail}`);
  check('A) 吊销检查开着时 curl 被拒（且原因是 CRYPT_E_NO_REVOCATION_CHECK）', a.ok === false && a.noRevocationCheck, `code=${a.code}`);

  // B) 接管期间关闭吊销检查
  const off = await disableRevocation();
  saved = off.saved;
  console.log(`\nB) disableRevocation → changed=${off.changed} saved=${JSON.stringify(saved)} warnings=${JSON.stringify(off.warnings)}`);
  const b = await curlOnce(TARGET);
  console.log(`   同一个 curl  → code=${b.code} ${b.ms}ms`);
  console.log(`   ${b.tail}`);
  check('B) 关掉吊销检查后同一个 curl 成功（证明 MITM 链路本身是好的）', b.ok === true, `code=${b.code} ${b.ms}ms`);
} finally {
  // C) 还原
  const r = await restoreRevocation(saved);
  restored = true;
  const after = await readRevocation();
  console.log(`\nC) restoreRevocation → ok=${r.ok} warnings=${JSON.stringify(r.warnings)}`);
  console.log(`   还原后 CertificateRevocation = ${after ? after.value : '(不存在)'}（原值 ${before ? before.value : '不存在'}）`);
  check('C) 注册表值已还原', (after ? after.value : null) === (before ? before.value : null));
  const c = await curlOnce(TARGET);
  console.log(`   还原后同一个 curl → code=${c.code} ${c.ms}ms  noRevocationCheck=${c.noRevocationCheck}`);
  check('C) 还原后失败复现（因果成立，不是巧合）', c.ok === false && c.noRevocationCheck, `code=${c.code}`);
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}（restored=${restored}）`);
process.exit(failures === 0 ? 0 : 1);
