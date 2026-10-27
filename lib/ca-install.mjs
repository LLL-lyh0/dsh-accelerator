// 根证书的安装 / 卸载 / 检测 —— 全部走 certutil，**不需要管理员权限**。
//
// 实测（`preflight.mjs`）：`certutil -addstore -user -f Root <cer>` 在标准用户下成功，
// 证书进 `Cert:\CurrentUser\Root`；删除同理 `certutil -delstore -user Root <name>`。
//
// 与本机 Watt Toolkit 的差别：它的根证书 `HasPrivateKey=True` 且私钥能导出，
// 任何同用户进程都能拿它伪造任意网站。我们**只把公钥证书装进存储**，
// 私钥始终留在 storages 目录（可自行加密），装的是 CA 不是「带私钥的密钥对」。

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';

const CERTUTIL = 'certutil.exe';

function run(args) {
  return new Promise((resolve) => {
    execFile(CERTUTIL, args, { windowsHide: true, maxBuffer: 8 << 20 }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
    });
  });
}

/**
 * 安装 CA 到当前用户 Root 存储。
 * @param {string} cerPath DER 文件路径
 * @param {string} subjectCN 用于事后核对
 */
export async function installCa(cerPath, subjectCN) {
  const r = await run(['-addstore', '-user', '-f', 'Root', cerPath]);
  const ok = r.code === 0 && (r.stdout.includes('成功') || /success/i.test(r.stdout));
  const present = await isCaInstalled(subjectCN);
  return { ok: ok || present, code: r.code, output: (r.stdout + r.stderr).trim(), present };
}

/** 从当前用户 Root 存储移除 CA（按 subject 名匹配）。 */
export async function uninstallCa(subjectCN) {
  const r = await run(['-delstore', '-user', 'Root', subjectCN]);
  const present = await isCaInstalled(subjectCN);
  return { ok: !present, code: r.code, output: (r.stdout + r.stderr).trim(), present };
}

/** 枚举 CurrentUser\Root，判断某个 subject 是否已装。 */
export async function isCaInstalled(subjectCN) {
  const r = await run(['-user', '-store', 'Root']);
  if (r.code !== 0) return false;
  // 输出里形如「颁发者: CN=DSH Accelerator Root CA, O=DSH Accelerator」
  const needle = subjectCN.toLowerCase();
  return r.stdout.toLowerCase().includes(needle);
}

/**
 * 检查已安装的那张证书的指纹是否**就是**我们当前这把 —— 不匹配说明装的是旧的、
 * 或者被别人替换过，必须重装（否则浏览器会拿旧根去验新叶证书，必然失败）。
 */
/**
 * 枚举「已安装的根证书指纹」。
 *
 * **为什么不解析 certutil 输出**：`certutil -user -store Root` 的汇总列表只印 subject/issuer，
 * 不印指纹；而且输出是本地化编码（本机 GBK），按行抓 40 位十六进制会一个都抓不到 ——
 * 实测后果是「明明装的就是当前这张 CA，却被判成指纹不匹配」，进而触发无意义的重装。
 * Windows 证书存储就在注册表里，**子键名本身就是 SHA-1 指纹**，这是精确且与语言无关的来源。
 *
 * 返回的是当前用户 Root 存储里的**全部**根证书指纹；判断「我们这张在不在」用 includes。
 */
async function rootThumbprintsFromRegistry() {
  const r = await new Promise((resolve) => {
    execFile('reg.exe',
      ['query', 'HKCU\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates'],
      { windowsHide: true, maxBuffer: 8 << 20 },
      (err, stdout) => resolve(String(stdout ?? '')));
  });
  const out = [];
  for (const line of r.split(/\r?\n/)) {
    const m = /([0-9a-fA-F]{40})\s*$/.exec(line.trim());
    if (m) out.push(m[1].toUpperCase());
  }
  return out;
}

export async function installedThumbprints(subjectCN) {
  const fromRegistry = await rootThumbprintsFromRegistry().catch(() => []);
  if (fromRegistry.length > 0) return fromRegistry;
  // 注册表读不到才退回 certutil（仅作为兜底，可能因本地化输出而抓不到）。
  const r = await run(['-user', '-store', 'Root']);
  if (r.code !== 0) return [];
  const out = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    if (subjectCN && !line.toLowerCase().includes(subjectCN.toLowerCase())) continue;
    const m = /([0-9a-fA-F]{40})/.exec(line);
    if (m) out.push(m[1].toUpperCase());
  }
  return out;
}

/** 这张 DER 的 SHA-1 指纹，同时也是它在注册表存储里的子键名。 */
export async function rootThumbprints() {
  return rootThumbprintsFromRegistry();
}

/** 这条 DER 的 SHA1 指纹（与 certutil / Windows 存储一致）。 */
export function thumbprintOf(der) {
  return crypto.createHash('sha1').update(der).digest('hex').toUpperCase();
}

export const CA_SUBJECT_CN = 'DSH Accelerator Root CA';
