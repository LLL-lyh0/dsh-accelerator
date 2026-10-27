// 系统代理（PAC / 固定代理）接管：改 HKCU 的 Internet Settings，不需要管理员。
//
// 为什么需要这条路：hosts 被别家提权加速器改成只读之后，「把域名引到本机」就做不到了
// （实测 Steamcommunity_302 会把 hosts 的 ACL 收成 Users:(RX)，并删掉我们段里重叠的行）。
// 而 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 是**每用户可写**的，
// 于是改用 PAC：只把受管域名指到本机代理，其余一律 DIRECT，不改变整机其它流量的走向。
//
// 所有注册表写操作都**先快照后修改**：stop() 时逐值还原（原值不存在就删掉），
// 不留「用户原来的代理设置被吃掉了」这种脏状态。
//
// 只认 ASCII 的解析：中文版 Windows 的 reg.exe 输出是 GBK，Node 按 UTF-8 解会变乱码，
// 所以任何判断都只依赖值名 / 类型名（ProxyEnable / REG_DWORD / REG_SZ）这些 ASCII 片段。

import { execFile } from 'node:child_process';

export const REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
export const MANAGED_VALUES = ['ProxyEnable', 'ProxyServer', 'AutoConfigURL', 'ProxyOverride'];

/** reg.exe 包一层 Promise（永不 reject —— 调用方按「拿没拿到值」处理）。 */
function reg(args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile('reg.exe', args, { windowsHide: true, timeout, maxBuffer: 1 << 20 }, (error, stdout) => {
      resolve({ error, stdout: String(stdout ?? '') });
    });
  });
}

/**
 * 解析 `reg query` 的输出。纯函数，便于离线断言。
 * 输入形如：
 *     ProxyEnable    REG_DWORD    0x1
 *     ProxyServer    REG_SZ    127.0.0.1:10808
 * 返回 `{ ProxyEnable: { type: 'REG_DWORD', value: 1, raw: '0x1' }, ... }`（找不到的值不出现）。
 */
export function parseRegistryQuery(text) {
  const out = {};
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(REG_[A-Z_]+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const [, name, type, rest] = m;
    const raw = rest.trim();
    if (type === 'REG_DWORD') {
      const n = /^0x([0-9a-fA-F]+)$/.exec(raw);
      out[name] = { type, value: n ? Number.parseInt(n[1], 16) : Number.parseInt(raw, 10), raw };
    } else if (type === 'REG_SZ' || type === 'REG_EXPAND_SZ') {
      if (raw === '') continue;              // 空值等于没设，别记为「原来是这样」
      out[name] = { type: 'REG_SZ', value: raw, raw };
    } else {
      out[name] = { type, value: raw, raw };
    }
  }
  return out;
}

/** 当前系统代理设置快照。 */
export async function readSettings() {
  const { stdout } = await reg(['query', REG_KEY]);
  const all = parseRegistryQuery(stdout);
  const snapshot = {};
  for (const name of MANAGED_VALUES) if (all[name]) snapshot[name] = all[name];
  return snapshot;
}

/** PAC 地址（本机代理自己会服务这个路径，见 lib/proxy.mjs）。 */
export function pacUrlFor(proxyHost, proxyPort) {
  const host = proxyHost === '0.0.0.0' || proxyHost === '::' ? '127.0.0.1' : proxyHost;
  return `http://${host}:${proxyPort}/proxy.pac`;
}

/** 把受管域名编译成 PAC 的判断项（纯函数）。 */
export function pacRules(domains) {
  const exact = [];
  const suffixes = [];
  for (const raw of domains ?? []) {
    const d = String(raw ?? '').trim().toLowerCase();
    if (d === '') continue;
    if (d.startsWith('*.')) suffixes.push(d.slice(1));   // '*.github.com' → '.github.com'
    else exact.push(d);
  }
  return { exact: [...new Set(exact)].sort(), suffixes: [...new Set(suffixes)].sort() };
}

/**
 * 生成 PAC 脚本。纯函数：domains × proxy → 文本。
 * 只命中受管域名，其余 DIRECT（这样不会把整机流量都拖进本机代理）。
 */
export function buildPac(domains, proxyHost, proxyPort) {
  const { exact, suffixes } = pacRules(domains);
  const proxy = `PROXY ${proxyHost === '0.0.0.0' ? '127.0.0.1' : proxyHost}:${proxyPort}; DIRECT`;
  const exactList = exact.map((d) => `  "${d}"`).join(',\n');
  const suffixList = suffixes.map((d) => `  "${d}"`).join(',\n');
  return `// dsh-accelerator PAC —— 只把受管域名交给本机加速器，其余 DIRECT。
// 生成时间 ${new Date().toISOString()}
var DSH_EXACT = [
${exactList}
];
var DSH_SUFFIX = [
${suffixList}
];
var DSH_PROXY = ${JSON.stringify(proxy)};

function FindProxyForURL(url, host) {
  host = String(host || '').toLowerCase();
  if (host === '') return 'DIRECT';
  for (var i = 0; i < DSH_EXACT.length; i++) {
    if (host === DSH_EXACT[i]) return DSH_PROXY;
  }
  for (var j = 0; j < DSH_SUFFIX.length; j++) {
    var s = DSH_SUFFIX[j];
    if (host.length > s.length && host.slice(-s.length) === s) return DSH_PROXY;
  }
  return 'DIRECT';
}
`;
}

async function setValue(name, type, value) {
  await reg(['add', REG_KEY, '/v', name, '/t', type, '/d', String(value), '/f']);
}

async function deleteValue(name) {
  await reg(['delete', REG_KEY, '/v', name, '/f']);
}

/**
 * Schannel / WinINET 的吊销检查开关（每用户可写，不需要管理员）。
 *
 * 为什么必须动它：我们的叶证书是本地 CA 现签的，**没有 CRL / OCSP 分发点**，
 * 而 Schannel 默认要求「能确认吊销状态」。实测（本机 2026-10-27）：
 *   curl.exe   → `curl: (35) schannel: ... CRYPT_E_NO_REVOCATION_CHECK (0x80092012)`
 *   git ls-remote（schannel 后端）→ `schannel: next InitializeSecurityContext failed: CRYPT_E_NO_REVOCATION_CHECK`
 *   PowerShell/WinHTTP 系同源；而 Chrome/Edge（BoringSSL）与 Node（自带 OpenSSL）不受影响 ——
 *   这就是「浏览器能开、curl/git 报证书错」的根因，不是证书链没签对。
 * 把手设为 0 之后，同一台机器上 `curl.exe https://github.com/` 立刻 200（实测 21.3s）。
 *
 * stop() 时按快照还原（原本没有这个值就删掉），不留全局副作用。
 */
export const REVOCATION_VALUE = 'CertificateRevocation';

/** 读当前吊销检查开关（没设过返回 null）。 */
export async function readRevocation() {
  const { stdout } = await reg(['query', REG_KEY, '/v', REVOCATION_VALUE]);
  const parsed = parseRegistryQuery(stdout);
  return parsed[REVOCATION_VALUE] ?? null;
}

/** 接管期间关闭吊销检查。返回 `{ok, changed, saved, warnings}`，`saved` 交给 stop() 还原。 */
export async function disableRevocation() {
  const saved = await readRevocation();
  const warnings = [];
  if (saved && Number(saved.value) === 0) return { ok: true, changed: false, saved: null, warnings };
  await setValue(REVOCATION_VALUE, 'REG_DWORD', 0);
  const after = await readRevocation();
  if (!after || Number(after.value) !== 0) warnings.push('CertificateRevocation 写入 0 后回读不一致');
  return { ok: warnings.length === 0, changed: true, saved, warnings };
}

/** 还原吊销检查开关：`saved` 为 null 表示原本没设过 → 删掉这个值。 */
export async function restoreRevocation(saved) {
  const warnings = [];
  if (saved && saved.value !== undefined) await setValue(REVOCATION_VALUE, saved.type || 'REG_DWORD', saved.value);
  else await deleteValue(REVOCATION_VALUE);
  const after = await readRevocation();
  const want = saved && saved.value !== undefined ? Number(saved.value) : null;
  const got = after ? Number(after.value) : null;
  if (want !== got) warnings.push(`CertificateRevocation 还原后为 ${got}，期望 ${want}`);
  return { ok: warnings.length === 0, warnings };
}

/**
 * 应用 PAC 接管。
 * @returns {{ok: boolean, mode: 'pac', url: string, saved: object, warnings: string[]}}
 */
export async function applyPac(pacUrl) {
  const warnings = [];
  const saved = await readSettings();
  await setValue('AutoConfigURL', 'REG_SZ', pacUrl);
  // PAC 优先于固定代理，但把 ProxyEnable 归零能避免「旧固定代理仍在某些程序里生效」的双重代理。
  await setValue('ProxyEnable', 'REG_DWORD', 0);
  await refreshWinInet().catch((e) => warnings.push(`WinINET 刷新失败（重启浏览器即可）：${e.message}`));
  const now = await readSettings();
  return {
    ok: now.AutoConfigURL?.value === pacUrl,
    mode: 'pac',
    url: pacUrl,
    saved,
    applied: now,
    warnings,
  };
}

/** 应用固定代理（`host:port`，HTTP + HTTPS 都走它）。 */
export async function applyFixed(server) {
  const warnings = [];
  const saved = await readSettings();
  await setValue('ProxyServer', 'REG_SZ', server);
  await setValue('ProxyEnable', 'REG_DWORD', 1);
  await deleteValue('AutoConfigURL');
  await refreshWinInet().catch((e) => warnings.push(`WinINET 刷新失败（重启浏览器即可）：${e.message}`));
  const now = await readSettings();
  return {
    ok: now.ProxyEnable?.value === 1 && now.ProxyServer?.value === server,
    mode: 'fixed',
    url: server,
    saved,
    applied: now,
    warnings,
  };
}

/**
 * 还原到快照状态：快照里有的值写回去，快照里没有的值删掉。
 * @param {object} saved readSettings() 的结果
 */
export async function restore(saved) {
  const warnings = [];
  const snap = saved && typeof saved === 'object' ? saved : {};
  for (const name of MANAGED_VALUES) {
    const entry = snap[name];
    if (entry && entry.value !== undefined && entry.value !== null) {
      await setValue(name, entry.type === 'REG_EXPAND_SZ' ? 'REG_EXPAND_SZ' : entry.type, entry.value);
    } else {
      await deleteValue(name);
    }
  }
  await refreshWinInet().catch((e) => warnings.push(`WinINET 刷新失败：${e.message}`));
  const now = await readSettings();
  const same = MANAGED_VALUES.every((name) => {
    const a = snap[name]?.value;
    const b = now[name]?.value;
    return String(a ?? '') === String(b ?? '');
  });
  return { ok: same, restored: now, warnings };
}

/**
 * 通知 WinINET 设置变了（InternetSetOption SETTINGS_CHANGED / REFRESH）。
 * 不刷新的话新设置有时要等重启浏览器才生效。失败只记 warning —— 这不是正确性的必要条件。
 */
export function refreshWinInet() {
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -Namespace DshAcc -Name WinInet -MemberDefinition '[DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int opt, IntPtr buf, int len);'",
    '[void][DshAcc.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)',
    '[void][DshAcc.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)',
    "Write-Output 'refreshed'",
  ].join('; ');
  return new Promise((resolve, reject) => {
    // 优先 pwsh（PowerShell 7），退到 Windows 自带的 powershell.exe（5.1）—— 两者都能 P/Invoke。
    // 之前只试 pwsh.exe，在只有 powershell.exe 的机器上会 `spawn pwsh.exe ENOENT`。
    const attempt = (exe) => execFile(exe, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 15000 }, (error, stdout) => {
      if (error) {
        if (error.code === 'ENOENT' && exe !== 'powershell.exe') { attempt('powershell.exe'); return; }
        reject(new Error(String(error.message).slice(0, 200)));
        return;
      }
      resolve(String(stdout ?? '').trim());
    });
    attempt('pwsh.exe');
  });
}

/** 当前是否已经指着我们的 PAC / 固定代理（用于 status，不写任何东西）。 */
export async function currentTakeover(proxyHost, proxyPort) {
  let settings = {};
  try { settings = await readSettings(); } catch { /* 读不到就当没有 */ }
  const wantPac = pacUrlFor(proxyHost, proxyPort);
  const fixed = `${proxyHost}:${proxyPort}`;
  const pacActive = settings.AutoConfigURL?.value === wantPac;
  const fixedActive = settings.ProxyEnable?.value === 1 && settings.ProxyServer?.value === fixed;
  return {
    pacActive,
    fixedActive,
    active: pacActive || fixedActive,
    autoConfigURL: settings.AutoConfigURL?.value ?? null,
    proxyEnable: settings.ProxyEnable?.value ?? 0,
    proxyServer: settings.ProxyServer?.value ?? null,
    pacUrl: wantPac,
  };
}

/**
 * **只清掉「确实是我们的」那几项**系统代理设置，别家留下的值一个都不碰。
 *
 * 为什么需要它：切回 `hosts` 接管后我们不再监听代理端口，但如果注册表里还留着上一轮
 * （可能是上一个 DSH 进程写的，快照已随进程消失）的 `AutoConfigURL = http://127.0.0.2:8843/proxy.pac`，
 * 认系统代理的程序就会去连一个没人听的端口。`restore({})` 不能用于这个场景 —— 它会把
 * `ProxyOverride`、别家写的 `ProxyServer` 一并删掉。
 *
 * @returns {Promise<{ok: boolean, cleared: string[], settings: object, warnings: string[], active: boolean}>}
 */
export async function clearOurTakeover(proxyHost, proxyPort) {
  const warnings = [];
  const wantPac = pacUrlFor(proxyHost, proxyPort);
  const fixed = `${proxyHost}:${proxyPort}`;
  let settings = {};
  try { settings = await readSettings(); } catch (e) { warnings.push(`读注册表失败：${e.message}`); }

  const cleared = [];
  if (settings.AutoConfigURL?.value === wantPac) {
    await deleteValue('AutoConfigURL');
    cleared.push('AutoConfigURL');
  }
  if (settings.ProxyEnable?.value === 1 && settings.ProxyServer?.value === fixed) {
    await deleteValue('ProxyServer');
    await deleteValue('ProxyEnable');
    cleared.push('ProxyEnable', 'ProxyServer');
  }
  if (cleared.length === 0) {
    return { ok: true, cleared, settings, warnings, active: false };
  }
  await refreshWinInet().catch((e) => warnings.push(`WinINET 刷新失败：${e.message}`));
  const now = await readSettings();
  const stillPac = now.AutoConfigURL?.value === wantPac;
  const stillFixed = now.ProxyEnable?.value === 1 && now.ProxyServer?.value === fixed;
  if (stillPac) warnings.push('AutoConfigURL 未能清除');
  if (stillFixed) warnings.push('ProxyServer/ProxyEnable 未能清除');
  return { ok: !stillPac && !stillFixed, cleared, settings: now, warnings, active: stillPac || stillFixed };
}
