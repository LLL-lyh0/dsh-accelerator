// DoH 解析 + 本机进程归属判定。
//
// 两件事都必须做对，否则整套东西会静默失效：
//  1) 上游解析**绝不能用系统 DNS** —— hosts 被加速器写成 127.0.0.1 时，代理会连回自己。
//  2) 「哪个进程发起的连接」只能靠 netstat 反查；Get-NetTCPConnection 单次 941ms，太慢。

import { execFile } from 'node:child_process';
import https from 'node:https';
import { DOH_ENDPOINTS } from './seed-nodes.mjs';

function requestJson(url, timeoutMs) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname);
    const req = https.request({
      hostname: u.hostname.startsWith('[') ? u.hostname.slice(1, -1) : u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: 'GET',
      // 直连 IP 时不能设 servername（RFC 6066 不允许给 IP 设 SNI，Node 会警告并忽略）
      ...(isIp ? {} : { servername: u.hostname }),
      headers: { accept: 'application/dns-json' },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { resolve(null); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

/**
 * 用 DoH 解析 A 记录。多个 DoH 端点并发，谁先给出非空答案用谁。
 * @param {string} host
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [opts]
 * @returns {Promise<string[]>}
 */
export async function resolveA(host, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 4000;
  const attempts = DOH_ENDPOINTS.map((ep) => {
    const url = `${ep}?name=${encodeURIComponent(host)}&type=A`;
    return requestJson(url, timeoutMs).then((json) => {
      if (!json || !Array.isArray(json.Answer)) return [];
      return json.Answer
        .filter((a) => a.type === 1 && typeof a.data === 'string')
        .map((a) => a.data)
        .filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !ip.startsWith('0.'));
    }).catch(() => []);
  });
  const results = await Promise.all(attempts);
  const merged = [];
  for (const list of results) for (const ip of list) if (!merged.includes(ip)) merged.push(ip);
  return merged;
}

// ── 进程归属 ─────────────────────────────────────────────────────────────────

const NETSTAT_RE = /^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$/;

let netstatCache = { at: 0, rows: [] };

function readNetstat() {
  return new Promise((resolve) => {
    execFile('netstat', ['-ano', '-p', 'tcp'], { windowsHide: true, maxBuffer: 8 << 20 }, (err, stdout) => {
      if (err) { resolve([]); return; }
      const rows = [];
      for (const line of String(stdout).split(/\r?\n/)) {
        const m = NETSTAT_RE.exec(line);
        if (!m) continue;
        rows.push({
          localIp: m[1], localPort: Number(m[2]),
          remoteIp: m[3], remotePort: Number(m[4]),
          state: m[5], pid: Number(m[6]),
        });
      }
      resolve(rows);
    });
  });
}

/**
 * 反查「连到本地 proxyPort 的那个客户端」是哪个 pid。
 *
 * 客户端（比如浏览器）会先连代理的 listenPort，此时 netstat 里有一条
 *   本地 clientPort → 远端 127.0.0.1:proxyPort
 * 的记录，它的 pid 就是发起方。缓存 500ms —— 一次握手一批连接，缓存能省掉绝大部分调用。
 *
 * @param {number} clientPort 客户端本地端口（= socket.remotePort）
 * @param {number} proxyPort  代理监听端口
 * @param {Map<number, string|null>} [pidNames]
 */
export async function attributePid(clientPort, proxyPort, pidNames) {
  const now = Date.now();
  if (now - netstatCache.at > 500) {
    netstatCache = { at: now, rows: await readNetstat() };
  }
  for (const row of netstatCache.rows) {
    if (row.localPort !== clientPort) continue;
    if (row.remotePort !== proxyPort) continue;
    if (!row.remoteIp.startsWith('127.')) continue;
    if (pidNames && !pidNames.has(row.pid)) pidNames.set(row.pid, null);
    return row.pid;
  }
  return null;
}

/** 批量取进程名（一条 PowerShell 调用搞定一批，别逐 pid 查）。 */
export function lookupProcessNames(pids) {
  const list = [...new Set(pids)].filter((p) => Number.isInteger(p) && p > 0);
  if (list.length === 0) return Promise.resolve(new Map());
  const filter = list.map((p) => `ProcessId=${p}`).join(' or ');
  const cmd = `Get-CimInstance Win32_Process -Filter "${filter}" | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress`;
  return new Promise((resolve) => {
    execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command', cmd], { windowsHide: true, maxBuffer: 8 << 20 }, (err, stdout) => {
      const map = new Map();
      if (!err) {
        try {
          const parsed = JSON.parse(String(stdout).trim() || '[]');
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          for (const p of arr) {
            if (!p || !p.ProcessId) continue;
            map.set(Number(p.ProcessId), {
              name: p.Name ?? null,
              path: p.ExecutablePath ?? null,   // 提权进程这里会是 null（已知限制）
            });
          }
        } catch { /* 解析失败就返回空，调用方按「未知进程」处理 */ }
      }
      resolve(map);
    });
  });
}
