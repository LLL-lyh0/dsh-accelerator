// 活体验收：真的用 PAC 接管一次系统代理，验证全链路，然后**必定还原**。
//
// 为什么必须是一个独立脚本：PAC 接管会改 HKCU 的 AutoConfigURL（真的动用户的系统代理设置）。
// 所以这个脚本：
//   - 开头打印接管前的快照（可核对）；
//   - start() 用 takeover:'pac'，断言注册表真的写进去了；
//   - 抓一次 PAC、走一次 CONNECT（受管域名要被 MITM，非受管域名要盲隧道）；
//   - finally 里 stop()，再**回读注册表确认已还原**，否则以非零码退出并打印可手工执行的修复命令。
//
// 用法：node test/live-takeover.mjs
// 注意：需要 127.0.0.2:8445（TLS）与 127.0.0.2:8845（代理）空闲 —— 刻意避开插件默认的 443/8843，
//       这样即使 DSH 里的加速器正开着，验收也能独立跑完。

import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Accelerator } from '../lib/accelerator.mjs';
import { readSettings, currentTakeover, restore as restoreProxy, applyPac, clearOurTakeover } from '../lib/system-proxy.mjs';

const CHILD = fileURLToPath(new URL('./proxy-client-child.mjs', import.meta.url));
// 端口刻意与插件的默认值（TLS 443 / 代理 8843）错开：验收脚本要能在
// 「DSH 里的加速器正开着」的情况下也跑得动，不抢它的监听端口。
const PROXY_PORT = 8845;
const TLS_PORT = 8445;

let fail = 0;
function check(name, good, detail) {
  console.log(`${good ? '  ✓' : '  ✗'} ${name}${detail === undefined ? '' : `  ${detail}`}`);
  if (!good) fail += 1;
}
function child(port, host, caFile) {
  return new Promise((resolve) => {
    const args = [CHILD, String(port), host];
    if (caFile) args.push(host, caFile);
    execFile(process.execPath, args, { timeout: 30_000 }, (err, stdout) => {
      const line = String(stdout || '').trim().split('\n').pop();
      try { resolve(JSON.parse(line)); } catch { resolve({ ok: false, why: `child:${err ? err.message : 'no-output'}` }); }
    });
  });
}
function fetchPac() {
  return new Promise((resolve) => {
    http.get({ host: '127.0.0.2', port: PROXY_PORT, path: '/proxy.pac', timeout: 5000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], body }));
    }).on('error', (e) => resolve({ status: 0, body: String(e.message) })).on('timeout', function () { this.destroy(); resolve({ status: 0, body: 'timeout' }); });
  });
}

const before = await readSettings();
console.log(`接管前快照: ${JSON.stringify(before)}\n`);

const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-acc-live-takeover-'));
const acc = new Accelerator({ dir: tmp, logger: { info: () => {}, warn: (...a) => console.log('  warn', ...a), error: (...a) => console.log('  error', ...a) } });
let stopped = false;
try {
  await acc.init();
  await acc.updateConfig({
    enabled: false, autoStart: false, smart: false,
    listenHost: '127.0.0.2', listenPort: TLS_PORT,
    proxyHost: '127.0.0.2', proxyPort: PROXY_PORT,
    takeover: 'pac', installCaOnEnable: false,
  });
  const started = await acc.start();
  const portCheck = (started.checks || []).find((c) => c.id === 'port');
  const proxyCheck = (started.checks || []).find((c) => c.id === 'proxy');
  check('start() 成功', started.ok === true, JSON.stringify(started.checks || []));
  check('TLS 监听起来了', Boolean(portCheck && portCheck.ok), portCheck && portCheck.detail);
  check('代理检查通过（PAC 已写入系统）', Boolean(proxyCheck && proxyCheck.ok), proxyCheck && proxyCheck.detail);

  const st = await acc.status();
  check('status().proxy.effective === "pac"', st.proxy.effective === 'pac', JSON.stringify(st.proxy));
  check('代理监听中', st.proxy.listening === true, String(st.proxy.listen));

  const reg = await currentTakeover('127.0.0.2', PROXY_PORT);
  check('注册表 AutoConfigURL 指向我们的 PAC', reg.autoConfigURL === st.proxy.pacUrl, String(reg.autoConfigURL));
  check('PAC 模式下 ProxyEnable 保持 0（不动固定代理）', Number(reg.proxyEnable) === 0, String(reg.proxyEnable));
  check('currentTakeover() 认出 pacActive', reg.pacActive === true, JSON.stringify(reg));

  const pac = await fetchPac();
  check('PAC 端点 200 + autoconfig', pac.status === 200 && String(pac.type).includes('proxy-autoconfig'), `${pac.status} ${pac.type}`);
  check('PAC 正文含 FindProxyForURL 与受管域名', /FindProxyForURL/.test(pac.body) && /github\.com/.test(pac.body));

  // 受管域名：把**这个实例自己生成的 CA** 交给子进程当信任锚（rejectUnauthorized:true）。
  // 这比「靠系统库验过」更硬 —— 它证明叶证书确实由该 CA 签发、链是通的，
  // 而不会被「这台机器上恰好装过别的 CA」蒙过去。
  const managed = await child(PROXY_PORT, 'github.com', path.join(tmp, 'ca.pem'));
  check('受管域名经 CONNECT 被 MITM 且证书链可用我们的 CA 验过', managed.ok === true && managed.authorized === true && String(managed.peerCN).includes('DSH'), JSON.stringify(managed));

  const other = await child(PROXY_PORT, 'www.baidu.com');
  check('非受管域名走盲隧道（没被解密）', other.ok === true && !String(other.peerCN).includes('DSH'), JSON.stringify(other));

  // 切回 hosts 模式时的「残留清理」路径：我们不再监听代理端口，就必须把**我们写的**
  // PAC 清掉，否则认系统代理的程序会被指到一个没人听的端口。
  // 同时必须证明：别家留下的 ProxyServer / ProxyOverride 一个字节都不动。
  await applyPac(st.proxy.pacUrl);
  const cleared = await clearOurTakeover('127.0.0.2', PROXY_PORT);
  const afterClear = await readSettings();
  const regAfter = await currentTakeover('127.0.0.2', PROXY_PORT);
  check('clearOurTakeover 清掉了我们写的 AutoConfigURL', cleared.cleared.includes('AutoConfigURL'), JSON.stringify(cleared));
  check('清理后 pacActive 变 false', regAfter.pacActive === false, JSON.stringify(regAfter));
  check(
    '清理不碰别家的 ProxyServer / ProxyOverride',
    String(afterClear.ProxyServer ?? '') === String(before.ProxyServer ?? '')
      && String(afterClear.ProxyOverride ?? '') === String(before.ProxyOverride ?? ''),
    JSON.stringify({ before, afterClear }),
  );
} finally {
  try {
    await acc.stop();
    stopped = true;
  } catch (error) {
    console.log(`  ! acc.stop() 抛错：${error && error.message}`);
  }
  if (!stopped) {
    // stop() 没走完时，用快照硬还原一次，绝不把用户的系统代理留在我们的 PAC 上。
    const forced = await restoreProxy(before);
    console.log(`  ! 用快照强制还原：${JSON.stringify(forced)}`);
  }
  await fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
}

const after = await readSettings();
check('stop() 后 AutoConfigURL 已还原', String(after.AutoConfigURL ?? '') === String(before.AutoConfigURL ?? ''), JSON.stringify(after));
check('stop() 后 ProxyEnable 已还原', String(after.ProxyEnable ?? '') === String(before.ProxyEnable ?? ''), JSON.stringify(after));
const stillOpen = await fetchPac();
check('stop() 后代理端口已关闭', stillOpen.status === 0, String(stillOpen.body));

if (fail > 0) {
  console.log('\n若系统代理没还原，手工执行（管理员或当前用户均可）：');
  console.log('  reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoConfigURL /t REG_SZ /d "" /f');
  console.log('  reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoConfigURL /f');
}
console.log(`\n${fail === 0 ? 'ALL PASS' : `${fail} FAILED`}`);
process.exit(fail === 0 ? 0 : 1);
