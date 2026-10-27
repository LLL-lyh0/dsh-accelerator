// status() 形状冒烟：只读本机（hosts / 证书库都是只读查询），不启动引擎、不改任何状态。
//
// 存在的理由：宿主不会热重载 lib/*.mjs（要重启 DSH 才生效），所以新的状态字段
// 不能只靠"打开管理页看一眼"来验证。这里用临时目录构造一个 Accelerator，
// 手工塞进 config/nodes，然后断言 status() 的契约。

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Accelerator } from '../lib/accelerator.mjs';

let checks = 0;
const failures = [];
function ok(cond, label, extra) {
  checks += 1;
  if (cond) console.log(`  ✓ ${label}`);
  else { failures.push(label); console.log(`  ✗ ${label}${extra === undefined ? '' : ` → ${JSON.stringify(extra)}`}`); }
}

const dir = mkdtempSync(join(tmpdir(), 'dsh-acc-status-'));
const silent = { info() {}, warn() {}, error() {}, debug() {} };
const acc = new Accelerator({ dir, logger: silent });

// 手工注入状态：一个普通域名 + 一个通配域名（通配不该出现在 hosts 引导里）
acc.config = {
  enabled: true,
  autoStart: true,
  smart: true,
  smartIntervalMin: 15,
  listenHost: '127.0.0.2',
  listenPort: 443,
  installCaOnEnable: true,
  upstream: { mode: 'direct', host: '', port: 0, username: '', password: '' },
  enforce: [],
  bypass: [],
  domainGroups: {},
};
acc.nodes = {
  'github.com': [{ ip: '140.82.114.4', sni: 'real' }, { ip: '20.205.243.166', sni: 'none' }],
  '*.github.com': [{ ip: '140.82.114.6', sni: 'real' }],
};

try {
  const s = await acc.status();

  // 顶层契约
  ok(s.enabled === true, 'status.enabled 反映 config');
  ok(s.autoStart === true, 'status.autoStart 反映 config.autoStart');
  ok(s.listen === '127.0.0.2:443', 'status.listen 是 host:port', s.listen);
  ok(typeof s.listening === 'boolean', 'status.listening 是布尔（引擎没起时 false）', s.listening);
  ok(typeof s.ca.installed === 'boolean' && s.ca.subject === 'DSH Accelerator Root CA', 'status.ca 带 installed + subject', s.ca);
  ok(s.upstream && s.upstream.mode === 'direct', 'status.upstream 透传');

  // hosts 诊断（本机实测路径）
  ok(s.hosts && typeof s.hosts.writable === 'boolean', 'status.hosts.writable 是布尔（运行期探测）', s.hosts);
  ok(typeof s.hosts.entries === 'number' && typeof s.hosts.expected === 'number', 'status.hosts 带 entries/expected', s.hosts);
  ok(Array.isArray(s.hosts.missing), 'status.hosts.missing 是数组', s.hosts.missing);
  ok(typeof s.hosts.active === 'boolean', 'status.hosts.active 保留', s.hosts.active);
  // 通配域名不该被算进 hosts 引导（写 hosts 只认具体域名）
  ok(s.hosts.expected === 1, 'expected 只数具体域名（通配 *.github.com 不算）', s.hosts.expected);
  ok(!JSON.stringify(s.hosts.missing).includes('*'), 'missing 里不出现通配', s.hosts.missing);

  // 域名与节点计数
  ok(s.domains.includes('github.com') && s.domains.includes('*.github.com'), 'status.domains 列出全部节点组', s.domains);
  ok(s.nodes['github.com'] === 2 && s.nodes['*.github.com'] === 1, 'status.nodes 是按域名的节点数', s.nodes);

  // 冲突按来源归因（对象数组，不是字符串数组）
  ok(Array.isArray(s.conflicts), 'status.conflicts 是数组');
  ok(s.conflicts.every((c) => c && typeof c.source === 'string' && Array.isArray(c.domains)), 'conflicts 每项带 source + domains', s.conflicts);

  // 智能与健康
  ok(s.smart && s.smart.enabled === true, 'status.smart.enabled 来自 config.smart', s.smart);
  ok(typeof s.health === 'object', 'status.health 是对象（域名级健康快照）', s.health);
  ok(Array.isArray(s.recent), 'status.recent 是数组');
} finally {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* 临时目录清理失败不影响结论 */ }
}

console.log(`\n${checks - failures.length}/${checks} 通过`);
if (failures.length) {
  console.log('失败项：');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
