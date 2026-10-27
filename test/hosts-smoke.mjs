// hosts 纯函数冒烟：不起服务、不碰真实 hosts 文件。
//
// 这些函数是「能不能干净回滚」和「用户看到哪条警告」的唯一依据，必须可离线复跑。
// 真实样本来自本机实测：Steamcommunity_302 重写 hosts 后留下 868 行 `127.0.0.1 <域名> #S302`，
// 并把我们段里与它重叠的行删掉（只剩 opencode.ai / openrouter.ai）。

import {
  stripOwnBlock, buildOwnBlock, parseOwnBlock, detectConflicts, missingManaged, composeHosts,
} from '../lib/hosts.mjs';

let checks = 0;
const failures = [];
function ok(cond, label, extra) {
  checks += 1;
  if (cond) console.log(`  ✓ ${label}`);
  else { failures.push(label); console.log(`  ✗ ${label}${extra === undefined ? '' : ` → ${JSON.stringify(extra)}`}`); }
}

const OUR = buildOwnBlock(['github.com', 'opencode.ai'], '127.0.0.2');
const S302 = [
  '127.0.0.1 github.com #S302',
  '127.0.0.1 api.github.com #S302',
  '127.0.0.1 store.steampowered.com #S302',
].join('\r\n');
const original = '# Copyright\r\n127.0.0.1 localhost\r\n';

// 1. 自己的段：构造 → 解析 → 剥离
const withOur = `${original}\r\n${OUR}${S302}\r\n`;
const own = parseOwnBlock(withOur);
ok(own.active === true, 'parseOwnBlock 认出自己的段');
ok(own.entries.length === 2 && own.entries[0].ip === '127.0.0.2', '解析出 2 条指向 127.0.0.2 的条目', own.entries);
ok(stripOwnBlock(withOur).includes('github.com #S302'), 'stripOwnBlock 只删自己的段，别家的行原样保留');
ok(!stripOwnBlock(withOur).includes('DSH Accelerator Start'), 'stripOwnBlock 后没有残留标记');
ok(stripOwnBlock(original) === original, '没有自己段时 stripOwnBlock 是恒等操作');

// 2. 缺哪几条（302 重写时会删掉重叠行）
ok(
  JSON.stringify(missingManaged(OUR, ['github.com', 'opencode.ai'])) === '[]',
  '自己的段齐全时 missingManaged 为空',
);
ok(
  JSON.stringify(missingManaged(OUR, ['github.com', 'opencode.ai', 'huggingface.co'])) === '["huggingface.co"]',
  'missingManaged 报出缺失域名',
);

// 3. 冲突归因：302 用行尾 `#S302`，Watt 用包裹段，都要认出来，并且不能把自己算进去
const watt = '# Steam++ Start\r\n127.0.0.1 github.com\r\n# Steam++ End';
const text = `${original}\r\n${OUR}${S302}\r\n${watt}\r\n`;
const conflicts = detectConflicts(text, ['github.com', 'api.github.com', 'opencode.ai', 'huggingface.co']);
const bySource = Object.fromEntries(conflicts.map((c) => [c.source, c]));
ok(conflicts.length === 2, '归因出两个来源（302 与 Watt）', conflicts.map((c) => c.source));
ok(Boolean(bySource['Steamcommunity_302']), '302 的行按 `#S302` 归因');
ok(
  bySource['Steamcommunity_302'] && bySource['Steamcommunity_302'].domains.join(',') === 'api.github.com,github.com',
  '302 只算受管域名（store.steampowered.com 不在节点池里就不报）',
  bySource['Steamcommunity_302'] && bySource['Steamcommunity_302'].domains,
);
ok(
  bySource['Steamcommunity_302'] && bySource['Steamcommunity_302'].ip === '127.0.0.1'
  && bySource['Steamcommunity_302'].line > 0,
  '冲突带 IP 与行号（管理页要能指到具体行）',
);
ok(Boolean(bySource['Steam++ (Watt Toolkit)']), 'Watt 的行按包裹段归因');
ok(
  !conflicts.some((c) => (c.domains || []).includes('opencode.ai')),
  '自己段里的域名不算冲突（opencode.ai 只在我们段里）',
);
ok(detectConflicts(text, []).length === 0, '没有受管域名时返回空数组');

// 4. 回滚不变量：删掉自己的段后，别家内容一个字节都不变
const restored = stripOwnBlock(withOur);
ok(restored.startsWith(original), '回滚后文件以自己的原始头开始');
ok(restored.includes(S302.split('\r\n')[0]), '回滚后 302 的第一行仍在');

// 5. ★ 谁先命中：Windows 解析 hosts 取首个命中，排在别家后面 = 写了但没生效
const foreignFirst = `${original}\r\n${S302}\r\n${OUR}`;          // 302 在前（本机实测的真实形态：它在第 12 行，我们在第 880 行）
const blocked = detectConflicts(foreignFirst, ['github.com', 'api.github.com', 'opencode.ai']);
const b302 = blocked.find((c) => c.source === 'Steamcommunity_302');
ok(Boolean(b302) && b302.severity === 'blocked', '别家的行在前 → severity 是 blocked（不是含糊的「互相干扰」）', b302);
ok(
  b302 && b302.shadowed.join(',') === 'api.github.com,github.com' && b302.overridden.length === 0,
  'blocked 时 shadowed 列出真正没生效的域名，overridden 为空',
  b302 && { shadowed: b302.shadowed, overridden: b302.overridden },
);
ok(
  b302 && /不生效/.test(b302.message) && !/互相干扰/.test(b302.message),
  'blocked 的文案说的是「我们的引导不生效」，不再是「会同时生效并互相干扰」',
  b302 && b302.message,
);
const oursFirst = detectConflicts(withOur, ['github.com', 'api.github.com', 'opencode.ai']);
const o302 = oursFirst.find((c) => c.source === 'Steamcommunity_302');
ok(Boolean(o302) && o302.severity === 'info', '我们的段在前 → severity 是 info（共存，不影响加速）', o302);
ok(
  o302 && o302.overridden.join(',') === 'api.github.com,github.com' && o302.shadowed.length === 0,
  'info 时 overridden 列出我们优先命中的域名',
  o302 && { shadowed: o302.shadowed, overridden: o302.overridden },
);
ok(
  detectConflicts(foreignFirst, ['github.com'], { ownAt: 0 })[0].severity === 'info',
  'ownAt 选项：写盘前预判「我们即将插到最前面」→ 不误报 blocked',
);

// 6. ★ 写入位置：有冲突时必须插到别家映射行之前
const composed = composeHosts(foreignFirst, ['github.com', 'opencode.ai'], '127.0.0.2');
ok(composed.insertAt > 0, 'composeHosts 报出插入位置（插在别家行之前）', composed.insertAt);
const composedLines = composed.text.split(/\r?\n/);
const ourLine = composedLines.findIndex((l) => l.includes('DSH Accelerator Start'));
const s302Line = composedLines.findIndex((l) => l.includes('#S302'));
ok(ourLine >= 0 && s302Line >= 0 && ourLine < s302Line, '我们的段确实排在 302 的映射行之前', { ourLine, s302Line });
ok(
  parseOwnBlock(composed.text).entries.length === 2,
  '插进去之后自己的段仍然可解析（2 条）',
  parseOwnBlock(composed.text).entries,
);
ok(
  detectConflicts(composed.text, ['github.com', 'api.github.com', 'opencode.ai'])
    .every((c) => c.severity === 'info'),
  '重排之后不再有 blocked 冲突',
);
const noConflict = composeHosts(original, ['github.com', 'opencode.ai'], '127.0.0.2');
ok(noConflict.insertAt === -1, '没有别家冲突时仍然追加到末尾（不无谓改动别人文件）', noConflict.insertAt);
ok(noConflict.text.startsWith(original), '追加模式不会动原文');

console.log(`\n${checks - failures.length}/${checks} 通过`);
if (failures.length) {
  console.log('失败项：');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
