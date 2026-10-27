// 纯函数自检：智能修复的「池子下限保护」。
//
// 实测背景（2026-10-27）：store.steampowered.com 的一次 repair 只活下来 1 个 IP，
// 于是整个池子被替换成那一条，复验反而更差。这里锁住「存活太少就不能缩池」这条规则，
// 并顺带用源码级断言钉住 repair() 真的调用了它（否则函数写得对、没人用也是白搭）。
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mergeKeepPrevious } from '../lib/smart.mjs';

let pass = 0;
let fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass += 1; console.log(`PASS  ${name}${detail ? '  ' + detail : ''}`); }
  else { fail += 1; console.log(`FAIL  ${name}${detail ? '  ' + detail : ''}`); }
}

const n = (ip, sni = 'real', sniValue) => ({ ip, sni, ...(sniValue ? { sniValue } : {}) });

// 1) 存活足够（>= min）→ 原样使用本次策展结果，旧候选不参与
{
  const alive = [n('1.1.1.1'), n('2.2.2.2')];
  const got = mergeKeepPrevious(alive, [n('9.9.9.9')], { min: 2, keep: 6 });
  check('存活 >= min 时直接用本次结果', got.length === 2 && got[0].ip === '1.1.1.1', JSON.stringify(got));
  check('存活 >= min 时不会掺进旧候选', !got.some((x) => x.ip === '9.9.9.9'));
}

// 2) 存活不足 → 旧的并回来，排在新候选之后
{
  const got = mergeKeepPrevious([n('1.1.1.1')], [n('8.8.8.8'), n('9.9.9.9')], { min: 2, keep: 6 });
  check('存活 1 条时把旧候选并回来（不缩池）', got.length === 3, JSON.stringify(got));
  check('新存活的那条排在第一位', got[0].ip === '1.1.1.1');
  check('旧候选按顺序补在后面', got[1].ip === '8.8.8.8' && got[2].ip === '9.9.9.9');
}

// 3) 去重按 ip+sni（同一个 IP 的不同 SNI 策略是两条合法候选）
{
  const got = mergeKeepPrevious([n('1.1.1.1', 'real')], [n('1.1.1.1', 'real'), n('1.1.1.1', 'none')], { min: 2, keep: 6 });
  check('同 ip+sni 不重复', got.filter((x) => x.ip === '1.1.1.1' && x.sni === 'real').length === 1);
  check('同 ip 不同 sni 视为不同候选', got.some((x) => x.ip === '1.1.1.1' && x.sni === 'none'));
}

// 4) keep 上限照样生效
{
  const got = mergeKeepPrevious([n('1.1.1.1')], [n('8.8.8.8'), n('9.9.9.9'), n('7.7.7.7')], { min: 2, keep: 2 });
  check('合并后仍受 keep 上限约束', got.length === 2, JSON.stringify(got));
}

// 5) sniValue 只在真的有时保留（sni=none 的候选不该带 CDN 名）
{
  const got = mergeKeepPrevious([], [n('1.1.1.1', 'cdn', 'a248.e.akamai.net'), n('2.2.2.2', 'real')], { min: 2, keep: 6 });
  check('sniValue 被保留', got[0].sniValue === 'a248.e.akamai.net');
  check('没有 sniValue 的候选不带该字段', !('sniValue' in got[1]));
}

// 6) 没有旧候选时不能凭空造
{
  const got = mergeKeepPrevious([], [], { min: 2, keep: 6 });
  check('旧池为空时结果为空（不造假候选）', got.length === 0);
}

// 7) 源码级：repair() 必须真的用它（否则这个保护是死代码）
{
  const src = readFileSync(fileURLToPath(new URL('../lib/smart.mjs', import.meta.url)), 'utf8');
  check('repair() 调用了 mergeKeepPrevious', /next\[key\]\s*=\s*mergeKeepPrevious\(/.test(src));
  check('下限默认值是 2', /min:\s*opts\.minKeep\s*\?\?\s*2/.test(src));
}

console.log(`\n${pass}/${pass + fail} 通过`);
process.exit(fail === 0 ? 0 : 1);
