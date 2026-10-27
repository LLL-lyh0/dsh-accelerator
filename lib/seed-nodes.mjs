// 种子节点池 —— 「开箱即用」的那一半。
//
// 每一条都来自本机实测（`D:\DeepSeekHarness\.tmp-accel-probe\preflight.mjs`），
// 关键字段是 `sni`：同一个 IP，发真 SNI 还是不发 SNI，结果可能完全相反。
//   real → TLS 握手时带真实域名（多数站点正常）
//   none → 完全不发 SNI（Akamai / CloudFront 系被 SNI 阻断时靠这个绕过）
//   cdn  → 填一个 CDN 的通用名（如 a248.e.akamai.net），进一步降特征
//
// 上限：这只是「够用的起点」。真正的优选靠 curator.mjs 定时扩池 / 主动测速，
// 外部 AI 也可以直接改 nodes.json 来替换（这就是 m00563 要的「可扩展」）。

/** @typedef {{ ip: string, sni: 'real'|'none'|'cdn', sniValue?: string }} SeedNode */

/** @type {Record<string, SeedNode[]>} */
export const SEED_NODES = {
  'github.com': [
    { ip: '140.82.114.4', sni: 'real' },
    { ip: '140.82.112.3', sni: 'real' },
    { ip: '140.82.114.6', sni: 'real' },
    { ip: '20.205.243.166', sni: 'none' },
  ],
  'api.github.com': [
    { ip: '140.82.114.6', sni: 'real' },
    { ip: '20.205.243.168', sni: 'none' },
  ],
  'raw.githubusercontent.com': [
    { ip: '185.199.108.133', sni: 'real' },
    { ip: '185.199.109.133', sni: 'real' },
    { ip: '185.199.110.133', sni: 'real' },
  ],
  'steamcommunity.com': [
    { ip: '23.218.239.27', sni: 'none', sniValue: 'a248.e.akamai.net' },
    { ip: '23.218.239.39', sni: 'none', sniValue: 'a248.e.akamai.net' },
  ],
  'store.steampowered.com': [
    { ip: '23.200.214.95', sni: 'real' },
  ],
  'api.steampowered.com': [
    // 23.59.88.194 本机实测常 TCP timeout（2026-10-27：5003ms tcp:timeout），
    // 23.35.148.x 是本机 DoH 解析 + 逐个测活得到的候选（均为真 SNI；该主机对无 SNI 直接
    // 回 ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR，所以不能给它们写 sni:'none'）。
    { ip: '23.35.148.193', sni: 'real' },
    { ip: '23.35.148.186', sni: 'real' },
    { ip: '23.35.148.190', sni: 'real' },
    { ip: '23.59.88.206', sni: 'real' },
    { ip: '23.59.88.194', sni: 'real' },
  ],
  'huggingface.co': [
    { ip: '3.167.226.59', sni: 'none' },
  ],
  'opencode.ai': [
    { ip: '172.65.90.23', sni: 'real' },
    { ip: '172.65.90.20', sni: 'real' },
  ],
  'openrouter.ai': [
    { ip: '104.18.2.115', sni: 'real' },
    { ip: '104.18.3.115', sni: 'real' },
  ],
};

/** DoH 解析器（国内可用的两家；系统 DNS 会被 hosts 污染，绝对不能用）。 */
export const DOH_ENDPOINTS = [
  'https://223.5.5.5/resolve',
  'https://1.12.12.12/resolve',
];

/** 叶证书要覆盖的域名（改了这里要重签叶证书 —— 纯 Node 几毫秒）。 */
export const DEFAULT_DOMAINS = Object.keys(SEED_NODES);
