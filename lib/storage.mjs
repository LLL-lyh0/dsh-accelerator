// 存储层：所有可变状态都在 storages/ 目录下的 JSON 里，**外部 AI 可以直接读写**。
//
// 这是 m00563「支持外部使用 ai 来进行扩展（包括更新其它节点）」的落地方式：
//   nodes.json    —— 节点池（按域名分组），AI/脚本可以直接改这个文件
//   config.json   —— 用户配置（端口、开机启动、启用哪些域名组、上游代理）
//   ca.pem/key.pem —— 根证书（私钥不放进证书存储）
//   leaf.pem/leaf.key —— 叶证书（域名集变了自动重签）
//
// 设计原则：**文件即接口**。插件只读 JSON、只写 JSON，不引入数据库。
// 谁写的都算数（插件自己、管理页、外部 AI、别的脚本），下一次读取即生效。

import fs from 'node:fs/promises';
import path from 'node:path';

export const STORAGE_FILES = {
  config: 'config.json',
  nodes: 'nodes.json',
  caCert: 'ca.pem',
  caKey: 'ca.key',
  leafCert: 'leaf.pem',
  leafKey: 'leaf.key',
  leafMeta: 'leaf.json',           // 叶证书的附加元数据（CDP 地址等，用于判断要不要重签）
  caCer: 'dsh-accelerator-ca.cer', // 供 certutil 安装用的 DER
  caCrl: 'ca.crl',                 // CRL（DER）—— 叶证书的 CRL 分发点指向本机代理的 /dsh-accelerator.crl
  crlMeta: 'crl.json',             // CRL 元数据（nextUpdate / crlNumber / 签发它的 CA 指纹）
};

export const DEFAULT_CONFIG = {
  enabled: true,                  // 默认开：装上即加速，不需要用户再手动开一次
  autoStart: true,                // DSH 启动时若 enabled 就自动拉起（无需再点一次）
  smart: true,                    // 智能加速：自动巡检 + 自动换节点 + 自动验证
  smartIntervalMin: 15,           // 智能巡检间隔（分钟）
  listenHost: '127.0.0.2',        // 127.0.0.1:443 已被 Steamcommunity_302 占用
  listenPort: 443,
  // 接管方式：hosts（无系统级副作用）| pac（每用户可写的系统代理，hosts 不可写时的出路）
  //          | fixed（整机固定代理）| auto（能写 hosts 就用 hosts，否则自动改 PAC）
  takeover: 'auto',
  proxyHost: '127.0.0.2',         // 代理监听地址（系统代理指向它）
  proxyPort: 8843,                // 与 302 的 34866 / Watt 的 81,444 都不冲突
  installCaOnEnable: true,        // 启用时自动把 CA 装进 CurrentUser\Root
  // 是否顺手把 WinINET 的吊销检查关掉（HKCU\...\Internet Settings\CertificateRevocation=0）。
  // 只对认这个设置的老式 WinINET 客户端有效；**curl.exe / git(schannel) 不认它**（实测），
  // 命令行客户端的正解是叶证书里的 CRL 分发点 + 本机代理服务 CRL。默认关，避免全局副作用。
  relaxRevocationCheck: false,
  upstream: {                     // 可插拔外部上游（对应需求 3）
    mode: 'direct',               // direct | http | socks5
    host: '',
    port: 0,
    username: '',
    password: '',
  },
  enforce: [],                    // 强制走本加速的进程名（需求 2），如 ['steam.exe']
  bypass: [],                     // 永不接管的进程名（隐私敏感的程序建议写这里）
  domainGroups: {},               // 每个域名的启用开关，缺省视为 true
};

/** 读 JSON，文件不存在或坏了都回退到 fallback（绝不因为存储损坏而起不来）。 */
async function readJson(file, fallback) {
  try {
    const raw = await fs.readFile(file, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed;
    return fallback;
  } catch {
    return fallback;
  }
}

/**
 * 原子写：先写 .tmp 再 rename。避免管理页/外部 AI 同时写时读到半个文件
 * （Windows 上 rename 覆盖已存在文件是原子的）。
 */
export async function writeJsonAtomic(file, value) {
  const tmp = `${file}.tmp.${process.pid}.${Date.now()}`;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await fs.rename(tmp, file);
}

export class Storage {
  /** @param {string} dir storages 目录绝对路径 */
  constructor(dir) {
    this.dir = dir;
  }

  file(name) {
    return path.join(this.dir, STORAGE_FILES[name] ?? name);
  }

  async ensureDir() {
    await fs.mkdir(this.dir, { recursive: true });
  }

  // ── config ────────────────────────────────────────────────────────────────
  async readConfig() {
    const raw = await readJson(this.file('config'), {});
    // 深合并一层：老配置缺新字段时用默认值补齐，不需要迁移脚本
    return {
      ...DEFAULT_CONFIG,
      ...raw,
      upstream: { ...DEFAULT_CONFIG.upstream, ...(raw.upstream ?? {}) },
      domainGroups: { ...DEFAULT_CONFIG.domainGroups, ...(raw.domainGroups ?? {}) },
    };
  }

  async writeConfig(config) {
    await writeJsonAtomic(this.file('config'), config);
  }

  // ── nodes ─────────────────────────────────────────────────────────────────
  /** 读节点池；不存在则用种子池初始化并落盘（首次启动即「已配置好」）。 */
  async readNodes(seed) {
    const raw = await readJson(this.file('nodes'), null);
    if (raw && typeof raw === 'object' && Object.keys(raw).length > 0) return raw;
    if (seed) await writeJsonAtomic(this.file('nodes'), seed);
    return seed ?? {};
  }

  async writeNodes(nodes) {
    await writeJsonAtomic(this.file('nodes'), nodes);
  }

  // ── 证书 ──────────────────────────────────────────────────────────────────
  async readCert(name) {
    try { return await fs.readFile(this.file(name), 'utf8'); } catch { return null; }
  }

  async writeCert(name, pem) {
    await this.ensureDir();
    await fs.writeFile(this.file(name), pem, 'utf8');
  }

  /** 写 DER 版 CA 供 certutil 安装。 */
  async writeDer(name, der) {
    await this.ensureDir();
    await fs.writeFile(this.file(name), der);
  }

  /** 读二进制文件（CRL 用），不存在返回 null。 */
  async readBinary(name) {
    try { return await fs.readFile(this.file(name)); } catch { return null; }
  }

  /** 读/写任意 JSON 元数据文件（leaf.json / crl.json）。 */
  async readJsonFile(name, fallback = null) {
    return readJson(this.file(name), fallback);
  }

  async writeJsonFile(name, value) {
    await writeJsonAtomic(this.file(name), value);
  }

  async hasAuthority() {
    const [cert, key] = await Promise.all([this.readCert('caCert'), this.readCert('caKey')]);
    return Boolean(cert && key);
  }
}
