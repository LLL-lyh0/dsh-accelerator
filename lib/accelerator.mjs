// 加速器的总装：把证书、存储、hosts、引擎、CA 安装串起来，对外只暴露 start/stop/status。
//
// 状态机刻意做得「可解释」：管理页要能回答「为什么现在没生效」而不只是显示一个红灯。
// 每一步都可能失败（端口被占 / hosts 不可写 / certutil 报错 / 别家加速器冲突），
// 全部收集成 `checks[]`，让用户看到具体卡在哪。

import { Engine } from './engine.mjs';
import { Storage } from './storage.mjs';
import { applyHosts, revertHosts, readHosts, detectConflicts, parseOwnBlock, missingManaged, probeHostsWritable } from './hosts.mjs';
import { installCa, uninstallCa, isCaInstalled, thumbprintOf, CA_SUBJECT_CN } from './ca-install.mjs';
import { createAuthority, createCrl, issueLeaf, buildSanList, thumbprint } from './certs.mjs';
import { SEED_NODES, DEFAULT_DOMAINS } from './seed-nodes.mjs';
import { matchDomain } from './sni.mjs';
import { CRL_PATH } from './proxy.mjs';
import { applyPac, applyFixed, restore as restoreProxy, currentTakeover, clearOurTakeover, pacUrlFor, buildPac, disableRevocation, restoreRevocation, readRevocation } from './system-proxy.mjs';

const DOMAINS_FILE_VERSION = 1;

export class Accelerator {
  /**
   * @param {{dir: string, logger?: any}} opts
   */
  constructor(opts) {
    this.storage = new Storage(opts.dir);
    this.logger = opts.logger ?? console;
    this.engine = new Engine({
      getConfig: () => this.config,
      getNodes: () => this.nodes,
      getLeaf: () => this.leaf,
      getPac: () => this.pacText(),
      getCrl: () => this.crlDer,
    });
    this.config = null;
    this.nodes = {};
    this.leaf = null;
    this.crlDer = null;        // 当前 CRL（DER），由本机代理在 /dsh-accelerator.crl 上服务
    this.authority = null;
    this.takeoverState = { mode: null, saved: null, applied: null };   // 系统代理接管前必须留快照
    this.decisions = [];       // 最近 N 条接管记录，给管理页用
    this.lastError = null;
    this.smart = null;         // SmartController 由宿主 index.js 挂上（避免 lib 互相依赖）
    this.lastVerify = null;
    this.lastRepair = null;
    this.hostsState = { active: false, entries: [] };
    this.engine.on('decision', (d) => {
      this.decisions.push({ ...d, at: Date.now() });
      if (this.decisions.length > 200) this.decisions.shift();
    });
    this.engine.on('error', (e) => { this.lastError = String(e && e.message); });
  }

  // ── 初始化 ────────────────────────────────────────────────────────────────
  /** 读存储、按需生成 CA 与叶证书、首次启动写入种子节点池。幂等。 */
  async init() {
    await this.storage.ensureDir();
    this.config = await this.storage.readConfig();
    this.nodes = await this.storage.readNodes(SEED_NODES);

    let caCert = await this.storage.readCert('caCert');
    let caKey = await this.storage.readCert('caKey');
    if (!caCert || !caKey) {
      const ca = createAuthority();
      caCert = ca.certPem;
      caKey = ca.keyPem;
      await this.storage.writeCert('caCert', caCert);
      await this.storage.writeCert('caKey', caKey);
      await this.storage.writeDer('caCer', ca.der);
      this.logger.info?.('[dsh-accelerator] 已生成新的根 CA');
    }
    this.authority = { certPem: caCert, keyPem: caKey };

    await this.ensureCrl();
    await this.ensureLeaf();
    this.hostsState = parseOwnBlock(await readHosts());
    return this;
  }

  /**
   * 叶证书的 CRL 分发点地址 —— 指向本机代理的 `/dsh-accelerator.crl`。
   *
   * 这是为了让 Windows Schannel 系客户端（curl.exe / git / WinHTTP）能通过链验证：
   * 它们默认要求「能确认吊销状态」，而本地自签叶证书若没有 CRL 分发点、或分发点取不到 CRL，
   * 握手会直接以 `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` 失败（实测）。
   */
  crlUrl() {
    const host = this.config?.proxyHost || '127.0.0.2';
    const port = this.config?.proxyPort || 8843;
    const h = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host;
    return `http://${h}:${port}${CRL_PATH}`;
  }

  /**
   * 准备 CRL：文件不存在 / 快过期（< 3 天）/ 换了 CA / 换了 CDP 地址时重签。
   * 空 CRL 就够了 —— Schannel 只要能拉到一份合法的（未过期、由 CA 签名的）列表即可。
   */
  async ensureCrl() {
    const url = this.crlUrl();
    const caDer = Buffer.from(this.authority.certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
    const caFingerprint = thumbprint(caDer);
    const meta = await this.storage.readJsonFile('crlMeta', null);
    const existing = await this.storage.readBinary('caCrl');
    const fresh = Boolean(
      meta && existing
      && meta.ca === caFingerprint
      && meta.url === url
      && Date.parse(meta.nextUpdate) - Date.now() > 3 * 864e5,
    );
    if (fresh) {
      this.crlDer = existing;
      this.crlMeta = meta;
      return { ...meta, reused: true };
    }
    const crl = createCrl(this.authority, { days: 30, crlNumber: (Number(meta?.crlNumber) || 0) + 1 });
    const next = {
      nextUpdate: crl.nextUpdate.toISOString(),
      thisUpdate: crl.thisUpdate.toISOString(),
      crlNumber: (Number(meta?.crlNumber) || 0) + 1,
      ca: caFingerprint,
      url,
      at: new Date().toISOString(),
    };
    await this.storage.writeDer('caCrl', crl.der);
    await this.storage.writeJsonFile('crlMeta', next);
    this.crlDer = crl.der;
    this.crlMeta = next;
    this.logger.info?.(`[dsh-accelerator] 已签发 CRL（#${next.crlNumber}，${next.nextUpdate} 过期）→ ${url}`);
    return next;
  }

  /** 叶证书：域名集或 CRL 分发点变了自动重签（用 SAN 覆盖面 + leaf.json 里的 CDP 对比）。 */
  async ensureLeaf() {
    const domains = this.managedDomains();
    const want = buildSanList(domains).sort().join(',');
    const crlUrl = this.crlUrl();
    const meta = await this.storage.readJsonFile('leafMeta', {});
    const existingCert = await this.storage.readCert('leafCert');
    const existingKey = await this.storage.readCert('leafKey');
    if (existingCert && existingKey && meta && meta.crlUrl === crlUrl) {
      try {
        const x = await import('node:crypto').then((m) => new m.X509Certificate(existingCert));
        const got = String(x.subjectAltName || '')
          .split(',')
          .map((s) => s.trim().replace(/^DNS:/, '').toLowerCase())
          .filter(Boolean)
          .sort()
          .join(',');
        if (got === want) {
          this.leaf = { certPem: existingCert, keyPem: existingKey };
          return this.leaf;
        }
      } catch { /* 解析失败就当过期，重签 */ }
    }
    const leaf = issueLeaf(this.authority, domains, 825, { crlUrl });
    await this.storage.writeCert('leafCert', leaf.certPem);
    await this.storage.writeCert('leafKey', leaf.keyPem);
    await this.storage.writeJsonFile('leafMeta', { crlUrl, san: leaf.san, at: new Date().toISOString() });
    this.leaf = { certPem: leaf.certPem, keyPem: leaf.keyPem };
    this.logger.info?.(`[dsh-accelerator] 已签发叶证书，覆盖 ${leaf.san.length} 条 SAN（CDP ${crlUrl}）`);
    return this.leaf;
  }

  /** 受管域名 = 节点池里的所有 key（含通配）。 */
  managedDomains() {
    const keys = Object.keys(this.nodes ?? {});
    return keys.length ? keys : DEFAULT_DOMAINS;
  }

  // ── 启停 ──────────────────────────────────────────────────────────────────
  async start() {
    const checks = [];
    if (!this.config) await this.init();

    // 0) 叶证书与 CRL 必须与「当前」代理端口一致（叶证书里的 CDP 就指向它）。
    //    ensureCrl/ensureLeaf 都是幂等的（meta 对得上就复用），放这里有两个好处：
    //    ① 端口/域名集改动后不用重启 DSH 就能重签；② 不会被上一轮 init 的旧 CRL 卡住
    //    （实测：修好 CRL 的 DER 标签后，宿主内存里仍是旧那份 a3，重启加速才换掉）。
    try {
      await this.ensureCrl();
      await this.ensureLeaf();
    } catch (e) {
      this.lastError = `CRL/叶证书准备失败: ${String(e && e.message)}`;
    }

    // 1) 端口
    try {
      await this.engine.start();
      checks.push({ id: 'port', ok: true, detail: `${this.config.listenHost}:${this.config.listenPort}` });
    } catch (e) {
      checks.push({ id: 'port', ok: false, detail: String(e && e.message) });
      this.lastError = String(e && e.message);
      return { ok: false, checks };
    }

    // 2) CA 安装
    if (this.config.installCaOnEnable) {
      const cerPath = this.storage.file('caCer');
      const r = await installCa(cerPath, CA_SUBJECT_CN);
      const installed = await isCaInstalled(CA_SUBJECT_CN);
      const wantTp = thumbprintOf(Buffer.from(
        (this.authority.certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')),
        'base64',
      ));
      const stale = installed && !(await this.hasMatchingThumbprint(wantTp));
      checks.push({
        id: 'ca',
        ok: installed,
        detail: installed ? (stale ? `已安装但指纹不匹配（应为 ${wantTp.slice(0, 12)}…），请重装` : `已信任 ${CA_SUBJECT_CN}`) : r.output,
      });
      if (stale) await this.reinstallCa();
    } else {
      checks.push({ id: 'ca', ok: true, detail: '已跳过（配置关闭）' });
    }

    // 3) 接管方式：hosts 优先（无系统级副作用）；hosts 不可写时自动退到 PAC。
    //    实测 Steamcommunity_302 会把 hosts 的 ACL 收成 Users:(RX)，所以「只靠 hosts」在
    //    这台机器上已经失效 —— 注册表是每用户可写的，PAC 是标准用户唯一还能用的接管路径。
    const hosts = this.managedDomains().filter((d) => !d.includes('*'));
    const before = await readHosts();
    const warnings = detectConflicts(before, hosts);
    const writable = await probeHostsWritable();
    const want = this.config.takeover ?? 'auto';
    const useHosts = want === 'hosts' || (want === 'auto' && writable);

    if (useHosts && !writable) {
      checks.push({
        id: 'hosts',
        ok: false,
        detail: `不可写（Users 只有 RX），${missingManaged(before, hosts).length} 个域名没能写进 hosts；`
          + '以管理员身份运行 DSH，或管理员执行 icacls "C:\\Windows\\System32\\drivers\\etc\\hosts" /grant Users:F',
        writable: false,
        missing: missingManaged(before, hosts),
        warnings,
      });
    } else if (useHosts) {
      try {
        const res = await applyHosts(hosts, this.config.listenHost);
        const after = await readHosts();
        this.hostsState = parseOwnBlock(after);
        const missing = missingManaged(after, hosts);
        // ★ 必须用「写后」的文本重新判定谁先命中：applyHosts 会把我们的段插到别家映射之前，
        //   若沿用写前那份 warnings，就会把已经解决的冲突照旧报成 blocked（实测假警报：
        //   面板报「7 个域名被压在后面」，而 hosts 里我们的段其实在第 14 行、302 在第 27 行）。
        const warningsAfter = detectConflicts(after, hosts, { ownAt: res.insertedAt });
        const shadowedAll = warningsAfter.filter((w) => w.severity === 'blocked');
        const blockedCount = shadowedAll.reduce((n, w) => n + w.shadowed.length, 0);
        checks.push({
          id: 'hosts',
          ok: this.hostsState.active && missing.length === 0 && blockedCount === 0,
          detail: `${this.hostsState.entries.length}/${hosts.length} 条 → ${this.config.listenHost}`
            + `${res.changed ? '' : '（无变化）'}`
            + `${res.insertedAt >= 0 && res.changed ? '；已插到别家的段之前（保证首个命中）' : ''}`
            + `${missing.length ? `；缺 ${missing.length} 条（被别家加速器删掉了）` : ''}`
            + `${blockedCount ? `；⚠ ${blockedCount} 个域名被别家的行压在后面，实际未生效` : ''}`,
          writable: true,
          missing,
          warnings: warningsAfter,
        });
      } catch (e) {
        checks.push({ id: 'hosts', ok: false, detail: String(e && e.message), writable, warnings });
      }
    } else {
      checks.push({
        id: 'hosts',
        ok: true,
        detail: writable ? `按配置跳过（接管方式 ${want}）` : 'hosts 不可写，已改用 PAC 接管',
        writable,
        skipped: true,
        warnings,
      });
    }

    // 4) 系统代理 / PAC（hosts 不可写时的接管路径）
    const takeover = want === 'auto' ? (writable ? 'hosts' : 'pac') : want;
    // 代理监听**两种接管方式都要起**：pac/fixed 靠它转发，hosts 模式下它只服务
    // 叶证书 CRL 分发点（/dsh-accelerator.crl）—— Schannel 系客户端（curl/git/WinHTTP）
    // 拉不到 CRL 就会以 CRYPT_E_NO_REVOCATION_CHECK 拒绝握手，命令行体验会整个坏掉。
    let proxyListenError = null;
    try {
      await this.engine.startProxy();
    } catch (e) {
      proxyListenError = String(e && e.message);
    }
    if (takeover === 'pac' || takeover === 'fixed') {
      const proxyHost = this.config.proxyHost || '127.0.0.2';
      const proxyPort = this.config.proxyPort || 8843;
      try {
        if (proxyListenError) throw new Error(proxyListenError);
        if (takeover === 'pac') {
          const r = await applyPac(pacUrlFor(proxyHost, proxyPort));
          this.takeoverState = { mode: 'pac', saved: r.saved, applied: r.applied };
          checks.push({
            id: 'proxy',
            ok: r.ok,
            detail: `PAC ${pacUrlFor(proxyHost, proxyPort)}（${this.managedDomains().length} 个域名走本机 ${proxyHost}:${proxyPort}，其余直连）`
              + `${r.warnings.length ? `；${r.warnings.join('；')}` : ''}`,
            warnings: r.warnings,
          });
        } else {
          const r = await applyFixed(`${proxyHost}:${proxyPort}`);
          this.takeoverState = { mode: 'fixed', saved: r.saved, applied: r.applied };
          checks.push({
            id: 'proxy',
            ok: r.ok,
            detail: `固定代理 ${proxyHost}:${proxyPort}（整机 HTTP/HTTPS 都走本机，非受管域名盲隧道转发）`
              + `${r.warnings.length ? `；${r.warnings.join('；')}` : ''}`,
            warnings: r.warnings,
          });
        }
      } catch (e) {
        checks.push({ id: 'proxy', ok: false, detail: String(e && e.message) });
      }
    } else {
      // hosts 模式：我们**不再监听代理端口**，所以上一轮写的 PAC/固定代理必须清掉 ——
      // 否则认系统代理的程序会被指到一个没人听的端口（实测踩过：切回 hosts 后
      // AutoConfigURL 还指着 http://127.0.0.2:8843/proxy.pac，而 8843 已经关了）。
      // 只清「确实是我们写的」那几项，别家留下的 ProxyServer 等值一个都不动。
      let detail = proxyListenError
        ? `hosts 接管；代理监听未起来（${proxyListenError}）→ Schannel 系客户端可能报 CRYPT_E_NO_REVOCATION_CHECK`
        : `hosts 接管；代理监听仅供 CRL 分发（${this.crlUrl()}）`;
      try {
        const proxyHost = this.config.proxyHost || '127.0.0.2';
        const proxyPort = this.config.proxyPort || 8843;
        const st = await currentTakeover(proxyHost, proxyPort);
        if (st.pacActive || st.fixedActive) {
          if (this.takeoverState?.saved) {
            const r = await restoreProxy(this.takeoverState.saved);
            detail += `；已还原上一轮的系统代理设置${r.ok ? '' : '（回读与快照不一致）'}`;
          } else {
            const r = await clearOurTakeover(proxyHost, proxyPort);
            detail += r.cleared.length
              ? `；已清掉上一轮残留的系统代理设置（${r.cleared.join('/')}）`
              : '；检测到残留系统代理，但清除失败';
          }
          this.takeoverState = { mode: null, saved: null, applied: null };
        }
      } catch (e) {
        detail += `；清理残留系统代理失败：${String(e && e.message)}`;
      }
      checks.push({ id: 'proxy', ok: true, detail, skipped: true });
    }

    // 5) 可选：把 WinINET 的吊销检查也关掉（config.relaxRevocationCheck，默认关）。
    //    注意**它治不了 curl.exe / git(schannel)** —— 实测这两个不读这个设置，只认证书里的
    //    CRL 分发点（见 ensureCrl）。这一步只对认 HKCU 这个值的老式 WinINET 客户端生效，
    //    所以默认不开，避免为了一个边缘收益去动全局安全设置。
    if (this.config.relaxRevocationCheck === true) {
      try {
        const r = await disableRevocation();
        this.takeoverState = { ...(this.takeoverState ?? {}), revocation: r.saved };
        checks.push({
          id: 'revocation',
          ok: r.ok,
          detail: r.changed
            ? '已把 WinINET 的 CertificateRevocation 置 0（只影响认这个值的老式客户端；curl/git 不读它）'
            : 'CertificateRevocation 本就是 0，无需改动',
          warnings: r.warnings,
        });
      } catch (e) {
        checks.push({ id: 'revocation', ok: false, detail: `关闭吊销检查失败：${String(e && e.message)}` });
      }
    }

    this.config.enabled = true;
    await this.storage.writeConfig(this.config);
    return { ok: checks.every((c) => c.ok), checks };
  }

  async stop() {
    const checks = [];
    await this.engine.stop().catch((e) => checks.push({ id: 'port', ok: false, detail: String(e && e.message) }));
    checks.push({ id: 'port', ok: true, detail: '已停止监听' });

    // 先还系统代理：留着 PAC 却关掉引擎，会让受管域名彻底打不开（流量被指到一个没人听的端口）。
    if (this.takeoverState?.saved) {
      try {
        const r = await restoreProxy(this.takeoverState.saved);
        checks.push({ id: 'proxy', ok: r.ok, detail: r.ok ? '已还原系统代理设置' : `还原后与快照不一致：${JSON.stringify(r.restored)}` });
      } catch (e) {
        checks.push({ id: 'proxy', ok: false, detail: `还原系统代理失败：${String(e && e.message)}` });
      }
      this.takeoverState = { mode: null, saved: null, applied: null };
    }

    // 还原吊销检查开关（接管期间被我们关掉的那个）。
    if (this.takeoverState && 'revocation' in this.takeoverState) {
      try {
        const r = await restoreRevocation(this.takeoverState.revocation);
        checks.push({
          id: 'revocation',
          ok: r.ok,
          detail: this.takeoverState.revocation ? `已还原 CertificateRevocation=${this.takeoverState.revocation.value}` : '已删除本插件写入的 CertificateRevocation',
          warnings: r.warnings,
        });
      } catch (e) {
        checks.push({ id: 'revocation', ok: false, detail: `还原吊销检查失败：${String(e && e.message)}` });
      }
    }

    try {
      const r = await revertHosts();
      this.hostsState = { active: false, entries: [] };
      checks.push({ id: 'hosts', ok: true, detail: r.changed ? '已从 hosts 移除本插件的段' : 'hosts 没有本插件的段' });
    } catch (e) {
      checks.push({ id: 'hosts', ok: false, detail: String(e && e.message) });
    }

    if (this.config) {
      this.config.enabled = false;
      await this.storage.writeConfig(this.config).catch(() => {});
    }
    return { ok: checks.every((c) => c.ok), checks };
  }

  /** 重装 CA：先删再装（指纹变了时必须走这条，否则浏览器验不过新叶证书）。 */
  async reinstallCa() {
    await uninstallCa(CA_SUBJECT_CN);
    return installCa(this.storage.file('caCer'), CA_SUBJECT_CN);
  }

  /** PAC 脚本文本（由 lib/proxy.mjs 在 `GET /proxy.pac` 时取用）。 */
  pacText() {
    if (!this.config) return '';
    const host = this.config.proxyHost || '127.0.0.2';
    const port = this.config.proxyPort || 8843;
    return buildPac(this.managedDomains(), host, port);
  }

  /** 当前系统代理是否已经指着我们（只读，用于 status）。 */
  async proxyTakeoverState() {
    const host = this.config?.proxyHost || '127.0.0.2';
    const port = this.config?.proxyPort || 8843;
    try {
      return await currentTakeover(host, port);
    } catch (e) {
      return { active: false, error: String(e && e.message) };
    }
  }

  async hasMatchingThumbprint(want) {
    const r = await import('./ca-install.mjs').then((m) => m.installedThumbprints(CA_SUBJECT_CN));
    return r.includes(want);
  }

  // ── 状态 ──────────────────────────────────────────────────────────────────
  async status() {
    const hostsText = await readHosts();
    const own = parseOwnBlock(hostsText);
    const caInstalled = await isCaInstalled(CA_SUBJECT_CN);
    const managed = this.managedDomains();
    const plain = managed.filter((d) => !d.includes('*'));
    const conflicts = detectConflicts(hostsText, plain);
    const writable = await probeHostsWritable();
    const missing = missingManaged(hostsText, plain);
    const takeover = this.config?.takeover ?? 'auto';
    const proxyHost = this.config?.proxyHost ?? '127.0.0.2';
    const proxyPort = this.config?.proxyPort ?? 8843;
    const proxyState = await this.proxyTakeoverState();
    let revocationValue = null;
    try {
      const r = await readRevocation();
      revocationValue = r ? Number(r.value) : null;
    } catch { /* 读不到就当 null，不影响状态主体 */ }
    const effective = takeover === 'auto' ? (writable ? 'hosts' : 'pac') : takeover;
    // hosts 模式下「是不是真在生效」取决于三件事：段在、域名齐、且没有被别家的行压在后面
    // （Windows 取首个命中，被压住就等于没生效）。
    const shadowed = conflicts.some((c) => c.severity === 'blocked');
    const hostsEffective = own.active && missing.length === 0 && !shadowed;
    return {
      enabled: Boolean(this.config?.enabled),
      autoStart: this.config?.autoStart !== false,
      listening: this.engine.listening,
      listen: this.config ? `${this.config.listenHost}:${this.config.listenPort}` : null,
      proxy: {
        listening: this.engine.proxyListening,
        listen: `${proxyHost}:${proxyPort}`,
        pacUrl: pacUrlFor(proxyHost, proxyPort),
        mode: takeover,
        effective,
        // active 的含义随 effective 变：hosts 模式 = hosts 段真的首命中生效；
        // pac/fixed = 注册表里确实指着我们。pacActive 单独给出，供管理页区分「残留」与「在用」。
        active: effective === 'hosts' ? hostsEffective : Boolean(proxyState.active),
        pacActive: Boolean(proxyState.active),
        autoConfigURL: proxyState.autoConfigURL ?? null,
        proxyEnable: proxyState.proxyEnable ?? 0,
        proxyServer: proxyState.proxyServer ?? null,
        // Schannel/WinINET 的吊销检查开关：1 = 开着（我们的叶证书没有 CRL，curl/git/WinHTTP 会报
        // CRYPT_E_NO_REVOCATION_CHECK），0 = 已关（接管期间应为 0），null = 这个值不存在于注册表。
        revocation: revocationValue,
      },
      ca: { installed: caInstalled, subject: CA_SUBJECT_CN },
      crl: {
        url: this.crlUrl(),
        served: Boolean(this.crlDer && this.engine.proxyListening),
        nextUpdate: this.crlMeta?.nextUpdate ?? null,
        number: this.crlMeta?.crlNumber ?? null,
      },
      hosts: {
        active: own.active,
        entries: own.entries.length,
        expected: plain.length,
        writable,
        missing,
      },
      domains: managed,
      nodes: Object.fromEntries(managed.map((d) => [d, (this.nodes[d] ?? []).length])),
      conflicts,
      stats: { ...this.engine.stats },
      recent: this.decisions.slice(-40),
      lastError: this.lastError,
      upstream: this.config?.upstream ?? null,
      smart: this.smart?.snapshot() ?? { enabled: this.config?.smart !== false },
      health: this.engine.health.hostSnapshot(),
    };
  }

  // ── 节点维护（供管理页 / 外部 AI 调用） ───────────────────────────────────
  readonlyNodes() {
    return JSON.parse(JSON.stringify(this.nodes));
  }

  async replaceNodes(next) {
    if (!next || typeof next !== 'object' || Array.isArray(next)) {
      throw new Error('nodes must be an object keyed by domain');
    }
    for (const [domain, list] of Object.entries(next)) {
      if (!Array.isArray(list)) throw new Error(`nodes[${domain}] must be an array`);
      for (const n of list) {
        if (!n || typeof n.ip !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(n.ip)) {
          throw new Error(`nodes[${domain}] contains an invalid ip: ${JSON.stringify(n)}`);
        }
        if (n.sni && !['real', 'none', 'cdn'].includes(n.sni)) {
          throw new Error(`nodes[${domain}] sni must be real|none|cdn`);
        }
      }
    }
    const leafBefore = this.leaf?.certPem ?? null;
    this.nodes = next;
    await this.storage.writeNodes(next);
    await this.ensureLeaf();          // 域名集可能变了 → 重签叶证书
    // 只有叶证书真的换了才需要重启引擎（引擎在 start() 时把证书抓死了）。
    // 纯节点更新是热生效的：引擎每次连接都现读 deps.getNodes()。重启会掐断所有
    // 正在传输的连接 —— 智能修复绝不能顺手把用户的下载断掉。
    if (this.engine.listening && (this.leaf?.certPem ?? null) !== leafBefore) {
      this.logger.info?.('[dsh-accelerator] 域名集变化 → 重载叶证书并重启引擎');
      const proxyWasUp = this.engine.proxyListening;
      await this.engine.stop();
      await this.engine.start();
      if (proxyWasUp) await this.engine.startProxy();   // stop() 会把代理监听一起关掉，别忘了拉回来
    }
    return this.readonlyNodes();
  }

  async upsertNode(domain, node) {
    const next = this.readonlyNodes();
    const list = Array.isArray(next[domain]) ? next[domain] : [];
    const idx = list.findIndex((n) => n.ip === node.ip);
    if (idx >= 0) list[idx] = { ...list[idx], ...node };
    else list.push(node);
    next[domain] = list;
    return this.replaceNodes(next);
  }

  async removeNode(domain, ip) {
    const next = this.readonlyNodes();
    const list = (next[domain] ?? []).filter((n) => n.ip !== ip);
    if (list.length === 0) delete next[domain];
    else next[domain] = list;
    return this.replaceNodes(next);
  }

  async updateConfig(patch) {
    const before = this.config?.takeover ?? 'auto';
    const beforeProxy = `${this.config?.proxyHost ?? ''}:${this.config?.proxyPort ?? ''}`;
    this.config = { ...this.config, ...patch, upstream: { ...this.config.upstream, ...(patch.upstream ?? {}) } };
    await this.storage.writeConfig(this.config);
    // 代理地址/端口变了 → CDP 地址就变了，CRL 与叶证书都要按新地址重签。
    const afterProxy = `${this.config.proxyHost ?? ''}:${this.config.proxyPort ?? ''}`;
    if (beforeProxy !== afterProxy) {
      await this.ensureCrl();
      await this.ensureLeaf();
    }
    // 接管方式改了且加速正在跑 → 立刻按新方式重来一遍（顺手把旧方式撤掉）。
    const after = this.config.takeover ?? 'auto';
    if (this.config.enabled && (this.engine.listening || this.engine.proxyListening) && before !== after) {
      await this.stop();
      await this.start();
    }
    return this.config;
  }
}
