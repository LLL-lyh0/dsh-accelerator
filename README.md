# dsh-accelerator

本机加速器插件：**回环 MITM 代理 + hosts 引导 + 节点池优选**，专治 SNI 阻断。
管理界面在 DSH 的 **设置 → 加速器**。

它不依赖任何自建服务器：全部效果来自本机的一台回环 HTTPS 代理，
以及一份**可被外部 AI / 脚本读写的节点池 JSON**。

## 开箱即用（默认就开着）

- **首次启动自带节点池**：文件不存在时用内置种子池（实测可用的 IP + 每域名 SNI 策略）落盘。
- **`enabled` 与 `autoStart` 默认 `true`**：DSH 一打开就自动拉起加速，**不需要再点一次**；
  启动后立即做一轮自检，不通的域名当场换节点。
- **智能加速**（`smart: true`，默认）：每 15 分钟巡检 + 引擎每次连接失败时立即触发，
  自动「测活 → DoH 补池 → 换到最快的存活节点 → 复验」，结论写进 `status.smart`。
- **设置页管理界面**：DSH 的 **设置 → 加速器**（`settings.section`）。
- **内置技能 `accelerator-repair`**：连接频繁失败时的三条修复路径（换节点 / 去 GitHub 搜上游更新 /
  隐私与数据安全核查），正文在 `skill/SKILL.md`。

## 它怎么工作

```
应用（认 hosts 的浏览器/Steam 等）
   │  github.com  →  127.0.0.2（hosts 引导，只写自己那一段）
   ▼
本机 MITM 引擎（127.0.0.2:443，自签 CA + 多 SAN 叶证书）
   │  按域名并发竞速多个候选节点（TCP + TLS 握手，谁先成功用谁）
   ▼
真实 IP（来自节点池；池子由实测 + DoH 补 IP 维护）
```

三个关键实测结论决定了实现形态（详见 `accelerator-analysis.md` 的对照分析）：

1. **SNI 策略是按域名逐个定的，不是全局开关**。Akamai（steamcommunity）与
   CloudFront（huggingface）在真 SNI 下会被 RST，**不发 SNI** 就能过；
   Cloudflare / GitHub 直连段反过来需要真 SNI。所以每个节点都带
   `sni: 'real' | 'none' | 'cdn'`。
2. **不能用系统 DNS 解析上游**：加速器会把 hosts 写成 127.0.0.1，代理会连回自己。
   DoH 也不可信（本机实测被污染），所以 DoH 只用来**补候选**，能不能用一律靠实测。
3. **拿到 TLS 握手成功就算这个节点可用**，不要等应用层首字节：
   TLS 1.3 握手完成后服务端立刻推 NewSessionTicket，会被误当成应用数据。

## 外部 AI 扩展（需求：支持外部使用 AI 扩展、更新节点）

### 通路一：文件（任何 AI / 脚本都能改）

`%USERPROFILE%\.dsh\storages\dsh-accelerator\nodes.json`

```json
{
  "github.com": [
    { "ip": "140.82.114.4", "sni": "real" },
    { "ip": "20.205.243.166", "sni": "none" }
  ],
  "steamcommunity.com": [
    { "ip": "23.218.239.27", "sni": "cdn", "sniValue": "a248.e.akamai.net" }
  ]
}
```

改完文件后，在管理页点「重载文件」，或让会话内 AI 调用 `accelerator` 工具
`action: reload_nodes`。同目录还有 `config.json`（策略）与自动生成的
`ca.pem` / `ca.key`（根证书，私钥只在这里，不进证书存储）、`leaf.pem` / `leaf.key`（叶证书，
域名集变化时自动重签）、`dsh-accelerator-ca.cer`（供 `certutil` 安装的公钥 DER）。

### 通路二：`accelerator` agent 工具（会话内 AI 直接调）

| action | 说明 |
| --- | --- |
| `status` | 运行状态、受管域名、hosts 冲突 |
| `start` / `stop` | 启停（start 会写 hosts、按需装根证书） |
| `nodes_get` / `nodes_set` | 读/写整个节点池 |
| `node_upsert` / `node_delete` | 单节点增删改（`{domain, ip, sni, sniValue}`） |
| `probe` | 全部节点测活，只报告不改数据 |
| `curate` | 测活 + DoH 补候选 + 只留最快可用节点写回 |
| `verify` | **经本机代理真发一次 HTTPS**，逐域名返回真实状态码与耗时 |
| `repair` | 先 `verify`，再对不通的域名换节点（测活 + 补池）并**复验**；`force` 绕过 90s 冷却 |
| `config_set` | 改策略（`enforce` / `bypass` 进程名、上游、监听地址、`smart` / `autoStart`） |
| `reload_nodes` | 采纳外部改过的 `nodes.json` |
| `log` | 最近日志 |

### 通路三：HTTP（管理页用，同源围栏）

`/api/dsh-accelerator/{status,nodes,config,log,probe,verify}`（GET）与
`/api/dsh-accelerator/{start,stop,reload-nodes,nodes,node-upsert,node-delete,config,ca-reinstall,curate,verify,repair,selfcheck}`（POST）。
只接受回环 Host + 同源 Origin。

## 三项扩展需求对应到哪里

| 需求 | 落地 |
| --- | --- |
| 指定加速特定软件 | `config.enforce`：填进程名后，只有这些进程的连接被接管（PID 由 netstat 反查，约 84ms，带 500ms 缓存） |
| 强制某软件走本加速 | 同上；`config.bypass` 是反向白名单。不认代理环境变量的原生程序靠 hosts 段生效 |
| 配置其它外部上游 | `config.upstream`：`direct` / `http` / `socks5` + 地址端口（对应 Watt Toolkit 的 TwoLevelAgent 行为） |

## 安全取舍（与两个商业加速器的关键差异）

- **私钥不导入证书存储**：Watt Toolkit 与 Steamcommunity_302 的根证书都在
  `Cert:\CurrentUser\Root` 里且 `HasPrivateKey=True`，同用户进程可导出后伪造任意站点。
  本插件的 CA 私钥只在 `~/.dsh/storages/dsh-accelerator/` 下，装进信任库的只有公钥 `.cer`。
- **hosts 只写自己那一段**（`# >>> DSH Accelerator Start >>>` … `<<< End <<<`），
  并在检测到 `# Steam++ Start` 等别家段时于管理页告警 —— 两个加速器同时写 hosts 会互相干扰。
- 看门狗每 30s 校验：引擎掉线自动回滚 hosts 并重启；hosts 段被别人删掉会自动补回。

## hosts 被改成只读时：改用 PAC 接管

Windows 上 hosts 的默认 ACL 允许 `Users` 写，但**提权运行的别家加速器会把它收成 `Users:(RX)`**
（本机实测：Steamcommunity_302 重写 hosts 后 `Everyone:FullControl` 消失，标准用户只剩读，
并且它会顺手删掉我们段里与它重叠的行）。插件对此**不报错、不硬闯**，而是准备了两条接管通路：

| 接管方式 | 原理 | 改什么 | 生效范围 |
| --- | --- | --- | --- |
| `hosts` | 把受管域名指到 `127.0.0.2`，再在本地做 TLS 终结 | `hosts` 文件 | 几乎所有程序（包括不认代理的） |
| `pac`（默认回退） | 写系统代理自动配置，只把受管域名交给本机代理 | `HKCU\...\Internet Settings\AutoConfigURL` | 认系统代理的程序（Edge/Chrome/WinHTTP 系） |
| `fixed` | 把整机 HTTP(S) 代理指到本机端口 | 同上的 `ProxyServer` + `ProxyEnable=1` | 认系统代理的**全部**流量（范围最大，慎用） |

- `takeover` 默认 `auto`：**能写 hosts 就用 hosts，写不了就自动切 PAC**，`status.proxy.effective` 与设置页
  「接管方式」一行会如实显示当前用的是哪一种。
- `pac` 走的是**本地 HTTP 代理 + `CONNECT`**：受管域名被 MITM 后走节点竞速，其余域名**盲隧道转发**
  （看到的是上游真实证书，不解密、不记录）。
- `stop()` 会**先还原系统代理再回滚 hosts** —— 留着 PAC 却关掉引擎会让受管域名彻底打不开。
- **切换回 `hosts` 时会自动清掉上一轮我们自己写的 PAC/固定代理**（`clearOurTakeover()`）：
  只删 `AutoConfigURL` 严格等于本插件 PAC 地址的那一项、以及严格等于本插件地址的 `ProxyServer`+`ProxyEnable`，
  **别家留下的 `ProxyServer` / `ProxyOverride` 一个字节都不动**（这是不能用「还原空快照」代替的原因）。

### 谁先命中：hosts 里「写进去」≠「生效」
Windows 解析 hosts **取第一个命中**，重叠的映射**不可能都生效**。别家加速器（Steamcommunity_302）会把
`127.0.0.1 <域名> #S302` 写在 hosts 很靠前的位置，本机实测它第 12 行、我们的段在第 880 行 ——
结果我们**一个域名都没生效**，而旧的冲突判定却还在说「两者会同时生效并互相干扰」，是错的。

现在 `applyHosts()` 走 `composeHosts()`：发现别家的映射行里有受管域名时，**把我们的段插到它前面**，
保证首个命中；`detectConflicts()` 也据此分成两种：

| severity | 含义 | 管理页显示 |
| --- | --- | --- |
| `blocked` | 别家的行在我们**前面** → 我们的引导对这 N 个域名**不生效** | `⚠ hosts 被压制：<来源> 的 N 个域名排在前面，我们的引导未生效` |
| `info` | 别家的行在我们**后面** → 我们优先命中，共存 | `hosts 共存：<来源> 也管 N 个域名（排在我们之后，我们优先）` |

- `start()` 的 hosts 检查在存在 `blocked` 时**判为不通过**并给出「会把本插件的段插到它前面」的说明；
- 30 秒 watchdog 在 hosts 模式下发现 `missing` 非空或出现 `blocked`，会**幂等重跑 `start()`** 自动重排；
- 没有别家冲突时**仍然追加到末尾**，不无谓改动别人的文件（`composeHosts().insertAt === -1`）。

- **边界**：`git` / `curl` / `npm` 自带 CA bundle 且不读 PAC，所以它们不受 PAC 影响
  （要走加速得自己设 `HTTPS_PROXY=http://127.0.0.2:<proxyPort>`）。被 hosts 模式接管时它们**默认不需要额外配置** ——
  叶证书带了 CRL 分发点，Schannel 的吊销检查能过（见下一节）；只有在极老或策略更严的机器上才需要退回
  `git config --global http.sslCAInfo ~/.dsh/storages/dsh-accelerator/ca.pem`。
- 想让 hosts 模式回来，两条路任选：**① 以管理员身份运行 DSH；② 管理员执行一次**
  `icacls "C:\Windows\System32\drivers\etc\hosts" /grant Users:F`（别家加速器可能再改回去）。

## 指定域名走外部上游（itch.io 这类域名的唯一真解）

有些域名不是「IP 选得不好」，而是被 **SNI 整段阻断**：同一台边缘服务器，SNI 填别的域名能通、
填目标域名一律 RST（本机实测：`151.101.1.44` 上 SNI=`www.fastly.com`/`example.com` 都 301，
SNI=`itch.io` 一律 `ECONNRESET`）。这类域名换任何 IP、换任何 SNI 策略都无解——
RST 跟着 SNI 走，不跟着 IP 走。

唯一真解是把该域名的流量**整域交给一个外部 HTTP/SOCKS5 上游**转发：

```json
// ~/.dsh/storages/dsh-accelerator/config.json
{
  "upstreams": {
    "itch.io": { "mode": "socks5", "host": "127.0.0.1", "port": 10808 },
    "*.itch.zone": { "mode": "http", "host": "127.0.0.1", "port": 10809 }
  }
}
```

- 命中的域名**完全经上游**（CONNECT 交出去，不竞速 IP）；上游是全局共享配置，
  也可以只对 itch.io 一个域名配。
- 同时要把该域名引导到本机：hosts 模式下加进 hosts（我们的段会自动抢首个命中）；
  PAC 模式下 PAC 脚本按受管域名生成，把域名加进 `nodes.json`（哪怕先不填候选）
  就会让它出现在 PAC 里。
- 没配上游时，这类域名只能失败（引擎不会凭空造通路）——如实报告，别反复 repair。

## 证书链：为什么命令行客户端一握手就被拒

`curl.exe`（Windows Schannel，走用户 Root 库）与 `git`（Git for Windows 默认 schannel 后端）最初对所有受管域名都是：

```
curl: (35) schannel: next InitializeSecurityContext failed:
  CRYPT_E_NO_REVOCATION_CHECK (0x80092012)      # 中文：吊销服务器无法验证证书是否吊销
fatal: unable to access 'https://github.com/...': schannel: next InitializeSecurityContext failed: ...
```

原因不是链不对，而是**叶证书是本地 CA 现签的、没有 CRL/OCSP 分发点**，Schannel 判「无法确认吊销状态」就直接拒绝握手。
Chrome/Edge 用 BoringSSL、Node 自带 OpenSSL，都不做这道检查，所以只有命令行客户端中招（这也解释了「浏览器正常、`git` 报证书错」）。

修法是让证书**自带 CRL 分发点（CDP），并在本机把 CRL 服务起来**：

1. `lib/certs.mjs` 的 `issueLeaf(ca, domains, days, { crlUrl })` 往叶证书写 CDP，指向本机代理的 `/dsh-accelerator.crl`；
2. `createCrl(ca, { days, crlNumber })` 签一份 CRL（v2、AKI + crlNumber、sha256 签名）；
3. **代理在任何接管模式下都要监听** —— hosts 模式下它只干「分发 CRL」这一件事，`GET /dsh-accelerator.crl` 回 `application/pkix-crl`；
4. `status.crl = { url, served, nextUpdate, number }` 可看它是否在服务；`start()` 每次都会 `ensureCrl()` + `ensureLeaf()`（幂等），
   所以改代理端口/域名集不需要重启 DSH。

两个会把人卡很久的坑：

- **CRL 的 `crlExtensions` 必须是 `[0]`（`0xa0`），不能是 `[3]`（`0xa3`）**。`[3]` 是**证书** `TBSCertificate.extensions` 的标签；
  DER 自洽、Node/OpenSSL 都能读，但 Windows CryptoAPI 解析不了它 —— 表现极具误导性：**CRL 被成功下载（HTTP 200、字节数正确）
  却报 `CRYPT_E_NO_MATCH`，链状态停在 `CERT_TRUST_IS_OFFLINE_REVOCATION`**。`lib/certs.selftest.mjs` 有这条回归断言，
  且用变异验证过（改回 `[3]` 会 FAIL）。
- **CryptoAPI 按 URL 负面缓存「吊销取不到」**：同一端口/URL 上先失败一次，之后即使服务已修好也是秒失败。复验必须**换端口/换 URL**，
  或用 `SKIP_A=1 node test/live-crl.mjs <域名> <新TLS端口> <新代理端口>`。`certutil -urlcache '*' delete` 在非管理员下无效（rc=3）。
- 兜底开关：`relaxRevocationCheck`（默认 `false`）只把 `HKCU\...\Internet Settings\CertificateRevocation` 置 0，
  对老式 WinINET 客户端有用；**`curl.exe` / `git(schannel)` 不读这个值**，不要指望它。

实测（真实客户端，经 hosts → `127.0.0.2:443`，不带 `--ssl-no-revoke`）：`curl.exe` 8/9 拿到真实状态码
（github.com 200、api.github.com 200、raw.githubusercontent.com 301、steamcommunity.com 200、huggingface.co 200、
opencode.ai 200、openrouter.ai 200、api.steampowered.com 404），`git ls-remote https://github.com/octocat/Hello-World.git HEAD`
成功返回 `7fd1a60b…HEAD`；唯一失败的 `store.steampowered.com` 是**上游整体不可达**（多 DoH 源只给 2 个 IP、完整 GET 0/4 可用），
与加速器无关。

## 配置项（`config.json`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `autoStart` | `true` | DSH 启动时自动拉起（不用再点一次） |
| `smart` | `true` | 智能巡检 + 自动换节点 + 自动复验 |
| `smartIntervalMin` | `15` | 智能巡检间隔（分钟） |
| `takeover` | `auto` | 接管方式：`auto` / `hosts` / `pac` / `fixed` |
| `proxyHost` / `proxyPort` | `127.0.0.2` / `8843` | PAC / 固定代理模式的本地代理监听 |
| `listenHost` / `listenPort` | `127.0.0.2` / `443` | `127.0.0.1:443` 常被 Steamcommunity_302 占用 |
| `installCaOnEnable` | `true` | 启用时自动把 CA 装进 `CurrentUser\Root` |
| `upstream` | `{mode:'direct'}` | 可插拔外部上游（`direct` / `http` / `socks5`）。**语义是「兜底」而不是「级联一切」**：仅当某域名直连池全挂时经它再试一次 |
| `upstreamFallback` | `true` | 直连池全挂时是否回退到全局上游（`false` = 直连失败就失败，不碰上游） |
| `upstreams` | `{}` | **按域名上游覆盖**（级联）：`{"itch.io":{"mode":"socks5","host":"127.0.0.1","port":10808}}` —— 该域名完全经上游转发，不选 IP。用于被 SNI 整段阻断、换任何 IP 都无解的域名 |
| `enforce` / `bypass` | `[]` | 强制接管 / 永不接管的进程名 |
| `domainGroups` | `{}` | 每个域名的接管开关（`false` 关闭） |
| `relaxRevocationCheck` | `false` | 兜底开关：把 `CertificateRevocation` 置 0（只对老式 WinINET 客户端有效；`curl.exe`/`git` 不读它） |

## 自检

```bash
node lib/certs.selftest.mjs     # 证书链 + CDP/CRL（CA 自签、叶证书可验、异 CA 验不过、CRL 扩展块是 [0]）
node lib/engine.selftest.mjs    # 引擎端到端（真实 200 + 客户端 TLS 校验通过）
node lib/proxy.selftest.mjs     # 代理/PAC 通路（CONNECT→MITM、盲隧道、PAC 正文、CRL、404）
node test/client-smoke.mjs      # 设置页（真实 client.js 跑在 React/DOM 桩里，69 项断言）
node test/hosts-smoke.mjs       # hosts 纯函数（回滚不变量 + 302/Watt 归因，28 项断言）
node test/status-shape.mjs      # status() 契约（含通配不进 hosts，19 项断言）
node test/smart-smoke.mjs       # 智能修复的池子下限保护（存活不足时不缩池，13 项断言）
node test/upstream-smoke.mjs    # 每域名上游覆盖 + 池子全挂回退（本地 SOCKS5 上游，6 项断言）
node test/live-verify.mjs       # 对【正在运行】的引擎逐域名真发 HTTPS（不启引擎、不动 hosts）
node test/live-takeover.mjs     # PAC 接管验收：真写系统代理→验全链路→**必定还原**
node test/live-crl.mjs          # CRL/Schannel 验收（curl.exe 真跑；复验请换端口并 SKIP_A=1）
node test/live-ab.mjs           # 真实平台 A/B：直连最优 IP vs 经本机加速器（逐域名结论）
```

`live-crl.mjs` 用法：`node test/live-crl.mjs [域名] [TLS端口] [代理端口]`；**复验一定要换端口或
`SKIP_A=1`** —— CryptoAPI 会按 URL 负面缓存「吊销状态取不到」，同一 URL 上先失败一次后秒失败。

`live-takeover.mjs` 会真的改一次 `HKCU` 的系统代理设置（所以它跑完会回读注册表确认已还原，
失败时把手工修复命令打印出来）。它用 `8445`（TLS）+ `8845`（代理）两个与插件默认值错开的端口，
所以**即使 DSH 里的加速器正开着也能独立跑**。若中途被打断而留下残留：

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL
```

`live-verify.mjs` 是唯一能回答「现在到底通不通」的自检：它直接读
`~/.dsh/storages/dsh-accelerator/{ca.pem,nodes.json}`，对本机 `127.0.0.2:443` 发真实请求，
每个域名回一个状态码与耗时（本机实测 9/9 通过、总耗时约 11.7s）。可选参数：
`node test/live-verify.mjs 127.0.0.2:443 github.com opencode.ai`。
