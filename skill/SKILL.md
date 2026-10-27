---
name: accelerator-repair
description: 修复本机 dsh-accelerator（本地加速器）连不上、变慢、证书报错的问题，并在需要时扩充节点池。当用户说「github 打不开 / steam 社区打不开 / huggingface 连不上 / 加速器不管用了 / 换节点 / 节点失效 / 加速器怎么修 / 更新节点」或某个域名反复超时、TLS 报错、502 时使用。也用于配置强制走加速的程序、屏蔽不想被接管的程序、切换外部上游（HTTP/SOCKS5），以及检查加速带来的隐私与数据安全影响。
---

# 加速器修复与扩充

本机装着一个**本地加速器**（插件 `dsh-accelerator`）：它在 `127.0.0.2:443` 起一个
本机 MITM 代理，把被 SNI 阻断的域名（github / steamcommunity / huggingface /
opencode / openrouter …）指到**实测可用的真实 IP** 上，并按域名使用不同的 SNI 策略。
它不改 DNS 服务器、不依赖你的服务器、也不依赖任何第三方节点服务——**节点池就是
一份可以随时改写的 JSON 文件**。

你有两个操作面，任选其一（推荐工具面，它自带围栏与校验）：

| 面 | 入口 | 适合 |
|---|---|---|
| 工具面 | `accelerator` 工具（`action` 枚举：`status` `verify` `repair` `curate` `nodes_get` `nodes_set` `node_upsert` `node_delete` `config_set` `reload_nodes` `probe` `log`） | 会话里直接做，有 JSON 结构化返回 |
| 文件面 | `%USERPROFILE%\.dsh\storages\dsh-accelerator\nodes.json` / `config.json` | 批量改、外部脚本改；改完必须 `accelerator reload_nodes`（或 `POST /api/dsh-accelerator/reload-nodes`） |

HTTP 面（同源，端口即 DSH 网页端口）：`GET /api/dsh-accelerator/status|nodes|verify|probe|log`、
`POST /api/dsh-accelerator/start|stop|repair|verify|curate|nodes|node-upsert|node-delete|config|reload-nodes|ca-reinstall|selfcheck`。

## 第 0 步：永远先量，不要猜

```text
accelerator { action: "status" }     # enabled / listening / proxy.effective / proxy.active / ca.installed / hosts.writable / hosts.missing / conflicts / health
accelerator { action: "verify" }     # 经本机代理逐域名真发一次 HTTPS，返回真实状态码
accelerator { action: "log" }        # 插件自己的环形日志（最近 80 条）
```

`verify` 返回里 `ok:false`、`note:"handshake-only"`、或 `status>=500` 都算**不通**
（判定函数在 `lib/verify.mjs` 的 `isBadResult`）。没有这一步，任何「已经修好了」都是假的。
注意 `verify` 的 TLS 握手是**与本机引擎**完成的，慢域名（github.com / store.steampowered.com）可能要 6–20s
才算完，别把它当死等 —— 真实等待上限在 `lib/verify.mjs` 的 `STATUS_WAIT_MS`（20s）。

四个最常见的误判，先排掉再谈修复：

- `listening:false` → 引擎根本没跑（不是节点坏了）。`accelerator { action: "start" }`。
- `ca.installed:false` → 证书没装，客户端会报 `self signed certificate` / `unable to verify the first certificate`。`accelerator { action: "config_set", config: { installCaOnEnable: true } }` 后重启加速，或 `POST /ca-reinstall`。
- `hosts.writable:false` → **hosts 对本用户只读**（Windows 上常见：Steamcommunity_302 之类提权运行的加速器重写 hosts 时把 ACL 收成 `Users:(RX)`）。这是**权限问题，不是节点问题**：
  - `hosts.missing` 列出没能写进去的域名（别家加速器还会主动删我们段里与它重叠的行）；
  - **但加速不该因此失效**：`takeover` 为 `auto`（默认）时插件会自动改用 **PAC 接管**，`status.proxy.effective === "pac"`、`status.proxy.active === true` 就说明系统代理已指向本机（`HKCU\...\Internet Settings\AutoConfigURL`）。先看这两项，再看 `hosts`。
  - 想换回 hosts 模式：要么以管理员身份跑 DSH，要么管理员执行一次
    `icacls "C:\Windows\System32\drivers\etc\hosts" /grant Users:F`（别家加速器可能再改回去）；
  - **不要**因此宣称「加速器坏了」，也不要反复 `start` 刷屏。
- `proxy.active:false` 而 `effective` 是 `pac`/`fixed` → PAC 地址没写进系统（或刚被别的软件覆盖）。`accelerator { action: "start" }` 会重写一次；写完 `AutoConfigURL` 应等于 `proxy.pacUrl`。
- `git` / `curl` 报 `CRYPT_E_NO_REVOCATION_CHECK`（中文「吊销服务器无法验证证书是否吊销」）→ 这是 **Windows Schannel 的吊销检查**，不是链不对、也不是节点问题：叶证书必须带 CRL 分发点（CDP）且本机把 CRL 服务起来（`status.crl.served === true`）。**别去改节点池、也别让用户关 `--ssl-no-revoke`**。历史坑：CRL 的 `crlExtensions` 写成了 `[3]`（证书的标签）而不是 `[0]` —— CryptoAPI 会「下载成功但解析失败」并报 `CRYPT_E_NO_MATCH`，见 `README.md` 的「证书链」一节；`lib/certs.selftest.mjs` 有回归断言。
- **PAC 的边界**：`git` / `curl` / `npm` 自带 CA bundle 且**不读 PAC**，所以 PAC 模式下它们不经加速。用户若要用它们走加速，得自己设 `HTTPS_PROXY=http://<proxyHost>:<proxyPort>`。**hosts 模式下它们默认能直接用**（叶证书带 CDP，Schannel 的吊销检查能过）；只有在极老/更严策略的机器上才需要 `git config --global http.sslCAInfo ~/.dsh/storages/dsh-accelerator/ca.pem`。
- `conflicts` 非空 → 别家加速器（Steam++/Watt Toolkit、Steamcommunity_302）也往 hosts 里写了同名域名段。
  每一项形如 `{source, domains, shadowed, overridden, severity, ip, line}`（`#S302` → Steamcommunity_302，`# Steam++ Start/End` 区间 → Watt Toolkit）：
  - `severity:'blocked'` → 别家的映射行**排在我们的段之前**，Windows 取首个命中 ⇒ **我们的 hosts 引导对这些域名不生效**（「写进去了」≠「生效了」）。`start()` 会把我们的段插到它前面重排，watchdog 也会在 30 秒内自动纠正；重排后同一条会变成 `info`。
  - `severity:'info'` → 别家在我们之后，我们优先命中，只是共存，**不是故障**。
  - 报告给用户，**不要**擅自删别人的段。
- `takeover:'hosts'` 且 `proxy.pacActive:true` → 上一轮 PAC 的残留（我们不再监听代理端口，认系统代理的程序会被指到没人听的端口）。`start()` 现在会自动清掉（只清严格等于本插件地址的那几项，别家留下的 `ProxyServer`/`ProxyOverride` 不动）。

## 第 1 条路径：换节点（最常用，90% 的偶发失败在这里解决）

```text
accelerator { action: "repair" }                        # 先 verify，再对不通的域名换节点并复验
accelerator { action: "repair", domains: ["github.com"] }  # 只修一个
accelerator { action: "curate", domains: ["github.com"] }  # 测活 + DoH 补池，保留最快的存活节点（不 verify）
accelerator { action: "node_upsert", domain: "github.com", ip: "140.82.114.4", sni: "real" }
accelerator { action: "node_delete", domain: "github.com", ip: "20.205.243.166" }
```

- `repair` 每一步都会**重新验证**，返回 `healed` / `changed` / `bestMs`；`healed:false` 说明这个域名换完还是不通 —— 那时才需要第 2 条路径去**补新 IP**，而不是继续瞎换。
- 每个节点的 `sni` 字段是**可用性的决定因素**，不要随手改成 `real`：
  - `real` —— 用真实域名发 SNI（github / raw.githubusercontent / opencode / openrouter / api.steampowered 这类要它）。
  - `none` —— **完全不发 SNI**。Akamai 系（steamcommunity）和 CloudFront 系（huggingface）**只有** `none` 能过。
  - `cdn` —— 伪造成 CDN 通用名，`sniValue` 里写（如 `a248.e.akamai.net`）。
- 单节点失败是竞速常态，**不要**因为一次失败就把 IP 删掉；只有 `repair` 复验仍不通、或 `verify` 连续多轮都在这个域名上失败时才算坏。
- `nodes.json` 结构：`{ "github.com": [ { "ip": "140.82.114.4", "sni": "real" } ], "*.github.com": [ … ] }`。键可以是通配模式（`*.github.com` 命中 `api.github.com`，**不**命中 `github.com` 本身）。

细节与实测数据见 `resources/node-pool.md`。

## 第 2 条路径：去 GitHub 搜上游节点，更新节点池

当 `repair` 之后仍然不通（说明**现有 IP 段整体失效**），需要引入新的候选 IP。做法：

1. **先确认是「池子不够」而不是「配置错了」**：`accelerator { action: "verify", domains: ["<域名>"] }` 看错误类型。
   - `ECONNRESET` / 超时 → 大概率被阻断，需要新 IP（走本路径）。
   - 证书链错误 → 是 CA 问题（回第 0 步），不是节点问题。
2. **用 `github-manager` 技能搜公开的 IP/优选仓库**（本机已装，工具 `github_api`）：搜 `Github520`、`hosts`、
   `github hosts`、`steamcommunity hosts`、`cf 优选 IP`、`SNI 阻断` 这类关键词的仓库，读它的 `hosts` / `*.txt` / `*.json` 正文（`github_api { method: "GET", path: "/repos/<owner>/<repo>/contents/<file>" }`）。
3. **只取 IP，不执行仓库里的任何脚本**；每个 IP 都要标出来源（写进 `source` 注释字段或记在回复里），便于日后回滚。
4. **不要整体替换**。用 `node_upsert` 逐个加，或读出 `nodes_get` → 合并 → `nodes_set`；新 IP 的 `sni` 先按上面第 1 条路径的域名规则给，再让 `curate` 去测：
   ```text
   accelerator { action: "node_upsert", domain: "github.com", ip: "<新IP>", sni: "real" }
   accelerator { action: "curate", domains: ["github.com"] }   # 测活 + DoH 补池，保留最快的
   accelerator { action: "verify",  domains: ["github.com"] }   # 必须复验
   ```
5. 如果外部 AI 是直接改文件的，改完**必须** `accelerator { action: "reload_nodes" }` 才生效（写盘后不重载等于没改）。
6. 判据：只有 `verify` 返回 `status: 200`（或至少 3xx/4xx，且 `ok:true`）才算补成功。**连续两轮换 IP 都不通就停下来告诉用户**，别再烧时间——那通常说明这个域名在当前网络下确实没有可用通路（实测：`steamcommunity.com` 的直连路径就是全挂的，只能靠代理出去）。

详细的可复用检索与判读流程见 `resources/repair-playbook.md`。

## 第 3 条路径：连接私密性与数据安全（**每次修完都要过一遍**）

这个加速器是 **MITM**：你配了 `enforce` 的程序、以及访问受管域名的流量，都会经过本机代理，
代理能读到 TLS 明文。所以：

- **需要澄清给用户的事实**：本机代理只在本机，流量只发给用户自己配置的上游（默认 `direct`，即直连真实 IP），
  **不经过任何第三方服务器**；但明文确实在内存里经过本机进程。
- **敏感程序一律 `bypass`**（网银、支付、邮箱、密码管理器、公司 VPN/办公、IM 私聊）——这些域名本来也不需要加速：
  ```text
  accelerator { action: "config_set", config: { bypass: ["chrome.exe", "wechat.exe", "…"] } }
  ```
  `bypass` 里的进程**永不接管**；`enforce` 是强制接管，**只对明确要加速的程序用**，
  且要提前告知用户「该程序的所有流量都会被本机代理看到」。
- **不要**把凭据/令牌放进节点配置或上游配置里明文保存；`config.json` 的 `upstream.password` 是明文，能用
  不需要认证的上游就不要填用户名密码。
- **CA 私钥**在 `%USERPROFILE%\.dsh\storages\dsh-accelerator\ca.key`（**故意不放进 Windows 证书存储**——
  对比 Watt Toolkit / Steamcommunity_302 把带私钥的根证书留在 `CurrentUser\Root` 里，那是可以被同机任意进程导出的）。
  不要把 `ca.key` 复制到别处、不要贴进对话、不要提交进仓库。
- **用完可关**：`accelerator { action: "stop" }` 会摘掉 hosts 段并停止监听；要彻底移除信任，
  再从「用户证书 → 受信任的根证书颁发机构」删掉 `DSH Accelerator Root CA`。
- 日志里**不记录 URL 内容与正文**，只有域名、PID、进程名与字节数；如果用户连这些都不想留，
  告诉他日志只在内存里、重启即空。

安全模型全文与逐项核查表见 `resources/privacy-and-safety.md`。

## 硬规则

- 报「修好了」之前**必须有** `verify` 的 `ok:true`（不能只看 `repair` 的返回）。
- 不整体覆盖 `nodes.json`；不删 `repair` 里仍然存活的 IP；不动别家加速器写在 hosts 里的段。
- 不执行从 GitHub 抄来的任何脚本；只抄 IP。
- 用户没有明确要求时，不要新增 `enforce`（强制接管）条目——那是隐私影响最大的开关。
- 涉及「要不要接管某个程序」「要不要把某个域名加进来」时，先说明影响再动手。
