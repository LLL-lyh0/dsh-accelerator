# 修复手册：从症状到动作

## 症状 → 首查项

| 症状 | 先看 | 常见真因 |
|---|---|---|
| 浏览器/程序报 `ERR_CONNECTION_RESET`、`ERR_TIMED_OUT` | `status` 的 `listening` | 引擎没跑（不是节点问题） |
| `self signed certificate`、`unable to verify the first certificate`、`ERR_CERT_AUTHORITY_INVALID` | `status` 的 `ca.installed` | CA 没装/被删/被换成旧指纹 |
| 只有某些站点慢，其它正常 | `status` 的 `health` + `verify` | 该域名的 IP 段退化，需要换/补 |
| 同一站点一会儿通一会儿不通 | `refresh` 后看 `health[域名]` | 空 SNI / CDN 节点抖动，池里应有多个候选 |
| 完全打不开某个站点，换节点也没用 | `conflicts` 与上游配置 | 别家加速器抢 hosts（只有 `severity:'blocked'` 才是真被抢；`'info'` 是我们优先命中，不是故障）；或该域名在当前网络确实无通路 |
| 只有部分域名生效、`status.hosts.missing` 非空 | `status` 的 `hosts.writable` **与** `proxy.effective` / `proxy.active` | **hosts 对本用户只读**（别家提速软件把 ACL 收成 `Users:(RX)`，并把我们段里重叠的行删掉）。此时默认应已自动切 **PAC 接管**：只要 `proxy.effective === "pac"` 且 `proxy.active === true`，受管域名照常被加速（认系统代理的程序），**不要**把它当故障反复 `start`。`proxy.active:false` 才是真问题 → 重跑 `start` 重写 `AutoConfigURL` |
| `hosts` 里明明写着我们的段，却一个域名都没生效 | `conflicts[].severity` | Windows 解析 hosts **取首个命中**：别家的映射行排在我们前面 ⇒ `severity:'blocked'`。跑一次 `start`（或等 30 秒 watchdog）会把我们的段**插到它前面**重排，之后变成 `'info'` |
| `takeover` 是 `hosts`，但 `proxy.pacActive:true` | `status.proxy` | 上一轮 PAC 的**残留**：我们不再监听代理端口，认系统代理的程序会被指到没人听的端口。`start` 会自动清掉（只清严格等于本插件地址的项，别家的 `ProxyServer`/`ProxyOverride` 不动） |
| `git` / `curl` 报 `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` / 中文「吊销服务器无法验证证书是否吊销」 | `status.crl.served` 与 `crl.url` | **Schannel 的吊销检查**，不是链错、不是节点坏：叶证书必须带 CDP，且本机代理要把 `/dsh-accelerator.crl` 服务起来（hosts 模式下代理监听也只为此而开）。`served:true` 却仍然失败时看 `crl.number`/`nextUpdate` 是否还是修 `[0]` 标签之前的旧那份 → 重启加速（`stop` + `start`，`start()` 会跑 `ensureCrl()`）。**不要**让用户关 `--ssl-no-revoke`，也不要改节点池 |
| `git` / `curl` / `npm` 报自签证书（`self signed certificate` / `unable to verify the first certificate`）或经 PAC 明显不走加速 | `proxy.effective` | 三个都**自带 CA bundle 且不读 PAC**：PAC 模式下要加速得自己设 `HTTPS_PROXY=http://127.0.0.2:8843`；hosts 模式下默认能用（叶证书带 CDP），极老/更严的机器才需要 `git config --global http.sslCAInfo ~/.dsh/storages/dsh-accelerator/ca.pem` |
| 某些程序突然上不了网 | `config.enforce` / `bypass` | 被误加入 `enforce`；或上游 `mode` 配错（指向了不存在的代理） |
| 报 `EADDRINUSE` 起不来 | `status.listen` | 443 被占（`127.0.0.1:443` 常被 Steamcommunity_302 占）。改 `listenPort` 或改 `listenHost` |

## 标准修复回合（照抄执行顺序）

```text
1. accelerator { action: "status" }
2. accelerator { action: "verify" }                      # 拿到真正不通的域名集合 bad[]
3. 若 bad 为空 → 结束，回报「全部通过」+ 各域名状态码/耗时
4. accelerator { action: "repair", domains: bad }        # 换节点 + 复验
5. accelerator { action: "verify", domains: bad }        # 独立复验（不信 repair 自己的结论）
6. 仍有 bad → 走「扩充节点池」；仍失败 → 停下报告，不再重复同一动作
```

**为什么第 5 步不能省**：`repair` 只对「换完之后再验一次」负责，而你给用户的结论必须来自一次
干净的 `verify`。历史上最容易犯的错就是「换了 IP 就当修好了」。

## 扩充节点池：可复用的检索流程

目标：给某个域名加**新的候选 IP**。前提是第 0 步已排除 CA / 端口 / 配置问题。

1. 确认需要新 IP（而不是重排旧 IP）：
   - `accelerator { action: "probe" }` 看这个域名现有节点是不是**全红**；
   - 若还有绿的，先 `repair`（它会挑最快的活节点），不必扩池。
2. 用 `github-manager` 技能（工具 `github_api`）搜公开仓库。可用的检索词：
   `Github520`、`github hosts`、`hosts 加速`、`steamcommunity hosts`、`cf 优选 IP`、`SNI 阻断 绕过`。
   ```text
   github_api { method: "GET", path: "/search/repositories", query: { q: "Github520", per_page: 5 } }
   github_api { method: "GET", path: "/repos/<owner>/<repo>/contents/hosts" }
   ```
   `contents` 返回的正文是 base64，需要解码；也可以直接走 `raw.githubusercontent.com`（本机加速后可达）。
3. **只提取 IP 字面量**，丢掉所有脚本、命令、`curl | bash`；对每个 IP 记下来源仓库与抓取时间。
4. 新 IP 的 `sni` 取值按 `resources/node-pool.md` 的域名规则：Akamai/CloudFront 系 → `none`，
   普通 CDN → 先 `real`，都不通再试 `cdn` + `sniValue`。
5. 增量写入 + 实测：
   ```text
   accelerator { action: "node_upsert", domain: "<域名>", ip: "<IP>", sni: "<策略>" }
   accelerator { action: "curate", domains: ["<域名>"] }
   accelerator { action: "verify", domains: ["<域名>"] }
   ```
   `curate` 会同时做 DoH 补池（每个 DoH IP 按 `real` 和 `none` 各试一次），比手工试更快。
6. 若外部 AI 是直接改 `nodes.json` 的：**必须** `accelerator { action: "reload_nodes" }`。

## 判读标准（避免假成功）

| 返回字段 | 含义 | 算成功吗 |
|---|---|---|
| `verify.results[].ok === true` 且 `status` 为 2xx/3xx | 端到端通了 | ✅ |
| `ok: true`，`note: "handshake-only"` | TLS 握手过了但没等到 HTTP 响应 | ❌（按 `isBadResult` 记不通） |
| `status >= 500` | 上游/网关错误 | ❌ |
| `repair.reports[].healed === true` | 换节点后复验通过 | ✅（仍需独立 `verify`） |
| `repair.reports[].skipped === "cooldown Ns"` | 被 90s 冷却挡住 | 用 `force: true` 重试 |
| `repair.reports[].alive === 0` | 这个域名的候选全挂 | 走扩池；扩池也 0 → 停下报告 |

## 停止条件（很重要）

出现下面任一情况就**停手并如实报告**，不要循环重试：

- 连续两轮「扩池 + 换节点 + verify」都不通过 → 该域名在当前网络下确实没有可用通路
  （实测例子：`steamcommunity.com` 的直连路径全挂，必须靠代理 + 无 SNI 节点）。
- `error` 里出现证书/ASN.1/端口类错误 → 属于配置或系统状态问题，不在本手册的修复范围内。
- hosts 被别家加速器（Steam++/Watt Toolkit、Steamcommunity_302）反复改写 → 报告冲突，让用户决定停用哪一个。

## 收尾必做

1. 报告**每个受管域名**的最终状态码与耗时（来自最后一次 `verify`）。
2. 说明这一轮**改了什么**（新增/删除了哪些 IP、来源、`sni` 变更）。
3. 过一遍 `resources/privacy-and-safety.md` 的核查表：`bypass` 是否需要更新、有没有不该被接管的程序。
4. 如果动了敏感设置（`enforce`、`upstream`），明确告诉用户怎么回退。
