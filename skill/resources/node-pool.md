# 节点池：字段语义、实测数据、维护方式

## 文件位置与形状

`%USERPROFILE%\.dsh\storages\dsh-accelerator\nodes.json`

```json
{
  "github.com":                  [ { "ip": "140.82.114.4", "sni": "real" } ],
  "raw.githubusercontent.com":   [ { "ip": "185.199.108.133", "sni": "real" } ],
  "steamcommunity.com":          [ { "ip": "23.218.239.27", "sni": "none" } ],
  "huggingface.co":              [ { "ip": "3.167.226.59", "sni": "none" } ],
  "*.github.com":                [ { "ip": "20.205.243.168", "sni": "none" } ]
}
```

- **键**：域名或通配模式。`*.github.com` 命中 `api.github.com`，**不**命中 `github.com` 本身
  （匹配函数 `matchDomain` 在 `lib/sni.mjs`）。
- **值**：节点数组，元素 `{ ip, sni, sniValue? }`。
  - `ip` 必须是 IPv4 字面量（插件校验 `/^\d+\.\d+\.\d+\.\d+$/`）。
  - `sni`：`real` | `none` | `cdn`。
  - `sniValue`：仅当 `sni === "cdn"` 时有意义，是实际发出去的 SNI 名。
- 写入后必须 `reload_nodes`；插件自己写（`node_upsert` / `nodes_set` / `curate` / `repair`）会自动生效。
- 首次启动时若文件不存在，会用内置种子池（`lib/seed-nodes.mjs`）落盘一份 ⇒ 装上就有可用节点。

## `sni` 为什么是决定性的

上游 CDN 用 SNI 决定回哪个站点。阻断发生在 SNI 明文里的域名上，所以：

| `sni` | 行为 | 什么时候用 |
|---|---|---|
| `real` | 用客户端请求的域名发 SNI | 目标 CDN 不挑 SNI；github/Fastly 系 |
| `none` | **完全省略** SNI 扩展 | Akamai（steamcommunity）、CloudFront（huggingface）——实测只有这种能过 |
| `cdn` | 发一个 CDN 通用名 | 目标 IP 必须看到某个 SNI 才给内容（如 `a248.e.akamai.net`） |

本机实测（同一 IP，只换 SNI，Host 头保持真域名）：

- `steamcommunity.com` @ `23.218.239.27`：真 SNI → `ECONNRESET 246ms`；**无 SNI → 200 / 967ms / 49265B，对端 CN=`a248.e.akamai.net`**。
- `huggingface.co` @ `3.167.226.59`：真 SNI → `ECONNRESET 287ms`；**无 SNI → 200 / 1798ms，CN=`*.cloudfront.net`**。
- `github.com` @ `140.82.114.4`：真 SNI 能通但慢（实测曾到 39s）；@ `20.205.243.166` 只有无 SNI 能通。
- `raw.githubusercontent.com` @ `185.199.108.133`：真 SNI 200 / 174ms（CN=`*.github.io`）。

⇒ **同一个 `sni` 策略不能套所有域名**。换节点时不要顺手把 `none` 改成 `real`。

## SNI 整段阻断的域名：换 IP 无解，只能走每域名上游

有的域名不是「节点选得不好」，而是 **RST 跟着 SNI 走、不跟着 IP 走**（2026-10-28 实测
`itch.io`）：同一台 Fastly 边缘 `151.101.1.44`，SNI=`www.fastly.com`/`example.com` 都
HTTP 301（对端 CN=`*.taboola.com`），SNI=`itch.io` 一律 `ECONNRESET`。穷举多源 DoH 的
全部 IP（Cloudflare `104.26.x`、`172.67.x`、Fastly anycast、`192.133.77.133`）+ 真/无 SNI
全败，明文 80 也 timeout。

⇒ 这类域名换任何 IP、换任何 SNI 策略都修不好。**唯一真解是把整域流量交给外部
HTTP/SOCKS5 上游**：

```json
// ~/.dsh/storages/dsh-accelerator/config.json
{ "upstreams": { "itch.io": { "mode": "socks5", "host": "127.0.0.1", "port": 10808 } } }
```

- 优先级：`upstreams[域名]`（级联，完全经上游、不竞速）> 全局 `upstream`（**兜底**：
  仅当直连池全挂时经它再试一次，`upstreamFallback:false` 可关）。
- 判别方法：先拿 DoH 出来的 IP 直发带真 SNI 的 HTTPS（全败）→ 再在同一 IP 上换填
  一个无关域名（能通）→ 即是 SNI 阻断，**不要再折腾节点，直接配 `upstreams` 并如实
  告诉用户「这台机器上没有上游就打不开」**。

## 可用种子（实测通过，会被预置）

| 域名 | IP | sni |
|---|---|---|
| github.com | 140.82.114.4 / 140.82.112.3 / 140.82.114.6 | real |
| github.com | 20.205.243.166 | none |
| api.github.com | 140.82.114.6 | real |
| api.github.com | 20.205.243.168 | none |
| raw.githubusercontent.com | 185.199.108.133 / 185.199.109.133 / 185.199.110.133 | real |
| steamcommunity.com | 23.218.239.27 / 23.218.239.39 | none |
| store.steampowered.com | 23.200.214.95 | real |
| api.steampowered.com | 23.35.148.193 / 23.35.148.186 / 23.35.148.190（2026-10-27 实测新增） | real |
| api.steampowered.com | 23.59.88.206 | real |
| huggingface.co | 3.167.226.59 | none |
| opencode.ai | 172.65.90.23 | real |
| openrouter.ai | 104.18.2.115 | real |

**SNI 策略是跟着 IP 段走的，不是跟着域名走的**：同一个 `api.steampowered.com`，
Akamai 段（`23.35.148.x`）**必须带真 SNI**（无 SNI 立刻 `ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR`），
而 `23.59.88.194` 干脆 TCP 都连不上（实测 5003ms `tcp:timeout`）。
所以「给这个域名统一设 `sni:'none'`」这种省事做法会在别的域名上把可用的 IP 变成不可用 ——
**每个节点单独定策略**（这也正是 `nodes.json` 把 `sni` 放在节点级别的原因）。

## DoH 只能用来「补充候选」，不能信

插件用 `https://223.5.5.5/resolve` 与 `https://1.12.12.12/resolve` 取 A 记录，但实测**结果会被污染**：

- `steamcommunity.com` → 只返回 `31.13.64.7`（Facebook Anycast）/ `199.96.59.95` 之类，直连全超时。
- `github.com` → 只返回 `20.205.243.166`（单一 IP，且慢）。
- 代理自己解析上游时**绝不能走系统 DNS**：加速器会往 hosts 写 `127.0.0.1`，系统解析会把代理指回它自己（实测过 `[OK] api.github.com via 127.0.0.1` 这种自环）。

⇒ 结论：**DoH/系统 DNS 只用来产生候选，能不能用永远由 `probe`/`curate` 的 TCP+TLS 实测决定。**

## 维护动作对照

| 想要 | 用什么 |
|---|---|
| 看每个节点活不活 | `accelerator { action: "probe" }`（只报告，不改数据） |
| 自动筛掉死的、补一批、保留最快的 | `accelerator { action: "curate", domains: [...] }` |
| 某个域名不通时全自动换 | `accelerator { action: "repair", domains: [...] }`（含复验） |
| 手工加一个 | `node_upsert` |
| 手工删一个 | `node_delete` |
| 外部脚本改了文件 | `reload_nodes` |

`curate` / `repair` 保留上限是 6 条/域名，按握手耗时升序，按 IP 去重。

**DoH 候选要「全试」，不要只试两三个**（`curator.mjs` 的 `dohLimit` 默认 8）。实测教训：
`api.steampowered.com` 一次 DoH 返回 10 个地址，同一时刻只有 7 个能服务，而且**每次查询返回的地址集都不一样**
（另一次返回的是 `23.45.119.x` / `23.211.14.x`）；早期把 `dohLimit` 写成 3，补进来的 3 个正好全是死的，
修复报告成「存活 2/11」并宣告修不好。**遇到「整池都是 tcp:timeout」时的正确动作是 `curate`/`repair` 重新解析**，
而不是手工往里塞旧 IP。判断一个域名上游到底有没有通路，可以用「拿 DoH 出来的 IP 直接发带真 SNI 的 HTTPS」对照
（本项目实测脚本思路：TCP 4s → TLS → `GET /`，一轮 30 次探测里 7/30 可用，全部是 `sni:real`，`sni:none` 一律
`ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR`）。

## 健康度与冷却（为什么不用手动反复修）

- 引擎记录**域名级**健康（`health.hostSnapshot()`）：只有「这个域名的**所有**候选都失败」才算不健康，
  单节点失败是竞速常态，不会触发修复。
- `SmartController` 默认每 15 分钟巡检一次（`smartIntervalMin`），另外在引擎报 `exhausted` 时立即修。
- 每个域名有 **90 秒修复冷却**（`REPAIR_COOLDOWN_MS`）；显式调用 `repair` 默认 `force:true`，会绕过冷却。
- 引擎每次连接都**现读** `nodes.json`，所以纯换节点是**热生效**的，不会掐断正在传输的连接
  （只有域名集合变化导致叶证书重签时才重启引擎）。
- **池子下限保护**：`repair()` 走 `mergeKeepPrevious(alive, before, { min: 2, keep: 6 })` ——
  存活数不足 2 条时把**原有候选并回来**，禁止把池子缩成一条。理由是一次实测：
  `store.steampowered.com` 的一次策展只活下来 1 个 IP，池子被从 5 条缩到 1 条，复验反而更差 ——
  `probeNode` 只证明 TCP+TLS 握手能成，**握手成功 ≠ 完整 GET 拿得到响应**。
  回归断言在 `test/smart-smoke.mjs`（含源码级「repair 真的调了它」断言，且变异验证过）。

## `store.steampowered.com`：链路抖动，别把一次失败当定论

- 2026-10-27 19:24 实测：多 DoH 源（223.5.5.5 / 1.12.12.12 / 8.8.8.8 / 1.1.1.1）合并后只有 2 个 IP；
  **5 个 IP × 5 种 SNI 策略 = 25 个组合，完整 GET 0/25 可用**
  （含 `a248.e.akamai.net`、`e.cdn.steampowered.com` 这类 Akamai 通用名；`23.218.239.27` 上这些名字
  只回 `ECONNRESET` —— 该边缘节点不服务这个 vhost）。
- 但**同一批候选在 19:40 又通了**：`test/live-verify.mjs` 报 `store.steampowered.com HTTP 200 3359ms`，
  全量 9/9 通过。⇒ 结论是「**本机到该域名的链路会整段不可达然后自己恢复**」，
  不是「节点选错了」，也不是「永久不可达」。
- 正确动作：① 别因为一次失败就反复 `repair`（每次都会重写池子，且 `probeNode` 的握手成功 ≠ 完整 GET 成功）；
  ② 保留 >1 个候选（[`mergeKeepPrevious`](#健康度与冷却为什么不用手动反复修) 会兜住）；
  ③ 报告给用户时说清「当前网络到该域名时通时不通，加速器只能在有通路时把它救回来」。


