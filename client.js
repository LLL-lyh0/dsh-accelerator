// dsh-accelerator — Client half.
//
// 在「设置」左侧导航挂一个「加速器」管理页（settings.section 槽）。
// 数据全部来自同源 /api/dsh-accelerator/*（Host 半有回环 Host + Origin 围栏）。
//
// 设计约束：本文件由 window.__ModuleLoader__ 直接执行，没有构建步骤 ——
// 纯 JS + React.createElement，不写 JSX，不 import（只能 require("react")）。

window.__ModuleLoader__.load({
	id: "dsh-accelerator",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		var React = require("react");
		var h = React.createElement;

		var API = "/api/dsh-accelerator";

		function call(method, path, body) {
			return fetch(API + path, {
				method: method,
				headers: body === undefined ? undefined : { "content-type": "application/json" },
				body: body === undefined ? undefined : JSON.stringify(body)
			}).then(function (r) {
				return r.text().then(function (text) {
					var data = null;
					try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
					// 404 会回 HTML，直接 json() 会抛 "Unexpected end of JSON input"
					if (!r.ok || !data || data.ok === false) {
						var msg = (data && (data.error || data.code)) || ("HTTP " + r.status);
						throw new Error(String(msg));
					}
					return data.value;
				});
			});
		}
		var get = function (p) { return call("GET", p); };
		var post = function (p, b) { return call("POST", p, b === undefined ? {} : b); };

		// ── 主题令牌（与 DSH 设置页同源） ──────────────────────────────────────
		var C = {
			primary: "var(--dsw-alias-label-primary)",
			secondary: "var(--dsw-alias-label-secondary)",
			tertiary: "var(--dsw-alias-label-tertiary)",
			border: "var(--dsw-alias-border-l2)",
			hover: "var(--dsw-alias-interactive-bg-hover)",
			base: "var(--dsw-alias-bg-base)"
		};

		var card = {
			border: "1px solid " + C.border,
			borderRadius: 10,
			padding: "14px 16px",
			marginBottom: 12
		};
		var btn = {
			border: "1px solid " + C.border,
			borderRadius: 8,
			padding: "5px 12px",
			fontSize: 13,
			cursor: "pointer",
			background: "transparent",
			color: C.primary
		};
		var btnPrimary = Object.assign({}, btn, { background: "var(--dsw-alias-interactive-bg-hover)" });
		var input = {
			border: "1px solid " + C.border,
			borderRadius: 6,
			padding: "4px 8px",
			fontSize: 12,
			background: "transparent",
			color: C.primary,
			minWidth: 0
		};
		var sectionTitle = { fontSize: 13, fontWeight: 600, marginBottom: 10, color: C.primary };
		var hint = { fontSize: 12, color: C.tertiary, lineHeight: 1.6 };
		var mono = { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12 };

		function Pill(props) {
			var on = props.on;
			return h("span", {
				style: {
					display: "inline-flex", alignItems: "center", gap: 6,
					borderRadius: 999, padding: "2px 10px", fontSize: 12,
					border: "1px solid " + C.border,
					color: on ? C.primary : C.secondary
				}
			}, [
				h("span", {
					key: "dot",
					style: {
						width: 7, height: 7, borderRadius: "50%",
						background: on ? "#22c55e" : "#9ca3af"
					}
				}),
				h("span", { key: "t" }, props.children)
			]);
		}

		function Row(props) {
			return h("div", {
				style: {
					display: "grid",
					gridTemplateColumns: props.cols || "120px 1fr",
					gap: 10,
					alignItems: "center",
					padding: "5px 0"
				}
			}, props.children);
		}

		function kv(label, value) {
			return h(Row, { key: label },
				h("div", { style: { fontSize: 12, color: C.tertiary } }, label),
				h("div", { style: Object.assign({}, mono, { color: C.secondary, wordBreak: "break-all" }) },
					value === null || value === undefined || value === "" ? "—" : String(value)));
		}

		var SNI_OPTIONS = [
			["real", "real（真域名）"],
			["none", "none（不发 SNI）"],
			["cdn", "cdn（指定 CDN 名）"]
		];

		function AcceleratorPanel() {
			var s = React.useState(null); var status = s[0]; var setStatus = s[1];
			var n = React.useState({}); var nodes = n[0]; var setNodes = n[1];
			var c = React.useState(null); var config = c[0]; var setConfig = c[1];
			var l = React.useState([]); var logs = l[0]; var setLogs = l[1];
			var b = React.useState(""); var busy = b[0]; var setBusy = b[1];
			var e = React.useState(null); var error = e[0]; var setError = e[1];
			var m = React.useState(""); var notice = m[0]; var setNotice = m[1];
			var d = React.useState(false); var dirty = d[0]; var setDirty = d[1];
			var v = React.useState(null); var verify = v[0]; var setVerify = v[1];
			var busyRef = React.useRef("");
			busyRef.current = busy;

			function fail(err) { setError(String(err && err.message ? err.message : err)); }

			// /status 里只有每个域名的节点**数量**（status.nodes），完整池子走 /nodes —— 保持一处真相
			var refreshAll = React.useCallback(function (opts) {
				var keepEdits = opts && opts.keepEdits;
				return Promise.all([get("/status"), get("/nodes"), get("/config"), get("/log")])
					.then(function (r) {
						setStatus(r[0]);
						if (!keepEdits) setNodes(r[1] || {});
						setConfig(r[2] || null);
						setLogs(r[3] || []);
						setError(null);
					}).catch(fail);
			}, []);

			React.useEffect(function () { refreshAll({}); }, [refreshAll]);

			// 不编辑时每 5s 静默刷新状态与日志
			React.useEffect(function () {
				var timer = window.setInterval(function () {
					if (busyRef.current !== "" || dirty) return;
					get("/status").then(setStatus).catch(function () {});
					get("/log").then(setLogs).catch(function () {});
				}, 5000);
				return function () { window.clearInterval(timer); };
			}, [dirty]);

			function run(label, fn) {
				setBusy(label); setNotice(""); setError(null);
				return fn().then(function (v) {
					setNotice(label + " 完成");
					return v;
				}).catch(function (err) {
					fail(err);
				}).then(function () {
					setBusy("");
					return refreshAll({});
				});
			}

			function mutateNodes(next) { setNodes(next); setDirty(true); }

			function setNodeField(domain, idx, key, value) {
				var next = JSON.parse(JSON.stringify(nodes));
				if (!Array.isArray(next[domain])) next[domain] = [];
				next[domain][idx] = Object.assign({}, next[domain][idx], { [key]: value });
				mutateNodes(next);
			}
			function addNode(domain) {
				var next = JSON.parse(JSON.stringify(nodes));
				if (!Array.isArray(next[domain])) next[domain] = [];
				next[domain].push({ ip: "", sni: "real" });
				mutateNodes(next);
			}
			function delNode(domain, idx) {
				var next = JSON.parse(JSON.stringify(nodes));
				next[domain].splice(idx, 1);
				mutateNodes(next);
			}
			function addDomain() {
				var dom = window.prompt("要加速的域名（例如 steamcommunity.com）");
				if (!dom) return;
				var next = JSON.parse(JSON.stringify(nodes));
				if (!next[dom]) next[dom] = [];
				mutateNodes(next);
			}
			function dropDomain(domain) {
				if (!window.confirm("删除域名 " + domain + " 及其全部节点？")) return;
				var next = JSON.parse(JSON.stringify(nodes));
				delete next[domain];
				mutateNodes(next);
			}

			function saveNodes() {
				var clean = {};
				for (var dom in nodes) {
					var list = (nodes[dom] || []).filter(function (x) { return x && typeof x.ip === "string" && x.ip.trim() !== ""; });
					if (list.length > 0) clean[dom] = list;
				}
				return run("保存节点池", function () {
					return post("/nodes", { nodes: clean }).then(function (saved) {
						setNodes(saved || {});
						setDirty(false);
					});
				});
			}

			function saveConfig() {
				var patch = {
					enforce: (config.enforce || []),
					bypass: (config.bypass || []),
					smart: config.smart !== false,
					autoStart: config.autoStart !== false,
					installCaOnEnable: config.installCaOnEnable !== false,
					listenHost: config.listenHost,
					listenPort: Number(config.listenPort) || 443,
					takeover: config.takeover || "auto",
					proxyHost: config.proxyHost,
					proxyPort: Number(config.proxyPort) || 8843,
					upstream: Object.assign({}, config.upstream, { port: Number(config.upstream && config.upstream.port) || 0 })
				};
				return run("保存策略", function () { return post("/config", { config: patch }); });
			}

			// 检测验证（GET /verify）：经本机代理真发一次 HTTPS，顺带证明证书链正确。
			// 智能修复（POST /repair）：先验证，再对不通的域名换节点/补 IP，最后**独立复验**。
			function doVerify(repair) {
				if (busyRef.current !== "") return Promise.resolve(null);
				setBusy(repair ? "智能修复" : "检测验证"); setNotice(""); setError(null);
				var chain = repair ? post("/repair") : Promise.resolve(null);
				return chain.then(function (rep) {
					if (rep) {
						setNotice(rep.nothingToDo
							? "智能修复：所有受管域名都在通过，无需修复"
							: "智能修复完成：恢复 " + ((rep.healed || []).length) + " 个域名" + ((rep.healed || []).length ? "（" + rep.healed.join(", ") + "）" : "，仍有 " + ((rep.reports || []).filter(function (x) { return x && x.healed === false; }).length) + " 个不通"));
					} else {
						setNotice("检测完成");
					}
					return get("/verify");
				}).then(function (res) {
					setVerify(res);
				}).catch(fail).then(function () { setBusy(""); return refreshAll({}); });
			}

			function csvToArr(text) {
				return String(text || "").split(/[,，\s]+/).filter(function (x) { return x !== ""; });
			}

			if (!status) {
				return h("div", { style: { padding: 16, color: C.secondary, fontSize: 13 } },
					error ? "加速器管理页加载失败：" + error : "加载中…");
			}

			var running = Boolean(status.listening);
			var domains = Object.keys(nodes).sort();
			var domainCount = domains.reduce(function (sum, d) { return sum + ((nodes[d] || []).length); }, 0);
			// hosts 只有「首个命中」生效：别家的行排在我们前面才算真冲突（severity === "blocked"）。
			var blockedConflicts = (status.conflicts || []).filter(function (c) { return c.severity === "blocked"; });
			var recent = (status.recent || []).slice(-14).reverse();
			var sm = status.smart || {};
			var lastTick = sm.lastTick || null;
			var lastRepair = sm.lastRepair || null;
			var checkLabel = { fontSize: 12, color: C.secondary, display: "inline-flex", gap: 6, alignItems: "center" };
			// 与后端 lib/verify.mjs 的 isBadResult 同一判据：ok!==true / handshake-only / status>=500 都算不通
			function isBad(r) { return r.ok !== true || r.note === "handshake-only" || (typeof r.status === "number" && r.status >= 500); }
			var verifyRow = null;
			if (verify && verify.results) {
				verifyRow = h("div", { key: "vr", style: { marginTop: 10 } }, [
					h("div", { key: "s", style: Object.assign({}, hint, { marginBottom: 4 }) },
						"最近一次检测：" + new Date(verify.at || Date.now()).toLocaleTimeString() +
						" · 通过 " + (verify.passed || 0) + "/" + (verify.total || (verify.results || []).length)),
					verify.results.map(function (r, i) {
						var bad = isBad(r);
						return h("div", {
							key: r.domain + ":" + i,
							style: { display: "flex", gap: 8, fontSize: 12, padding: "3px 0", color: bad ? "#ef4444" : C.secondary }
						}, [
							h("span", { key: "d", style: Object.assign({}, mono, { flex: 1, color: C.primary }) }, r.domain),
							h("span", { key: "s" }, bad ? (r.error || r.note || ("HTTP " + r.status)) : ("HTTP " + r.status)),
							h("span", { key: "m", style: { width: 72, textAlign: "right", color: C.tertiary } }, (r.ms || 0) + "ms")
						]);
					})
				]);
			}

			return h("div", { style: { maxWidth: 880, color: C.primary } }, [
				// 顶部：状态 + 主操作
				h("div", { key: "head", style: card }, [
					h("div", { key: "l1", style: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" } }, [
						h(Pill, { key: "p", on: running }, running ? "运行中" : "已停止"),
						h("span", { key: "e", style: { fontSize: 12, color: C.tertiary } },
							status.enabled ? "开机自启：开" : "开机自启：关"),
						h("span", { key: "sp", style: { flex: 1 } }),
						busy ? h("span", { key: "b", style: { fontSize: 12, color: C.tertiary } }, busy + "…") : null,
						h("button", {
							key: "toggle", style: running ? btn : btnPrimary,
							onClick: function () { run(running ? "停止" : "启动", function () { return post(running ? "/stop" : "/start"); }); }
						}, running ? "停止加速" : "启动加速"),
						h("button", { key: "r", style: btn, onClick: function () { refreshAll({}); } }, "刷新")
					]),
					error ? h("div", { key: "err", style: { marginTop: 10, fontSize: 12, color: "#ef4444" } }, "✗ " + error) : null,
					notice && !error ? h("div", { key: "ok", style: { marginTop: 10, fontSize: 12, color: C.tertiary } }, notice) : null,
					h("div", { key: "gr", style: { marginTop: 12 } }, [
						kv("监听", status.listen),
						kv("根证书", status.ca && status.ca.installed ? "已安装 · " + status.ca.subject : "未安装（启动时会自动装）"),
						kv("hosts 引导", (function () {
							var hs = status.hosts || {};
							var n = (hs.entries || 0) + "/" + (hs.expected || 0);
							if (hs.writable === false) return "不可写 · 已写 " + n + " 条";
							return hs.active ? "已写入 " + n + " 条" : "未写入";
						})()),
						status.hosts && status.hosts.missing && status.hosts.missing.length
							? kv("⚠ hosts 缺", status.hosts.missing.join("、"))
							: null,
						kv("接管方式", (function () {
							var px = status.proxy || {};
							var mode = px.effective || (config && config.takeover) || "auto";
							var label = mode === "pac" ? "PAC（系统代理自动配置）"
								: mode === "fixed" ? "固定系统代理"
									: mode === "hosts" ? "hosts 引导" : "自动";
							if (px.listening) label += " · 代理 " + px.listen;
							if ((mode === "pac" || mode === "fixed") && px.active === false) label += " · 未写入系统";
							// hosts 模式下如果注册表还留着我们的 PAC，那是上一轮的残留（认系统代理的程序会被指到没人听的端口）
							if (mode === "hosts" && px.pacActive) label += " · PAC 残留待清（重启加速即清）";
							return label;
						})()),
						status.proxy && status.proxy.pacUrl
							? kv("PAC 地址", status.proxy.pacUrl + (status.proxy.autoConfigURL === status.proxy.pacUrl ? "（已写入系统）" : ""))
							: null,
						kv("受管域名", (status.domains || []).length + " 个 · 节点 " + domainCount),
						status.conflicts && status.conflicts.length
							? kv(
								blockedConflicts.length ? "⚠ hosts 被压制" : "hosts 共存",
								blockedConflicts.length
									? blockedConflicts.map(function (c) {
										return c.source + " 的 " + (c.shadowed || c.domains || []).length + " 个域名排在前面，我们的引导未生效";
									}).join(" / ")
									: status.conflicts.map(function (c) {
										return c.source + " 也管 " + (c.domains || []).length + " 个域名（排在我们之后，我们优先）";
									}).join(" / ")
							)
							: null,
						status.lastError ? kv("最近错误", status.lastError) : null
					]),
					status.hosts && status.hosts.writable === false
						? h("div", { key: "hro", style: { marginTop: 10, fontSize: 12, lineHeight: 1.7, color: "#f59e0b" } }, [
							"⚠ hosts 对当前用户不可写（Users 只有 RX）—— 别家加速器重写 hosts 时会把它改成只读，我们改不回来。",
							h("br", { key: "b1" }),
							"修复任选其一：① 以管理员身份运行 DSH；② 管理员执行 icacls \"C:\\Windows\\System32\\drivers\\etc\\hosts\" /grant Users:F",
							h("br", { key: "b2" }),
							"在此之前：已写入的域名照常生效，缺的域名仍可通过「检测与智能」直接验证本插件通路是否正常。"
						])
						: null
				]),

				// 检测与智能（m01160：检测验证调整 + 智能加速）
				h("div", { key: "smart", style: card }, [
					h("div", { key: "t", style: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" } }, [
						h("div", { key: "a", style: Object.assign({}, sectionTitle, { marginBottom: 0, flex: 1 }) }, "检测与智能"),
						h("label", { key: "sm", style: checkLabel }, [
							h("input", {
								key: "i", type: "checkbox", checked: config ? config.smart !== false : true,
								onChange: function (ev) { setConfig(Object.assign({}, config, { smart: ev.target.checked })); }
							}),
							"智能加速"
						]),
						h("label", { key: "as", style: checkLabel }, [
							h("input", {
								key: "i", type: "checkbox", checked: config ? config.autoStart !== false : true,
								onChange: function (ev) { setConfig(Object.assign({}, config, { autoStart: ev.target.checked })); }
							}),
							"随 DSH 启动"
						]),
						h("button", { key: "v", style: btn, disabled: busy !== "", onClick: function () { doVerify(false); } }, "立即检测"),
						h("button", { key: "rp", style: btnPrimary, disabled: busy !== "", onClick: function () { doVerify(true); } }, "智能修复")
					]),
					h("div", { key: "h", style: Object.assign({}, hint, { marginTop: 8 }) },
						"检测 = 经本机代理真发一次 HTTPS（同时证明根证书链可用）；智能修复 = 先检测，再对不通的域名换节点/补 IP 并复验。两个开关改完要点下面的「保存策略」。"),
					h("div", { key: "gr", style: { marginTop: 12 } }, [
						kv("智能巡检", lastTick ? "每 " + (sm.intervalMin || 15) + " 分钟 · 已跑 " + (sm.rounds || 0) + " 轮" : "每 " + (sm.intervalMin || 15) + " 分钟（尚未跑过）"),
						lastTick ? kv("最近巡检", new Date(lastTick.at).toLocaleTimeString() + " · 通过 " + lastTick.ok + "/" + lastTick.verified +
							(lastTick.bad ? " · 异常 " + lastTick.bad : "") + (lastTick.repaired ? " · 修复 " + lastTick.repaired : "")) : null,
						lastRepair ? kv("最近修复", lastRepair.domain + " → " + (lastRepair.healed
							? "已恢复 " + (lastRepair.bestMs === null || lastRepair.bestMs === undefined ? "" : lastRepair.bestMs + "ms") + "（存活 " + lastRepair.alive + "/" + (lastRepair.alive + lastRepair.dead) + "）"
							: "仍未通（存活 " + lastRepair.alive + "/" + (lastRepair.alive + lastRepair.dead) + "）")) : null
					]),
					verifyRow
				]),

				// 节点池
				h("div", { key: "nodes", style: card }, [
					h("div", { key: "t", style: { display: "flex", alignItems: "center", gap: 10 } }, [
						h("div", { key: "a", style: Object.assign({}, sectionTitle, { marginBottom: 0, flex: 1 }) }, "节点池（" + domains.length + " 个域名）"),
						h("button", { key: "ad", style: btn, onClick: addDomain }, "添加域名"),
						h("button", { key: "pl", style: btn, onClick: function () { run("测活", function () { return post("/probe"); }); } }, "测活"),
						h("button", { key: "cu", style: btn, onClick: function () { run("策展", function () { return post("/curate"); }); } }, "策展补 IP"),
						h("button", { key: "rl", style: btn, onClick: function () { run("重载文件", function () { return post("/reload-nodes"); }); } }, "重载文件"),
						h("button", { key: "sv", style: dirty ? btnPrimary : btn, onClick: saveNodes }, dirty ? "保存 *" : "保存")
					]),
					h("div", { key: "h", style: Object.assign({}, hint, { marginTop: 8 }) },
						"SNI 策略：real = 用真域名（Cloudflare / GitHub 直连段需要）；none = 握手时不发 SNI（Akamai / CloudFront 绕阻断靠这个，实测决定成败）；cdn = 填一个 CDN 通用名。"),
					h("div", { key: "l", style: { marginTop: 10 } },
						domains.length === 0 ? h("div", { style: hint }, "暂无节点") : domains.map(function (domain) {
							return h("div", {
								key: domain,
								style: { borderTop: "1px solid " + C.border, paddingTop: 8, marginTop: 8 }
							}, [
								h("div", { key: "h", style: { display: "flex", alignItems: "center", gap: 8 } }, [
									h("div", { key: "d", style: Object.assign({}, mono, { color: C.primary, flex: 1 }) }, domain),
									h("button", { key: "a", style: btn, onClick: function () { addNode(domain); } }, "+ 节点"),
									h("button", { key: "x", style: btn, onClick: function () { dropDomain(domain); } }, "删域名")
								]),
								(nodes[domain] || []).map(function (node, idx) {
									return h("div", {
										key: domain + ":" + idx,
										style: { display: "grid", gridTemplateColumns: "1fr 150px 1fr 40px", gap: 8, alignItems: "center", marginTop: 6 }
									}, [
										h("input", {
											key: "ip", style: input, value: node.ip || "", placeholder: "1.2.3.4",
											onChange: function (ev) { setNodeField(domain, idx, "ip", ev.target.value.trim()); }
										}),
										h("select", {
											key: "sni", style: input, value: node.sni || "real",
											onChange: function (ev) { setNodeField(domain, idx, "sni", ev.target.value); }
										}, SNI_OPTIONS.map(function (o) { return h("option", { key: o[0], value: o[0] }, o[1]); })),
										node.sni === "cdn"
											? h("input", {
												key: "sv", style: input, value: node.sniValue || "", placeholder: "例如 a248.e.akamai.net",
												onChange: function (ev) { setNodeField(domain, idx, "sniValue", ev.target.value.trim()); }
											})
											: h("div", { key: "sv", style: hint }, node.sni === "none" ? "不发 SNI" : "用 " + domain),
										h("button", { key: "d", style: btn, onClick: function () { delNode(domain, idx); } }, "×")
									]);
								})
							]);
						})
					)
				]),

				// 策略
				h("div", { key: "cfg", style: card }, [
					h("div", { key: "t", style: sectionTitle }, "策略"),
					h(Row, { key: "en", cols: "200px 1fr" }, [
						h("div", { key: "l", style: { fontSize: 12, color: C.tertiary } }, "强制走加速的进程"),
						h("input", {
							key: "i", style: input,
							value: (config.enforce || []).join(", "),
							placeholder: "进程名，逗号分隔，例如 steam.exe, git.exe",
							onChange: function (ev) { setConfig(Object.assign({}, config, { enforce: csvToArr(ev.target.value) })); }
						})
					]),
					h(Row, { key: "by", cols: "200px 1fr" }, [
						h("div", { key: "l", style: { fontSize: 12, color: C.tertiary } }, "不走加速的进程"),
						h("input", {
							key: "i", style: input,
							value: (config.bypass || []).join(", "),
							placeholder: "进程名，逗号分隔",
							onChange: function (ev) { setConfig(Object.assign({}, config, { bypass: csvToArr(ev.target.value) })); }
						})
					]),
					h(Row, { key: "up", cols: "200px 1fr" }, [
						h("div", { key: "l", style: { fontSize: 12, color: C.tertiary } }, "外部上游"),
						h("div", { key: "i", style: { display: "flex", gap: 8 } }, [
							h("select", {
								key: "m", style: input, value: (config.upstream && config.upstream.mode) || "direct",
								onChange: function (ev) { setConfig(Object.assign({}, config, { upstream: Object.assign({}, config.upstream, { mode: ev.target.value }) })); }
							}, ["direct", "http", "socks5"].map(function (v) { return h("option", { key: v, value: v }, v); })),
							h("input", {
								key: "h", style: Object.assign({}, input, { flex: 1 }), placeholder: "上游地址",
								value: (config.upstream && config.upstream.host) || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { upstream: Object.assign({}, config.upstream, { host: ev.target.value.trim() }) })); }
							}),
							h("input", {
								key: "p", style: Object.assign({}, input, { width: 80 }), placeholder: "端口",
								value: (config.upstream && config.upstream.port) || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { upstream: Object.assign({}, config.upstream, { port: ev.target.value.trim() }) })); }
							})
						])
					]),
					h(Row, { key: "tk", cols: "200px 1fr" }, [
						h("div", { key: "l", style: { fontSize: 12, color: C.tertiary } }, "接管方式"),
						h("div", { key: "i", style: { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" } }, [
							h("select", {
								key: "m", style: Object.assign({}, input, { width: 240 }),
								value: (config && config.takeover) || "auto",
								onChange: function (ev) { setConfig(Object.assign({}, config, { takeover: ev.target.value })); }
							}, [
								h("option", { key: "auto", value: "auto" }, "自动（能写 hosts 就用 hosts，否则 PAC）"),
								h("option", { key: "hosts", value: "hosts" }, "只用 hosts 引导"),
								h("option", { key: "pac", value: "pac" }, "PAC（系统代理自动配置）"),
								h("option", { key: "fixed", value: "fixed" }, "固定系统代理（全部流量）")
							]),
							h("input", {
								key: "ph", style: Object.assign({}, input, { width: 150 }), placeholder: "代理监听地址",
								value: (config && config.proxyHost) || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { proxyHost: ev.target.value.trim() })); }
							}),
							h("input", {
								key: "pp", style: Object.assign({}, input, { width: 80 }), placeholder: "代理端口",
								value: (config && config.proxyPort) || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { proxyPort: ev.target.value.trim() })); }
							})
						])
					]),
					h(Row, { key: "li", cols: "200px 1fr" }, [
						h("div", { key: "l", style: { fontSize: 12, color: C.tertiary } }, "监听地址"),
						h("div", { key: "i", style: { display: "flex", gap: 8, alignItems: "center" } }, [
							h("input", {
								key: "h", style: Object.assign({}, input, { width: 160 }), value: config.listenHost || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { listenHost: ev.target.value.trim() })); }
							}),
							h("input", {
								key: "p", style: Object.assign({}, input, { width: 80 }), value: config.listenPort || "",
								onChange: function (ev) { setConfig(Object.assign({}, config, { listenPort: ev.target.value.trim() })); }
							}),
							h("label", { key: "c", style: { fontSize: 12, color: C.secondary, display: "inline-flex", gap: 6, alignItems: "center" } }, [
								h("input", {
									key: "i", type: "checkbox", checked: config.installCaOnEnable !== false,
									onChange: function (ev) { setConfig(Object.assign({}, config, { installCaOnEnable: ev.target.checked })); }
								}),
								"启动时自动安装根证书"
							])
						])
					]),
					h("div", { key: "a", style: { display: "flex", gap: 8, marginTop: 10 } }, [
						h("button", { key: "s", style: btnPrimary, onClick: saveConfig }, "保存策略"),
						h("button", {
							key: "ca", style: btn,
							onClick: function () { run("重装根证书", function () { return post("/ca-reinstall"); }); }
						}, "重装根证书")
					]),
					h("div", { key: "h", style: Object.assign({}, hint, { marginTop: 8 }) }, [
						"进程名来自 netstat 反查（约 84ms，已缓存）。强制走加速只对认代理环境变量的程序有效；对不认 env 的原生程序，请用 hosts 引导路径。",
						h("br", { key: "b1" }),
						"接管方式：hosts 引导靠改 hosts（免提权，但会被别家加速器重写/改只读）；PAC 改的是系统代理自动配置（HKCU，同样免提权），" +
						"只把受管域名指向本机代理，其余流量直连 —— 生效范围是「认系统代理的程序」（Edge/Chrome/WinHTTP 系）；" +
						"git、curl、npm 这类自带 CA bundle 且不读 PAC 的程序不受影响，它们要走加速得自己设 HTTPS_PROXY。"
					])
				]),

				// 最近裁定 + 日志
				h("div", { key: "log", style: card }, [
					h("div", { key: "t", style: sectionTitle }, "最近裁定"),
					recent.length === 0
						? h("div", { key: "e", style: hint }, "还没有请求走过加速器。")
						: h("div", { key: "l", style: mono }, recent.map(function (d, i) {
							return h("div", {
								key: i,
								style: { color: C.secondary, padding: "2px 0", wordBreak: "break-all" }
							}, [d.host, d.via ? " via " + d.via : "", d.ms ? " " + d.ms + "ms" : "", d.reason ? " · " + d.reason : ""].join(""));
						})),
					h("div", { key: "t2", style: Object.assign({}, sectionTitle, { marginTop: 14 }) }, "日志"),
					h("div", {
						key: "ll",
						style: Object.assign({}, mono, { maxHeight: 200, overflow: "auto", color: C.tertiary, lineHeight: 1.7 })
					}, logs.length === 0 ? "（空）" : logs.slice(-40).map(function (row, i) {
						return h("div", { key: i }, "[" + row.level + "] " + row.msg);
					}))
				])
			]);
		}

		var inject = ["slots"];

		function apply(ctx) {
			ctx.effect(function () {
				try {
					return ctx.slots.inject("settings.section", function () {
						return ctx.slots.register({
							name: "settings.section",
							id: "dsh-accelerator",
							order: 18,
							label: function () { return "加速器"; }
						}, AcceleratorPanel);
					});
				} catch (err) {
					console.warn("[dsh-accelerator] settings.section 槽不可用，管理页缺席：", err);
					return;
				}
			}, "dsh-accelerator: settings page");
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
