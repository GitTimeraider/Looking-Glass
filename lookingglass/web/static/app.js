/* Looking Glass shared front-end helpers */
"use strict";

const LG = {
  async api(path, opts = {}) {
    const init = { headers: { "Accept": "application/json", "X-Looking-Glass": "1" }, ...opts };
    if (opts.body && typeof opts.body !== "string") {
      init.body = JSON.stringify(opts.body);
      init.headers["Content-Type"] = "application/json";
    }
    const r = await fetch(path, init);
    if (r.status === 401) { location.href = "/login"; throw new Error("not authenticated"); }
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json() : await r.text();
    // a proxy in front (nginx 504 ...) answers with an HTML page and, over HTTP/2, an empty status text
    if (!r.ok) throw new Error((data && data.detail) || `HTTP ${r.status} ${r.statusText}`.trim());
    return data;
  },
  esc(v) {
    if (v === null || v === undefined) return "";
    return String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  },
  num(v) { return v === null || v === undefined ? "–" : Number(v).toLocaleString(); },
  /** 24 / 12 hour clock from Settings › Display (browser = the browser's language decides) */
  hc() {
    const f = window.LG_TIME_FORMAT;
    return f === "24h" ? { hourCycle: "h23" } : f === "12h" ? { hour12: true } : {};
  },
  time(iso) {
    if (iso === null || iso === undefined || iso === "") return "";
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", ...LG.hc() });
  },
  /** current clock time, e.g. for "updated 14:05:09" */
  clock(d) { return (d || new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", ...LG.hc() }); },
  ago(iso) {
    if (!iso) return "never";
    const s = (Date.now() - (typeof iso === "number" ? iso * 1000 : new Date(iso).getTime())) / 1000;
    if (isNaN(s)) return "–";
    if (s < 5) return "just now";  // also small clock differences between browser and server
    if (s < 60) return Math.round(s) + "s ago";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  },
  bytes(v) {
    if (v === null || v === undefined || isNaN(v)) return "–";
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; v = Number(v);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(i ? 1 : 0) + " " + u[i];
  },
  bps(v) {
    if (v === null || v === undefined) return "–";
    const u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return v.toFixed(1) + " " + u[i];
  },
  sev(s) { return `<span class="badge ${LG.esc(s)}">${LG.esc(s)}</span>`; },
  syslogSev(n) { return ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"][n] || n; },
  ip(ip) { return ip ? `<a class="mono${String(ip).includes(":") ? "" : " whole"}" href="/events?ip=${encodeURIComponent(ip)}&hours=168" title="show events">${LG.esc(ip)}</a>` : ""; },
  mac(m) { return m ? `<span class="mono small whole">${LG.esc(m)}</span>` : ""; },
  src(s) { return `<span class="badge src">${LG.esc(s)}</span>`; },
  flag(cc) {
    if (!cc || cc.length !== 2) return "";
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1A5 + c.charCodeAt(0))) + " " + LG.esc(cc);
  },
  /** Render a table. cols: [{k, l, f?: (v,row)=>html, num?: bool}] */
  /** onRow(row): makes rows clickable (e.g. open the matching events) */
  // Sortable columns: c.s = function(row) or true (the cell value); opts.sortAll makes every labelled column sortable.
  // Clicking a header sorts (numbers / c.desc: biggest or newest first), clicking again reverses.
  // opts.order = {k, dir}: the order the rows already arrive in (server side), marked on its header.
  sortKey(v) {
    if (v === null || v === undefined || v === "") return null;
    if (typeof v === "number" || typeof v === "boolean") return Number(v);
    if (Array.isArray(v)) return v.join(", ").toLowerCase() || null;
    if (typeof v === "object") return null;
    const t = String(v).trim();
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t.split(".").map(x => x.padStart(3, "0")).join(".");  // IPv4 in numeric order
    return t.toLowerCase();
  },
  table(el, cols, rows, empty = "No data", onRow, opts = {}) {
    if (typeof el === "string") el = document.querySelector(el);
    if (!rows || !rows.length) { el.innerHTML = `<div class="empty">${LG.esc(empty)}</div>`; return; }
    cols = cols.map(c => c.s || !opts.sortAll || !c.l ? c : { ...c, s: true });
    const all = rows, st = el._sort, sc = st && cols[st.i];
    if (sc && sc.s) {
      const val = r => LG.sortKey(sc.s === true ? r[sc.k] : sc.s(r));
      rows = [...rows].sort((a, b) => {
        const x = val(a), y = val(b);
        if (x === null) return y === null ? 0 : 1;  // empty values last, both directions
        if (y === null) return -1;
        if (typeof x !== typeof y) return (typeof x === "number" ? -1 : 1) * st.dir;
        return (x < y ? -1 : x > y ? 1 : 0) * st.dir;
      });
    }
    const mark = st ? st : opts.order ? { i: cols.findIndex(c => c.k === opts.order.k && c.s), dir: opts.order.dir } : null;
    const head = cols.map((c, i) => c.s
      ? `<th class="${c.num ? "num " : ""}sortable" data-sort="${i}" title="Sort by ${LG.esc(c.l)}">${LG.esc(c.l)}<span class="arrow">${mark && mark.i === i ? (mark.dir > 0 ? "▲" : "▼") : ""}</span></th>`
      : `<th class="${c.num ? "num" : ""}">${LG.esc(c.l)}</th>`).join("");
    const body = rows.map((r, i) => `<tr${onRow ? ` class="clickable" data-row="${i}" title="Show matching events"` : ""}>` + cols.map(c => {
      const v = r[c.k];
      const html = c.f ? c.f(v, r) : (c.num ? LG.num(v) : LG.esc(Array.isArray(v) ? v.join(", ") : v));
      return `<td class="${c.num ? "num" : ""}" data-label="${LG.esc(c.l || "")}">${html}</td>`;
    }).join("") + "</tr>").join("");
    el.innerHTML = `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
    LG.fit(el.querySelector(".table-wrap"));
    el.querySelectorAll("th[data-sort]").forEach(th => th.onclick = () => {
      const i = Number(th.dataset.sort), c = cols[i];
      el._sort = { i, dir: mark && mark.i === i ? -mark.dir : (c.num || c.desc ? -1 : 1) };
      LG.table(el, cols, all, empty, onRow, opts);
    });
    if (onRow) el.querySelectorAll("tr[data-row]").forEach(tr => tr.onclick = e => {
      if (e.target.closest("a")) return;
      onRow(rows[Number(tr.dataset.row)]);
    });
  },
  /** Never scroll sideways: a table that does not fit its box (narrow card, phone) gets tighter cells, and if that is
   *  not enough it is shown as stacked "label: value" rows instead. Checked again whenever the box changes size. Cells need data-label (LG.table sets it). */
  fit(wrap) {
    if (!wrap) return;
    // hand-built tables: take the stacked labels from the header
    const heads = [...wrap.querySelectorAll("thead th")].map(th => th.textContent.trim());
    wrap.querySelectorAll("tbody > tr").forEach(tr => [...tr.children].forEach((td, i) => {
      if (!td.hasAttribute("data-label") && !td.hasAttribute("colspan")) td.setAttribute("data-label", heads[i] || "");
    }));
    const check = () => {
      // first try tighter cells; stack only if that still does not fit
      wrap.classList.remove("stacked", "compact");
      const t = wrap.querySelector("table"), over = () => t && t.scrollWidth > wrap.clientWidth;
      if (over()) wrap.classList.add("compact");
      if (over()) { wrap.classList.remove("compact"); wrap.classList.add("stacked"); }
    };
    check();
    if (!wrap._fitObs && window.ResizeObserver) {
      let w = wrap.clientWidth;
      wrap._fitObs = new ResizeObserver(() => { if (Math.abs(wrap.clientWidth - w) > 1) { w = wrap.clientWidth; check(); } });
      wrap._fitObs.observe(wrap);
    }
  },
  // Bar / pie order: "desc" (largest first, as the server sends them), "asc" or "name"
  sortRows(rows, mode) {
    if (!mode || mode === "desc") return rows;
    const r = [...rows];
    if (mode === "asc") return r.sort((a, b) => Number(a.v) - Number(b.v));
    return r.sort((a, b) => String(a.label ?? "").localeCompare(String(b.label ?? ""), undefined, { numeric: true, sensitivity: "base" }));
  },
  sortToggle(key, onChange) {
    // small button for a card title: cycles largest first -> smallest first -> A-Z, remembered per chart
    const modes = { desc: "↓ most", asc: "↑ fewest", name: "A–Z" }, next = { desc: "asc", asc: "name", name: "desc" };
    let mode = "desc";
    try { mode = localStorage.getItem("lg-sort-" + key) || "desc"; } catch (e) {}
    const b = document.createElement("button");
    b.className = "sort-toggle"; b.type = "button"; b.title = "Change the order";
    const show = () => { b.textContent = modes[mode] || modes.desc; };
    b.onclick = e => {
      e.stopPropagation(); mode = next[mode] || "desc"; show();
      try { localStorage.setItem("lg-sort-" + key, mode); } catch (err) {}
      onChange(mode);
    };
    show();
    return { el: b, mode: () => mode };
  },
  md(text) {
    if (window.marked && window.DOMPurify) return DOMPurify.sanitize(marked.parse(text || ""));
    return `<pre>${LG.esc(text)}</pre>`;
  },
  palette: ["#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#a855f7", "#14b8a6", "#ec4899", "#eab308", "#64748b", "#06b6d4", "#f97316", "#84cc16"],
  sourceColors: { firewall: "#3b82f6", nginx: "#22c55e", unbound: "#14b8a6", crowdsec: "#f97316", suricata: "#ef4444",
                  zenarmor: "#a855f7", qfeeds: "#ec4899", auth: "#eab308", vpn: "#06b6d4", dhcp: "#84cc16", system: "#64748b",
                  unraid: "#f43f5e", docker: "#0ea5e9" },
  charts: {},
  /* theme (Settings › Display): <html data-theme> is the setting, data-mode the light / dark actually shown */
  theme(mode, accent) {
    const r = document.documentElement;
    if (mode) r.dataset.theme = mode;
    if (accent) r.dataset.accent = accent;
    r.dataset.mode = r.dataset.theme === "auto" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
      : r.dataset.theme === "light" ? "light" : "dark";
    LG.chartColors();
    Object.values(LG.charts).forEach(c => c.update("none"));
  },
  chartColors() {  // axis text and grid lines follow the theme
    if (!window.Chart) return;
    const css = getComputedStyle(document.documentElement);
    Chart.defaults.color = css.getPropertyValue("--muted").trim() || "#8b98a9";
    Chart.defaults.borderColor = css.getPropertyValue("--border").trim() || "#263241";
  },
  chart(id, config) {
    if (LG.charts[id]) LG.charts[id].destroy();
    const el = document.getElementById(id);
    if (!el || !window.Chart) return null;
    const box = el.parentElement, ds = config.data.datasets || [];
    const empty = !ds.length || ds.every(d => !(d.data || []).length);
    box.classList.toggle("nodata", empty);
    if (empty) { delete LG.charts[id]; return null; }
    LG.chartColors();
    LG.charts[id] = new Chart(el, config);
    return LG.charts[id];
  },
  qs() { return Object.fromEntries(new URLSearchParams(location.search)); },
  seg(el, value, onChange) {
    el.querySelectorAll("button").forEach(b => {
      b.classList.toggle("on", b.dataset.v === String(value));
      b.onclick = () => { el.querySelectorAll("button").forEach(x => x.classList.remove("on")); b.classList.add("on"); onChange(b.dataset.v); };
    });
  },
  /* ---- WebAuthn (passkeys): JSON <-> ArrayBuffer conversion ---- */
  webauthn: {
    b64uToBuf(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; },
    bufToB64u(b) { return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
    creationOptions(o) {
      return { ...o, challenge: this.b64uToBuf(o.challenge), user: { ...o.user, id: this.b64uToBuf(o.user.id) },
               excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: this.b64uToBuf(c.id) })) };
    },
    requestOptions(o) {
      return { ...o, challenge: this.b64uToBuf(o.challenge), allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: this.b64uToBuf(c.id) })) };
    },
    credentialJSON(c) {
      const r = c.response, out = { id: c.id, rawId: this.bufToB64u(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {}, response: {} };
      out.response.clientDataJSON = this.bufToB64u(r.clientDataJSON);
      if (r.attestationObject) { out.response.attestationObject = this.bufToB64u(r.attestationObject); if (r.getTransports) out.response.transports = r.getTransports(); }
      if (r.authenticatorData) { out.response.authenticatorData = this.bufToB64u(r.authenticatorData); out.response.signature = this.bufToB64u(r.signature);
                                 out.response.userHandle = r.userHandle ? this.bufToB64u(r.userHandle) : null; }
      if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
      return out;
    },
  },
  /* ---- click-through to event search ---- */
  drillUrl(params) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) if (v !== undefined && v !== null && v !== "") p.set(k, v);
    return "/events?" + p.toString();
  },
  /** Chart.js options that call fn(index, datasetIndex) on click and show a pointer over clickable elements */
  clickOpts(fn) {
    if (!fn) return {};
    return { onClick: (e, els) => { if (els.length) fn(els[0].index, els[0].datasetIndex); },
             onHover: (e, els) => { e.native.target.style.cursor = els.length ? "pointer" : "default"; } };
  },
  /* ---- chart helpers ---- */
  color(i) { return LG.palette[i % LG.palette.length]; },
  timeLabel(t, hours) {
    const d = new Date(t);
    if (hours > 48) {
      const h = window.LG_TIME_FORMAT === "12h" ? d.toLocaleTimeString([], { hour: "numeric", hour12: true })
              : String(d.getHours()).padStart(2, "0") + "h";
      return d.toLocaleDateString(undefined, { month: "short", day: "2-digit" }) + " " + h;
    }
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", ...LG.hc() });
  },
  /** rows [{t, series, v}] -> stacked bar (or line) chart */
  seriesChart(id, rows, opts = {}) {
    const buckets = [...new Set(rows.map(r => r.t))].sort();
    const series = [...new Set(rows.map(r => r.series))];
    const idx = Object.fromEntries(buckets.map((b, i) => [b, i]));
    const datasets = series.map((s, i) => {
      const data = new Array(buckets.length).fill(0);
      rows.filter(r => r.series === s).forEach(r => data[idx[r.t]] = Number(r.v));
      const c = (opts.colors && opts.colors[s]) || LG.sourceColors[s] || LG.color(i);
      return opts.line ? { label: s ?? "?", data, borderColor: c, backgroundColor: c + "33", fill: !!opts.fill, pointRadius: 0, tension: .25, borderWidth: 1.5 }
                       : { label: s ?? "?", data, backgroundColor: c, stack: "s" };
    });
    const click = opts.onClick ? LG.clickOpts((i, ds) => opts.onClick(buckets[i], series[ds])) : {};
    return LG.chart(id, { type: opts.line ? "line" : "bar", data: { labels: buckets.map(b => LG.timeLabel(b, opts.hours || 24)), datasets },
      options: { ...click, maintainAspectRatio: false, animation: false, interaction: { mode: opts.onClick ? "nearest" : "index", intersect: !!opts.onClick },
        scales: { x: { stacked: !opts.line, ticks: { maxTicksLimit: 10, maxRotation: 0 } }, y: { stacked: !opts.line, beginAtZero: true, ticks: { callback: opts.fmt || (v => v) } } },
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } } });
  },
  /** metric series {label: [[t, v], ...]} -> line chart */
  lineChart(id, series, opts = {}) {
    const datasets = Object.entries(series || {}).map(([label, pts], i) => ({
      label: (opts.rename ? opts.rename(label) : label) || id, borderColor: LG.color(i), backgroundColor: LG.color(i) + "22", fill: !!opts.fill,
      data: pts.map(p => ({ x: new Date(p[0]).getTime(), y: opts.neg && opts.neg(label) ? -p[1] : p[1] })), pointRadius: 0, borderWidth: 1.5, tension: opts.step ? 0 : .2, stepped: opts.step ? "before" : false }));
    const fmt = opts.fmt || (v => Math.round(v * 100) / 100);
    return LG.chart(id, { type: "line", data: { datasets }, options: { maintainAspectRatio: false, animation: false, parsing: false,
      interaction: { mode: "nearest", intersect: false },
      scales: { x: { type: "linear", ticks: { callback: v => LG.timeLabel(v, opts.hours || 24), maxTicksLimit: 7, maxRotation: 0 } },
                y: { min: opts.min, max: opts.max, ticks: { callback: v => fmt(Math.abs(v)) } } },
      plugins: { legend: { display: datasets.length > 1, position: "bottom", labels: { boxWidth: 10 } },
                 tooltip: { callbacks: { title: i => LG.time(i[0].parsed.x), label: c => `${c.dataset.label}: ${fmt(Math.abs(c.parsed.y))}` } } } } });
  },
  pieChart(id, rows, onClick) {
    return LG.chart(id, { type: "doughnut", data: { labels: rows.map(r => r.label ?? "?"),
      datasets: [{ data: rows.map(r => Number(r.v)), backgroundColor: rows.map((r, i) => LG.sourceColors[r.label] || LG.color(i)), borderWidth: 0 }] },
      options: { ...LG.clickOpts(onClick && (i => onClick(rows[i]))), maintainAspectRatio: false, animation: false,
                 plugins: { legend: { position: "right", labels: { boxWidth: 10 },
                                      onClick: onClick ? (e, item) => onClick(rows[item.index]) : undefined } } } });
  },
  barChart(id, rows, horizontal, onClick) {
    return LG.chart(id, { type: "bar", data: { labels: rows.map(r => r.label ?? "?"),
      datasets: [{ data: rows.map(r => Number(r.v)), backgroundColor: rows.map((r, i) => LG.color(horizontal ? 0 : i)) }] },
      options: { ...LG.clickOpts(onClick && (i => onClick(rows[i]))), indexAxis: horizontal ? "y" : "x", maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } },
                 scales: { y: { ticks: { autoSkip: false, font: { size: 11 } } } } } });
  },
  gauge(pct, label, sub) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0)), cls = p > 90 ? "bad" : p > 75 ? "warn" : "";
    return `<div class="gauge"><div class="gv">${pct === null || pct === undefined ? "–" : Math.round(p) + "%"}</div><div class="bar ${cls}"><i style="width:${p}%"></i></div><div class="l">${LG.esc(label)}</div>${sub ? `<div class="small muted">${sub}</div>` : ""}</div>`;
  },
};
// Every table on every page - also the ones a page builds itself - gets the no-sideways-scrolling check (LG.fit).
if (window.MutationObserver) {
  const fitAll = () => document.querySelectorAll(".table-wrap").forEach(w => { if (!w._fitObs) LG.fit(w); });
  let queued = false;
  new MutationObserver(() => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; fitAll(); }); } })
    .observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener("DOMContentLoaded", fitAll);
}

LG.theme();  // resolve data-theme="auto" before the page is painted (this script loads in <head>)
matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => LG.theme());
