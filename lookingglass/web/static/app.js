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
    if (!r.ok) throw new Error((data && data.detail) || r.statusText);
    return data;
  },
  esc(v) {
    if (v === null || v === undefined) return "";
    return String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  },
  num(v) { return v === null || v === undefined ? "–" : Number(v).toLocaleString(); },
  time(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  },
  ago(iso) {
    if (!iso) return "never";
    const s = (Date.now() - (typeof iso === "number" ? iso * 1000 : new Date(iso).getTime())) / 1000;
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
  ip(ip) { return ip ? `<a class="mono" href="/events?ip=${encodeURIComponent(ip)}&hours=168" title="show events">${LG.esc(ip)}</a>` : ""; },
  src(s) { return `<span class="badge src">${LG.esc(s)}</span>`; },
  flag(cc) {
    if (!cc || cc.length !== 2) return "";
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1A5 + c.charCodeAt(0))) + " " + LG.esc(cc);
  },
  /** Render a table. cols: [{k, l, f?: (v,row)=>html, num?: bool}] */
  table(el, cols, rows, empty = "No data") {
    if (typeof el === "string") el = document.querySelector(el);
    if (!rows || !rows.length) { el.innerHTML = `<div class="empty">${LG.esc(empty)}</div>`; return; }
    const head = cols.map(c => `<th class="${c.num ? "num" : ""}">${LG.esc(c.l)}</th>`).join("");
    const body = rows.map(r => "<tr>" + cols.map(c => {
      const v = r[c.k];
      const html = c.f ? c.f(v, r) : (c.num ? LG.num(v) : LG.esc(Array.isArray(v) ? v.join(", ") : v));
      return `<td class="${c.num ? "num" : ""}">${html}</td>`;
    }).join("") + "</tr>").join("");
    el.innerHTML = `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  },
  md(text) {
    if (window.marked && window.DOMPurify) return DOMPurify.sanitize(marked.parse(text || ""));
    return `<pre>${LG.esc(text)}</pre>`;
  },
  palette: ["#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#a855f7", "#14b8a6", "#ec4899", "#eab308", "#64748b", "#06b6d4", "#f97316", "#84cc16"],
  sourceColors: { firewall: "#3b82f6", nginx: "#22c55e", unbound: "#14b8a6", crowdsec: "#f97316", suricata: "#ef4444",
                  zenarmor: "#a855f7", qfeeds: "#ec4899", auth: "#eab308", vpn: "#06b6d4", dhcp: "#84cc16", system: "#64748b" },
  charts: {},
  chart(id, config) {
    if (LG.charts[id]) LG.charts[id].destroy();
    const el = document.getElementById(id);
    if (!el || !window.Chart) return null;
    const box = el.parentElement, ds = config.data.datasets || [];
    const empty = !ds.length || ds.every(d => !(d.data || []).length);
    box.classList.toggle("nodata", empty);
    if (empty) { delete LG.charts[id]; return null; }
    Chart.defaults.color = "#8b98a9";
    Chart.defaults.borderColor = "#263241";
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
  /* ---- chart helpers ---- */
  color(i) { return LG.palette[i % LG.palette.length]; },
  timeLabel(t, hours) {
    const d = new Date(t);
    return hours > 48 ? d.toLocaleDateString(undefined, { month: "short", day: "2-digit" }) + " " + String(d.getHours()).padStart(2, "0") + "h"
                      : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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
    return LG.chart(id, { type: opts.line ? "line" : "bar", data: { labels: buckets.map(b => LG.timeLabel(b, opts.hours || 24)), datasets },
      options: { maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
        scales: { x: { stacked: !opts.line, ticks: { maxTicksLimit: 10, maxRotation: 0 } }, y: { stacked: !opts.line, beginAtZero: true, ticks: { callback: opts.fmt || (v => v) } } },
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } } });
  },
  /** metric series {label: [[t, v], ...]} -> line chart */
  lineChart(id, series, opts = {}) {
    const datasets = Object.entries(series || {}).map(([label, pts], i) => ({
      label: (opts.rename ? opts.rename(label) : label) || id, borderColor: LG.color(i), backgroundColor: LG.color(i) + "22", fill: !!opts.fill,
      data: pts.map(p => ({ x: new Date(p[0]).getTime(), y: opts.neg && opts.neg(label) ? -p[1] : p[1] })), pointRadius: 0, borderWidth: 1.5, tension: .2 }));
    const fmt = opts.fmt || (v => Math.round(v * 100) / 100);
    return LG.chart(id, { type: "line", data: { datasets }, options: { maintainAspectRatio: false, animation: false, parsing: false,
      interaction: { mode: "nearest", intersect: false },
      scales: { x: { type: "linear", ticks: { callback: v => LG.timeLabel(v, opts.hours || 24), maxTicksLimit: 7, maxRotation: 0 } },
                y: { min: opts.min, max: opts.max, ticks: { callback: v => fmt(Math.abs(v)) } } },
      plugins: { legend: { display: datasets.length > 1, position: "bottom", labels: { boxWidth: 10 } },
                 tooltip: { callbacks: { title: i => new Date(i[0].parsed.x).toLocaleString(), label: c => `${c.dataset.label}: ${fmt(Math.abs(c.parsed.y))}` } } } } });
  },
  pieChart(id, rows) {
    return LG.chart(id, { type: "doughnut", data: { labels: rows.map(r => r.label ?? "?"),
      datasets: [{ data: rows.map(r => Number(r.v)), backgroundColor: rows.map((r, i) => LG.sourceColors[r.label] || LG.color(i)), borderWidth: 0 }] },
      options: { maintainAspectRatio: false, animation: false, plugins: { legend: { position: "right", labels: { boxWidth: 10 } } } } });
  },
  barChart(id, rows, horizontal) {
    return LG.chart(id, { type: "bar", data: { labels: rows.map(r => r.label ?? "?"),
      datasets: [{ data: rows.map(r => Number(r.v)), backgroundColor: rows.map((r, i) => LG.color(horizontal ? 0 : i)) }] },
      options: { indexAxis: horizontal ? "y" : "x", maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } },
                 scales: { y: { ticks: { autoSkip: false, font: { size: 11 } } } } } });
  },
  gauge(pct, label, sub) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0)), cls = p > 90 ? "bad" : p > 75 ? "warn" : "";
    return `<div class="gauge"><div class="gv">${pct === null || pct === undefined ? "–" : Math.round(p) + "%"}</div><div class="bar ${cls}"><i style="width:${p}%"></i></div><div class="l">${LG.esc(label)}</div>${sub ? `<div class="small muted">${sub}</div>` : ""}</div>`;
  },
};
