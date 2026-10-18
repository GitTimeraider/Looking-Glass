/* MonRaider shared front-end helpers */
"use strict";

const MR = {
  async api(path, opts = {}) {
    const init = { headers: { "Accept": "application/json", "X-MonRaider": "1" }, ...opts };
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
  sev(s) { return `<span class="badge ${MR.esc(s)}">${MR.esc(s)}</span>`; },
  syslogSev(n) { return ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"][n] || n; },
  ip(ip) { return ip ? `<a class="mono" href="/events?ip=${encodeURIComponent(ip)}&hours=168" title="show events">${MR.esc(ip)}</a>` : ""; },
  src(s) { return `<span class="badge src">${MR.esc(s)}</span>`; },
  flag(cc) {
    if (!cc || cc.length !== 2) return "";
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1A5 + c.charCodeAt(0))) + " " + MR.esc(cc);
  },
  /** Render a table. cols: [{k, l, f?: (v,row)=>html, num?: bool}] */
  table(el, cols, rows, empty = "No data") {
    if (typeof el === "string") el = document.querySelector(el);
    if (!rows || !rows.length) { el.innerHTML = `<div class="empty">${MR.esc(empty)}</div>`; return; }
    const head = cols.map(c => `<th class="${c.num ? "num" : ""}">${MR.esc(c.l)}</th>`).join("");
    const body = rows.map(r => "<tr>" + cols.map(c => {
      const v = r[c.k];
      const html = c.f ? c.f(v, r) : (c.num ? MR.num(v) : MR.esc(Array.isArray(v) ? v.join(", ") : v));
      return `<td class="${c.num ? "num" : ""}">${html}</td>`;
    }).join("") + "</tr>").join("");
    el.innerHTML = `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  },
  md(text) {
    if (window.marked && window.DOMPurify) return DOMPurify.sanitize(marked.parse(text || ""));
    return `<pre>${MR.esc(text)}</pre>`;
  },
  palette: ["#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#a855f7", "#14b8a6", "#ec4899", "#eab308", "#64748b", "#06b6d4", "#f97316", "#84cc16"],
  sourceColors: { firewall: "#3b82f6", nginx: "#22c55e", unbound: "#14b8a6", crowdsec: "#f97316", suricata: "#ef4444",
                  zenarmor: "#a855f7", qfeeds: "#ec4899", auth: "#eab308", vpn: "#06b6d4", dhcp: "#84cc16", system: "#64748b" },
  charts: {},
  chart(id, config) {
    if (MR.charts[id]) MR.charts[id].destroy();
    const el = document.getElementById(id);
    if (!el || !window.Chart) return null;
    Chart.defaults.color = "#8b98a9";
    Chart.defaults.borderColor = "#263241";
    MR.charts[id] = new Chart(el, config);
    return MR.charts[id];
  },
  qs() { return Object.fromEntries(new URLSearchParams(location.search)); },
  seg(el, value, onChange) {
    el.querySelectorAll("button").forEach(b => {
      b.classList.toggle("on", b.dataset.v === String(value));
      b.onclick = () => { el.querySelectorAll("button").forEach(x => x.classList.remove("on")); b.classList.add("on"); onChange(b.dataset.v); };
    });
  },
};
