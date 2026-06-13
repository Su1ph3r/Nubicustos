// nubicustos web UI (Pass A: shell + read-only screens, wired to /api/v1).
// Dependency-free vanilla. Operator screens (tools run, preflight, scan
// launcher with SSE progress) land in Pass B.
"use strict";

const TOKEN = new URLSearchParams(location.search).get("t") || "";
const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_C = { critical: "#ff5263", high: "#ff8a3d", medium: "#f3c14b", low: "#57a0ff", info: "#7e8a9c" };
const EDGE_C = { "exposed-to-internet": "#ff5263", admin: "#ff8a3d", "admin-root": "#ff8a3d", "can-escalate": "#f3c14b", "can-assume-role": "#57a0ff" };
const VERDICT_C = { confirmed: "#3fd089", unconfirmed: "#f3c14b", blocked: "#ff5263" };

const state = {
  meta: null, scanID: null, scanMeta: null,
  fSev: new Set(), fReach: "", fEvidence: false, fService: "", fProvider: "",
  sortKey: "severity", sortDir: 1,
  services: [], findings: [], selFinding: null,
  paths: [], selPath: 0,
};

// --- helpers ---------------------------------------------------------------
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const el = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).error?.message || detail; } catch {}
    const e = new Error(detail); e.status = r.status; throw e;
  }
  return r.json();
}

function sevPill(s) {
  const c = SEV_C[s] || "#7e8a9c";
  return `<span class="pill" style="border-color:${c}55;background:${c}1a;color:${c}"><span class="sw" style="background:${c}"></span>${esc(s)}</span>`;
}
function reachBadge(r) {
  if (r === "reachable") return `<span class="mono" style="color:#ff5263">● reachable</span>`;
  if (r === "not-reachable") return `<span class="mono" style="color:#7e8a9c">○ not reachable</span>`;
  return `<span class="mono" style="color:#7e8a9c">? unknown</span>`;
}

// preBlock renders a copyable code block. The copy button carries NO data — a
// delegated handler copies the adjacent <pre>'s textContent — so untrusted
// (cloud-derived) text never lands in an attribute or inline handler.
function preBlock(text, cls) {
  return `<div class="codewrap"><button class="copy" type="button" data-copy>copy</button><pre class="code ${cls || ""}">${esc(text)}</pre></div>`;
}
function flash(btn, txt, cls) {
  const orig = btn.getAttribute("data-orig") || btn.textContent;
  btn.setAttribute("data-orig", orig);
  btn.textContent = txt; if (cls) btn.classList.add(cls);
  setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1300);
}
function legacyCopy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand("copy"); document.body.removeChild(ta); return ok;
  } catch { return false; }
}
// Delegated clicks: copy buttons (read the adjacent <pre>, never embed data),
// and service/tool chips (data attributes, never interpolated into a handler).
document.addEventListener("click", (ev) => {
  const cp = ev.target.closest("[data-copy]");
  if (cp) {
    const pre = cp.parentElement.querySelector("pre");
    if (!pre) return;
    const text = pre.textContent;
    const ok = () => flash(cp, "✓ copied", "copied");
    const fail = () => { if (legacyCopy(text)) ok(); else flash(cp, "copy failed"); };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(ok, fail);
    else fail();
    return;
  }
  const svc = ev.target.closest("[data-svc]");
  if (svc) { setService(svc.getAttribute("data-svc")); return; }
  const tool = ev.target.closest("[data-tool]");
  if (tool) { startTool(tool.getAttribute("data-tool")); return; }
});

// --- boot + routing --------------------------------------------------------
async function boot() {
  try {
    state.meta = await api("/api/v1/meta");
  } catch (e) {
    document.body.innerHTML = `<div class="empty">Cannot reach the API: ${esc(e.message)}</div>`;
    return;
  }
  try {
    const scans = await api("/api/v1/scans?limit=1");
    state.scanID = scans.data?.[0]?.id || null;
    if (state.scanID) state.scanMeta = scans.data[0];
  } catch {}
  await refreshAuth();
  renderShell();
  window.addEventListener("hashchange", renderScreen);
  renderScreen();
}

const isOperator = () => state.meta && state.meta.mode === "operator";
const authPresent = () => state.auth && state.auth.status && state.auth.status !== "none";

async function refreshAuth() {
  if (!isOperator()) return;
  try { state.auth = await api("/api/v1/auth"); } catch { state.auth = { status: "none" }; }
}

async function refreshScans() {
  try {
    const s = await api("/api/v1/scans?limit=1");
    state.scanID = s.data?.[0]?.id || null;
    state.scanMeta = s.data?.[0] || null;
  } catch {}
  state.services = [];
  renderShell();
  renderScreen();
}

function screenName() { return (location.hash.replace("#/", "") || "overview"); }

const NAV = [
  ["overview", "Overview"], ["findings", "Findings"], ["paths", "Attack paths"],
  ["preflight", "Preflight"], ["tools", "Tools"],
];

function renderShell() {
  const op = state.meta.mode === "operator";
  document.body.innerHTML = `
  <div class="app ${op ? "op" : ""}">
    <aside class="side">
      <div class="logo">
        <svg class="reticle" viewBox="0 0 25 25" fill="none" stroke="#9ae64b" stroke-width="1.4">
          <circle cx="12.5" cy="12.5" r="8"/><circle cx="12.5" cy="12.5" r="1.6" fill="#9ae64b" stroke="none"/>
          <path d="M12.5 1v3M12.5 21v3M1 12.5h3M21 12.5h3"/></svg>
        <div><span class="wm">nubicustos</span><span class="sub">cloud posture</span></div>
      </div>
      <div class="scanpick">
        <div class="eyebrow">Active scan</div>
        <div class="val">${state.scanMeta ? esc(state.scanMeta.provider) + " · " + esc(state.scanMeta.account) : "— no scans —"}</div>
      </div>
      <nav class="nav"><div class="eyebrow">Results</div>${NAV.map(navLink).join("")}</nav>
      ${modeCard(op)}
    </aside>
    <main class="main">
      <header class="hdr">
        <div><div class="title" id="scr-title"></div><div class="subtitle" id="scr-sub"></div></div>
        <div class="right">
          ${state.scanMeta ? `<span class="chip">${esc(state.scanMeta.provider)} · ${esc(state.scanMeta.account)}</span>` : ""}
          ${op ? `<button class="btn primary" onclick="openLauncher()">▸ Run scan</button>` : ""}
        </div>
      </header>
      <div class="content"><div id="screen"></div></div>
    </main>
  </div>`;
}

function navLink([key, label]) {
  const active = key === screenName() ? "active" : "";
  return `<a class="${active}" href="#/${key}">${esc(label)}</a>`;
}

function modeCard(op) {
  if (op) {
    const a = state.auth;
    const sess = authPresent()
      ? `<div class="note mono" style="word-break:break-all">${esc(a.identity || "")}</div>
         <div class="note">${esc(a.method || "")}${a.expires_at ? " · exp " + esc(a.expires_at.slice(11, 16)) + "Z" : a.expiry === "unknown" ? " · exp unknown" : ""}</div>`
      : `<div class="note">no session</div>`;
    return `<div class="modecard op"><div class="row"><span class="dot"></span><span class="lbl">OPERATOR</span><span class="mono muted">127.0.0.1</span></div>
      ${sess}<button class="btn" style="margin-top:8px;width:100%" onclick="openAuthModal()">${authPresent() ? "session" : "sign in"}</button></div>`;
  }
  return `<div class="modecard read"><div class="row"><span class="dot"></span><span class="lbl">READ ONLY</span></div>
    <div class="note">Browse &amp; export results. No live actions.</div></div>`;
}

function setHeader(title, sub) {
  if (el("scr-title")) el("scr-title").textContent = title;
  if (el("scr-sub")) el("scr-sub").textContent = sub || "";
}

async function renderScreen() {
  // keep nav highlight in sync
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#/" + screenName()));
  const scr = el("screen");
  if (!scr) return;
  const s = screenName();
  if (!state.scanID && s !== "tools") {
    setHeader(cap(s), "");
    scr.innerHTML = `<div class="empty">No scans yet. Run a scan, then results appear here.</div>`;
    return;
  }
  try {
    if (s === "overview") await renderOverview(scr);
    else if (s === "findings") await renderFindings(scr);
    else if (s === "paths") await renderPaths(scr);
    else if (s === "tools") await renderTools(scr);
    else if (s === "preflight") await renderPreflight(scr);
    else scr.innerHTML = `<div class="empty">Unknown screen.</div>`;
  } catch (e) {
    scr.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// --- overview --------------------------------------------------------------
async function renderOverview(scr) {
  setHeader("Overview", "posture summary for the active scan");
  const sum = await api(`/api/v1/scans/${state.scanID}/summary`);
  const sev = sum.severity, reach = sum.reachability;
  const tallies = SEV.map((k) => `
    <div class="tally" style="border-top-color:${SEV_C[k]}" onclick="location.hash='#/findings'">
      <div class="k" style="color:${SEV_C[k]}"><span class="sw" style="background:${SEV_C[k]}"></span>${k}</div>
      <div class="metric">${sev[k] || 0}</div></div>`).join("");
  const exposed = reach.reachable, notReach = reach.not_reachable, totalReach = reach.reachable + reach.not_reachable + reach.unknown;
  const pct = totalReach ? Math.round((exposed / totalReach) * 100) : 0;
  scr.innerHTML = `
    <div class="card" style="margin-bottom:16px"><div class="mono" style="color:var(--tx-2)">${esc(state.scanMeta?.identity || "")}</div></div>
    <div class="grid tallies">${tallies}</div>
    <div class="grid" style="grid-template-columns:1fr 1fr;margin-bottom:16px">
      <div class="card"><div class="section-label">Reachability exposure</div>
        <div><span class="metric" style="color:#ff5263">${exposed}</span> <span class="muted">/ ${notReach} not reachable</span></div>
        <div class="mono muted" style="margin-top:6px">${pct}% exposed · ${totalReach} in scope</div></div>
      <div class="card"><div class="section-label">Total findings</div><div class="metric">${sum.total}</div></div>
    </div>
    <div class="card"><div class="section-label">Top attack paths</div>${
      (sum.top_paths || []).length
        ? sum.top_paths.map((p) => `<div class="pathitem" onclick="location.hash='#/paths'">
            <span class="score" style="color:${SEV_C[p.severity]}">${p.score}</span>
            <div><div>${esc(p.title)}</div><div class="fsub">${esc(p.severity)}</div></div></div>`).join("")
        : `<div class="muted">none</div>`
    }</div>`;
}

// --- findings --------------------------------------------------------------
function findingsQuery() {
  const q = new URLSearchParams();
  if (state.fSev.size) q.set("severity", [...state.fSev].join(","));
  if (state.fService) q.set("service", state.fService);
  if (state.fProvider) q.set("provider", state.fProvider);
  if (state.fReach) q.set("reachable", state.fReach);
  if (state.fEvidence) q.set("has_evidence", "true");
  q.set("sort", (state.sortDir < 0 ? "-" : "") + state.sortKey);
  return q.toString();
}

async function renderFindings(scr) {
  setHeader("Findings", "filterable posture findings");
  if (!state.services.length) {
    try { state.services = (await api(`/api/v1/scans/${state.scanID}/services`)).data || []; } catch {}
  }
  const res = await api(`/api/v1/scans/${state.scanID}/findings?` + findingsQuery());
  state.findings = res.data || [];
  const sevChips = SEV.map((s) => `<button class="fchip ${state.fSev.has(s) ? "on" : ""}" onclick="toggleSev('${s}')">${s}</button>`).join("");
  const reachChips = [["", "all"], ["reachable", "reachable"], ["not_reachable", "not reachable"], ["unknown", "unknown"]]
    .map(([v, l]) => `<button class="fchip ${state.fReach === v ? "on" : ""}" onclick="setReach('${v}')">${l}</button>`).join("");
  const svcChips = ["", ...state.services].map((s) => `<button class="fchip ${state.fService === s ? "on" : ""}" type="button" data-svc="${esc(s)}">${esc(s) || "all services"}</button>`).join("");
  const rows = state.findings.map((f, i) => `
    <tr class="row" onclick="openFinding(${i})">
      <td>${sevPill(f.severity)}</td>
      <td>${esc(f.title)}<div class="fsub">${esc(f.provider)} · ${esc(f.resource?.region || "-")} · ${esc(f.resource?.id || "-")}</div></td>
      <td class="mono">${esc(f.service)}</td>
      <td>${reachBadge(f.reachable)}</td>
    </tr>`).join("");
  scr.innerHTML = `
    <div class="card" style="margin-bottom:12px"><div class="filters">${sevChips}
      <span style="width:1px;height:18px;background:var(--hair-2);margin:0 4px"></span>${reachChips}
      <button class="fchip ${state.fEvidence ? "on" : ""}" onclick="toggleEvidence()">has evidence</button>
      <span class="mono muted" style="margin-left:auto">${state.findings.length} of ${res.total}</span></div>
      <div class="filters" style="margin-top:8px">${svcChips}</div></div>
    ${state.findings.length ? `<table class="findings"><thead><tr>
      <th onclick="sortBy('severity')">Severity</th><th>Finding</th>
      <th onclick="sortBy('service')">Service</th><th>Reachability</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="empty">No findings match these filters.</div>`}
    <div id="drawer-mount"></div>`;
}

window.toggleSev = (s) => { state.fSev.has(s) ? state.fSev.delete(s) : state.fSev.add(s); renderScreen(); };
window.setReach = (v) => { state.fReach = v; renderScreen(); };
window.setService = (v) => { state.fService = state.fService === v ? "" : v; renderScreen(); };
window.toggleEvidence = () => { state.fEvidence = !state.fEvidence; renderScreen(); };
window.sortBy = (k) => { if (state.sortKey === k) state.sortDir *= -1; else { state.sortKey = k; state.sortDir = 1; } renderScreen(); };

window.openFinding = (i) => {
  const f = state.findings[i];
  const mount = el("drawer-mount");
  const row = (lbl, val) => val ? `<div class="sec"><div class="section-label">${lbl}</div><div>${esc(val)}</div></div>` : "";
  const codeBlk = (lbl, val, cls) => val ? `<div class="sec"><div class="section-label">${lbl}</div>${preBlock(val, cls)}</div>` : "";
  const compliance = (f.compliance || []).map((c) => `<span class="pill" style="border-color:var(--border-mid);color:var(--tx-2)">${esc(c.framework)} / ${esc(c.control)}</span>`).join(" ");
  const evidence = (f.evidence || []).map((e) => `<div class="evidence" style="margin-top:8px">
      <div class="mono" style="font-size:10px"><span style="color:${e.vantage === "external" ? "#ff8a3d" : "#57a0ff"}">${esc(e.vantage)}</span>
      · <span style="color:${VERDICT_C[e.verdict] || "#7e8a9c"}">${esc(e.verdict)}</span></div>
      <div class="section-label" style="margin-top:8px">request</div><pre class="code">${esc(e.request)}</pre>
      <div class="section-label">response</div><pre class="code">${esc(e.response)}</pre></div>`).join("");
  mount.innerHTML = `<div class="scrim" onclick="closeDrawer()"></div><div class="drawer">
    <div class="dh">${sevPill(f.severity)} <button class="x" style="float:right" onclick="closeDrawer()">×</button>
      <div style="font-weight:700;font-size:15px;margin-top:8px">${esc(f.title)}</div>
      <div class="mono fsub">${esc(f.check_id)}</div></div>
    <div class="db">
      <div class="sec"><div class="section-label">resource</div>
        <div class="mono" style="font-size:11px">${esc(f.resource?.id || "-")} · ${esc(f.resource?.type || "")} · ${esc(f.resource?.region || "-")}</div>
        ${f.resource?.arn ? `<div class="mono" style="font-size:11px;color:var(--tx-mut);margin-top:4px">${esc(f.resource.arn)}</div>` : ""}</div>
      ${row("description", f.description)}${row("impact", f.impact)}
      ${codeBlk("remediation", f.remediation)}${codeBlk("proof of concept", f.poc, "poc")}
      ${row("reachability", f.reachable)}
      ${compliance ? `<div class="sec"><div class="section-label">compliance</div>${compliance}</div>` : ""}
      <div class="sec"><div class="section-label">validation evidence</div>${evidence || `<div class="muted">No captured evidence — configuration-derived.</div>`}</div>
    </div></div>`;
};
window.closeDrawer = () => { const m = el("drawer-mount"); if (m) m.innerHTML = ""; };

// --- attack paths ----------------------------------------------------------
async function renderPaths(scr) {
  setHeader("Attack paths", "scored exploit chains");
  state.paths = (await api(`/api/v1/scans/${state.scanID}/paths`)).data || [];
  if (!state.paths.length) { scr.innerHTML = `<div class="empty">No attack paths in this scan.</div>`; return; }
  const idx = Math.min(state.selPath, state.paths.length - 1);
  const list = state.paths.map((p, i) => `<div class="pathitem ${i === idx ? "sel" : ""}" onclick="selPath(${i})">
      <span class="score" style="color:${SEV_C[p.severity]}">${p.score}</span>
      <div><div>${esc(p.title)}</div><div class="fsub">${esc(p.severity)} · ${p.edges?.length || 0} hop(s)</div></div></div>`).join("");
  const p = state.paths[idx];
  const nodeLabel = (id) => (p.nodes || []).find((n) => n.id === id)?.label || id;
  const hops = (p.edges || []).map((e, i) => {
    const c = EDGE_C[e.kind] || "#7e8a9c";
    return `<div class="hop"><span class="node" style="border-color:${c}"></span>
      <div>${esc(nodeLabel(e.src))} → ${esc(nodeLabel(e.dst))} <span class="pill" style="border-color:${c}55;color:${c}">${esc(e.kind)}</span></div>
      ${e.detail ? `<div class="fsub">${esc(e.detail)}</div>` : ""}
      ${e.poc ? `<div style="margin-top:6px">${preBlock(e.poc, "poc")}</div>` : ""}</div>`;
  }).join("");
  scr.innerHTML = `<div class="paths-wrap"><div>${list}</div>
    <div class="card"><div><span class="metric" style="color:${SEV_C[p.severity]}">${p.score}</span><span class="muted">/100</span> ${sevPill(p.severity)}</div>
      <div style="font-weight:700;margin:8px 0">${esc(p.title)}</div>
      ${p.rationale ? `<div class="muted" style="margin-bottom:14px">${esc(p.rationale)}</div>` : ""}
      <div class="section-label">chain</div>${hops}</div></div>`;
}
window.selPath = (i) => { state.selPath = i; renderScreen(); };

// --- tools (read-only list; operator run in Pass B) ------------------------
async function renderTools(scr) {
  setHeader("Tools", "optional external scanners");
  const tools = (await api("/api/v1/tools")).data || [];
  const op = isOperator();
  const anyInstalled = tools.some((t) => t.available);
  const ctrl = (t) => {
    if (!op) return `<span class="disabled-action">operator only</span>`;
    if (!t.available) return `<span class="disabled-action">not installed</span>`;
    return `<button class="btn" type="button" data-tool="${esc(t.name)}">▸ run</button>`;
  };
  const rows = tools.map((t) => `<div class="pathitem" style="cursor:default">
      <span class="mono" style="color:${t.available ? "#3fd089" : "#7e8a9c"}">${t.available ? "●" : "○"}</span>
      <div style="flex:1"><div>${esc(t.name)} <span class="mono muted">${esc(t.category)}</span></div>
        <div class="fsub">${t.has_run ? "last " + esc(t.last_run) + " · " + t.findings + " findings" : "never run"}</div></div>
      <div>${ctrl(t)}</div></div>`).join("");
  const header = op
    ? `<div style="display:flex;justify-content:flex-end;margin-bottom:12px">
         <button class="btn primary" type="button" data-tool="" ${anyInstalled ? "" : "disabled"}>▸ Run all installed</button></div>`
    : "";
  scr.innerHTML = header + (rows || `<div class="empty">No tools registered.</div>`);
}

// --- preflight (operator-run report; Pass B adds the run button) -----------
async function renderPreflight(scr) {
  setHeader("Access preflight", "tool access for the active credential");
  const op = isOperator();
  const runBtn = op
    ? `<div style="display:flex;justify-content:flex-end;margin-bottom:12px"><button class="btn primary" onclick="runPreflight()" ${authPresent() ? "" : "disabled title='sign in first'"}>▸ Run / re-run preflight</button></div>`
    : "";
  try {
    const rep = await api("/api/v1/preflight");
    scr.innerHTML = runBtn + `<div class="banner">method: ${esc(rep.method)} · overall ${esc(rep.overall)}</div>` +
      (rep.tools || []).map(preflightCard).join("");
  } catch (e) {
    if (e.status === 404) {
      scr.innerHTML = runBtn + `<div class="empty">No preflight report yet.${op ? " Run one to check tool access." : " Available in operator mode."}</div>`;
    } else throw e;
  }
}

window.runPreflight = async () => {
  if (!authPresent()) { openAuthModal(); return; }
  const scr = el("screen");
  scr.innerHTML = `<div class="empty">checking access — simulating + probing IAM…</div>`;
  try {
    await api("/api/v1/preflight/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  } catch (e) {
    scr.innerHTML = `<div class="empty">preflight failed: ${esc(e.message)}</div>`;
    return;
  }
  renderScreen();
};
const RDY_C = { ready: "#3fd089", partial: "#f3c14b", unverified: "#9aa0d6", failed: "#ff5263", unknown: "#7e8a9c" };
function preflightCard(t) {
  const c = RDY_C[t.readiness] || "#7e8a9c";
  const list = (lbl, arr, col) => (arr && arr.length) ? `<div style="margin-top:8px"><div class="section-label">${lbl}</div><div class="mono" style="font-size:11px;color:${col}">${arr.map(esc).join(", ")}</div></div>` : "";
  return `<div class="card" style="border-top:2px solid ${c};margin-top:12px">
    <div><b>${esc(t.name)}</b> <span class="pill" style="border-color:${c}55;color:${c}">${esc(t.readiness)}</span></div>
    <div class="muted" style="margin-top:6px">${esc(t.remediation?.summary || "")}</div>
    ${list("missing (IAM-denied)", t.denied, "#ff5263")}
    ${list("runtime-blocked (SCP/boundary)", t.conflicts, "#ff8a3d")}
    ${list("could not verify", t.unknown, "#9aa0d6")}
    ${t.remediation?.policy_document ? `<div style="margin-top:8px"><div class="section-label">remediation policy</div>${preBlock(t.remediation.policy_document)}</div>` : ""}</div>`;
}

// --- operator actions: modals, SSE job streaming --------------------------
function openModal(html) {
  let m = el("modal-root");
  if (!m) { m = document.createElement("div"); m.id = "modal-root"; document.body.appendChild(m); }
  m.innerHTML = `<div class="modal-scrim"><div class="modal">${html}</div></div>`;
}
window.closeModal = () => { const m = el("modal-root"); if (m) m.innerHTML = ""; };

let activeJob = null;

// streamJob opens the SSE stream for a started job and renders live progress.
// The bar advances only on real backend "phase" events — never a timer. The
// stream resumes via Last-Event-ID on reconnect, so transient drops don't
// duplicate the log; a terminal frame is processed exactly once (finished
// guard), and a server that stays unreachable resolves to a "connection lost"
// state instead of spinning forever.
function streamJob(jobID, title, onDone) {
  openModal(`<h3>${esc(title)}</h3>
    <div class="phase-line" id="job-phase">starting…</div>
    <div class="prog indeterminate" id="job-prog"><i></i></div>
    <div class="log" id="job-log"></div>
    <div class="foot"><button class="btn danger" onclick="cancelJob()">× Cancel</button>
      <button class="btn" onclick="closeModal()">Hide</button></div>`);

  const append = (cls, msg) => {
    const L = el("job-log"); if (!L) return;
    const d = document.createElement("div");
    if (cls) d.className = cls;
    d.textContent = msg; // textContent: never interpret backend strings as HTML
    L.appendChild(d); L.scrollTop = L.scrollHeight;
  };
  const setPhase = (phase, done, total) => {
    const p = el("job-phase"); if (p) p.textContent = phase + (total > 0 ? ` — ${done}/${total}` : "");
    const bar = el("job-prog"); if (!bar) return;
    const fill = bar.querySelector("i");
    if (total > 0) { bar.classList.remove("indeterminate"); fill.style.width = Math.round((done / total) * 100) + "%"; }
    else { bar.classList.add("indeterminate"); fill.style.width = ""; }
  };

  const es = new EventSource(`/api/v1/jobs/${jobID}/events` + (TOKEN ? `?t=${encodeURIComponent(TOKEN)}` : ""));
  activeJob = { id: jobID, es };
  let finished = false, drops = 0;
  const finish = (fn) => { if (finished) return; finished = true; es.close(); fn(); };

  es.addEventListener("phase", (e) => { if (finished) return; drops = 0; const d = JSON.parse(e.data); setPhase(d.phase, d.done, d.total); append("ph", "→ " + d.phase + (d.total > 0 ? ` (${d.done}/${d.total})` : "") + (d.detail ? " · " + d.detail : "")); });
  es.addEventListener("log", (e) => { if (finished) return; drops = 0; append("", JSON.parse(e.data).message); });
  es.addEventListener("done", (e) => { drops = 0; const d = JSON.parse(e.data); finish(() => onDone(d)); });
  es.addEventListener("error", (e) => {
    // A named terminal frame carries data (status: error|cancelled); a bare
    // connection error does not — EventSource will reconnect and resume.
    let data = null; try { if (e.data) data = JSON.parse(e.data); } catch {}
    if (data) {
      const cancelled = data.status === "cancelled";
      finish(() => openModal(`<h3>${cancelled ? "Run cancelled" : "Run failed"}</h3>
        <div class="${cancelled ? "muted" : "err mono"}">${esc(data.message || "")}</div>
        <div class="foot"><button class="btn" onclick="closeModal()">Close</button></div>`));
      return;
    }
    if (finished) { es.close(); return; }
    if (++drops > 5) {
      finish(() => openModal(`<h3>Connection lost</h3>
        <div class="muted">Lost contact with the server; the job may still be running. Re-open this view to check its status.</div>
        <div class="foot"><button class="btn" onclick="closeModal()">Close</button></div>`));
    }
  });
}

window.cancelJob = async () => {
  const p = el("job-phase"); if (p) p.textContent = "cancelling…";
  if (!(activeJob && activeJob.id)) return;
  try {
    await api(`/api/v1/jobs/${activeJob.id}/cancel`, { method: "POST" });
  } catch (e) {
    const L = el("job-log"); if (L) { const d = document.createElement("div"); d.className = "err"; d.textContent = "cancel request failed: " + e.message; L.appendChild(d); }
  }
};

// scan launcher
window.openLauncher = () => {
  if (!authPresent()) { openAuthModal(); return; }
  openModal(`<h3>Run scan</h3>
    <label class="field"><span class="lbl">regions (comma-separated; blank = all enabled)</span>
      <input class="input" id="lc-regions" placeholder="us-east-1, us-west-2"></label>
    <label class="field"><span class="lbl"><input type="checkbox" id="lc-validate"> active validation (read-only)</span></label>
    <div class="foot"><button class="btn primary" onclick="startScan()">▸ Start scan</button>
      <button class="btn" onclick="closeModal()">Cancel</button>
      <span class="mono muted" style="margin-left:auto">live scan against ${esc(state.auth.account)}</span></div>`);
};
window.startScan = async () => {
  const regions = el("lc-regions").value.split(",").map((s) => s.trim()).filter(Boolean);
  const validate = el("lc-validate").checked;
  try {
    const r = await api("/api/v1/scans/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ regions, validate }) });
    streamJob(r.job_id, "Scanning…", async (data) => {
      const persisted = (data.scan_ids || []).length > 0;
      if (persisted) await refreshScans();
      openModal(`<h3>Scan complete</h3>
        <div class="muted">${esc(data.summary || (persisted ? "" : "no new results persisted"))}</div>
        <div class="foot">${persisted
          ? `<button class="btn primary" onclick="closeModal();location.hash='#/overview'">Open dashboard →</button>`
          : `<button class="btn" onclick="closeModal()">Close</button>`}</div>`);
    });
  } catch (e) {
    openModal(`<h3>Could not start scan</h3><div class="err mono">${esc(e.message)}</div>
      <div class="foot"><button class="btn" onclick="closeModal()">Close</button></div>`);
  }
};

// tool runs
window.startTool = async (name) => {
  try {
    const r = await api("/api/v1/tools/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tool: name, target: "." }) });
    streamJob(r.job_id, name ? "Running " + name + "…" : "Running all installed tools…", async (data) => {
      const persisted = (data.scan_ids || []).length > 0;
      if (persisted) await refreshScans();
      openModal(`<h3>Tools complete</h3><div class="muted">${esc(data.summary || "")}</div>
        <div class="foot">${persisted
          ? `<button class="btn primary" onclick="closeModal();location.hash='#/findings'">View findings →</button>`
          : `<button class="btn" onclick="closeModal()">Close</button>`}</div>`);
    });
  } catch (e) {
    openModal(`<h3>Could not start tool</h3><div class="err mono">${esc(e.message)}</div>
      <div class="foot"><button class="btn" onclick="closeModal()">Close</button></div>`);
  }
};

// auth / session
window.openAuthModal = () => {
  const a = state.auth;
  const status = authPresent()
    ? `<div class="mono muted" style="word-break:break-all">${esc(a.identity)}<br>${esc(a.method || "")}${a.expires_at ? " · expires " + esc(a.expires_at) : a.expiry === "unknown" ? " · expiry unknown" : ""}</div>`
    : `<div class="muted">No active session.</div>`;
  openModal(`<h3>AWS session</h3>${status}
    <div class="section-label" style="margin:14px 0 6px">sign in</div>
    <label class="field"><span class="lbl">profile</span><input class="input" id="au-profile" placeholder="default / named profile"></label>
    <label class="field"><span class="lbl">region</span><input class="input" id="au-region" placeholder="us-east-1"></label>
    <label class="field"><span class="lbl">mfa serial (optional)</span><input class="input" id="au-mfaserial"></label>
    <label class="field"><span class="lbl">mfa token (optional)</span><input class="input" id="au-mfatoken"></label>
    <div class="foot"><button class="btn primary" onclick="doLogin()">Sign in</button>
      ${authPresent() ? `<button class="btn" onclick="doLogout()">Sign out</button>` : ""}
      <button class="btn" onclick="closeModal()">Close</button></div>
    <div id="au-err" class="err mono" style="margin-top:8px"></div>`);
};
window.doLogin = async () => {
  const body = {
    provider: "aws", profile: el("au-profile").value.trim(), region: el("au-region").value.trim(),
    mfa_serial: el("au-mfaserial").value.trim(), mfa_token: el("au-mfatoken").value.trim(),
  };
  try {
    state.auth = await api("/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    closeModal(); renderShell(); renderScreen();
  } catch (e) { const er = el("au-err"); if (er) er.textContent = e.message; }
};
window.doLogout = async () => {
  try { await api("/api/v1/auth/logout", { method: "POST" }); } catch {}
  state.auth = { status: "none" };
  closeModal(); renderShell(); renderScreen();
};

boot();
