/* Security Alert Management Platform — dashboard (vanilla JS, no build step) */

const state = {
  key: localStorage.getItem("samp_api_key") || "",
  alerts: [],
  sources: new Set(),
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.key) headers["X-API-Key"] = state.key;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    $("loginOverlay").classList.remove("hidden");
    throw new Error("Unauthorized — API key required");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || res.statusText);
  }
  return res.json();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function badge(kind, value) {
  return `<span class="badge b-${kind}">${esc(value)}</span>`;
}

function renderStats(s) {
  const fp = s.false_positive_rate === null ? "—" : `${(s.false_positive_rate * 100).toFixed(1)}%`;
  $("stats").innerHTML = `
    <div class="card"><div class="num">${s.total}</div><div class="lbl">Total alerts</div></div>
    <div class="card crit"><div class="num">${s.by_severity.critical}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="num">${s.open_critical}</div><div class="lbl">Open critical</div></div>
    <div class="card"><div class="num">${s.by_status.escalated}</div><div class="lbl">Escalated</div></div>
    <div class="card"><div class="num">${s.by_classification.tp}</div><div class="lbl">TP</div></div>
    <div class="card"><div class="num">${fp}</div><div class="lbl">FP rate</div></div>`;
}

function populateSourceFilter(alerts) {
  alerts.forEach((a) => a.source && state.sources.add(a.source));
  const select = $("fSource");
  const current = select.value;
  select.innerHTML = '<option value="">All sources</option>' +
    [...state.sources].sort().map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  select.value = current;
}

function renderTable(alerts) {
  const body = $("alertsBody");
  if (!alerts.length) {
    body.innerHTML = '<tr><td colspan="8" class="empty">No alerts match the current filters.</td></tr>';
    return;
  }
  body.innerHTML = alerts.map((a) => {
    const ioc = a.ip_address || a.domain || a.file_hash || "—";
    const cls = a.classification ? badge(a.classification, a.classification.toUpperCase()) : '—';
    return `<tr data-id="${esc(a.id)}">
      <td>${badge(a.severity, a.severity.toUpperCase())}</td>
      <td class="title-cell">${esc(a.title)}</td>
      <td>${esc(a.source)}</td>
      <td class="mono">${esc(ioc)}</td>
      <td>${badge(a.status, a.status.replace("_", " "))}</td>
      <td>${cls}</td>
      <td>${esc(a.assignee) || "—"}</td>
      <td class="muted">${esc((a.created_at || "").slice(0, 16).replace("T", " "))}</td>
    </tr>`;
  }).join("");
  body.querySelectorAll("tr[data-id]").forEach((tr) => {
    tr.addEventListener("click", () => openDetail(tr.dataset.id));
  });
}

async function load() {
  try {
    const p = new URLSearchParams();
    if ($("q").value) p.set("q", $("q").value.trim());
    if ($("fSeverity").value) p.set("severity", $("fSeverity").value);
    if ($("fStatus").value) p.set("status", $("fStatus").value);
    if ($("fSource").value) p.set("source", $("fSource").value);
    const [alerts, stats] = await Promise.all([api(`/api/alerts?${p}`), api("/api/stats")]);
    state.alerts = alerts;
    renderStats(stats);
    populateSourceFilter(alerts);
    renderTable(alerts);
  } catch (e) {
    console.error(e);
  }
}

/* ---------- detail panel ---------- */
function timelineHTML(a) {
  if (!a.timeline || !a.timeline.length) return '<p class="muted">No timeline entries yet.</p>';
  return a.timeline.map((t) => `
    <div class="tl-entry">
      <div class="tl-head">
        <span class="tl-time">${esc((t.ts || "").slice(0, 19).replace("T", " "))}</span>
        <span class="tl-user">${esc(t.user)}</span>
        <span class="tl-action">${esc(t.action)}</span>
      </div>
      ${t.note ? `<div class="tl-note">${esc(t.note)}</div>` : ""}
    </div>`).join("");
}

async function openDetail(id) {
  let a;
  try {
    a = await api(`/api/alerts/${id}`);
  } catch (e) {
    return;
  }
  const enrich = Object.entries(a.enrichments || {});
  $("detailPanel").innerHTML = `
    <div class="panel-head">
      <div>
        <h2>${esc(a.title)}</h2>
        <p class="muted">${badge(a.severity, a.severity.toUpperCase())} ${badge(a.status, a.status.replace("_", " "))}
           ${a.classification ? badge(a.classification, a.classification.toUpperCase()) : ""} · ${esc(a.source)} · ${esc(a.id)}</p>
      </div>
      <button class="btn ghost" id="detailClose">✕ Close</button>
    </div>
    <div class="panel-body">
      <section>
        <h3>Description</h3>
        <p>${esc(a.description) || '<span class="muted">—</span>'}</p>
      </section>
      <section class="grid2">
        <div><h3>Indicators</h3>
          <p class="mono">IP: ${esc(a.ip_address) || "—"}<br/>Domain: ${esc(a.domain) || "—"}<br/>Hash: ${esc(a.file_hash) || "—"}</p>
        </div>
        <div><h3>MITRE ATT&CK</h3>
          ${a.mitre && a.mitre.length ? a.mitre.map((m) => `<span class="chip">${esc(m)}</span>`).join(" ") : '<span class="muted">—</span>'}
        </div>
      </section>
      <section>
        <h3>Triage actions</h3>
        <div class="row wrap">
          <select id="dStatus">
            ${["new", "analyzing", "escalated", "false_positive", "resolved"].map((s) =>
              `<option value="${s}" ${a.status === s ? "selected" : ""}>${s.replace("_", " ")}</option>`).join("")}
          </select>
          <select id="dClassification">
            <option value="">No classification</option>
            ${["fp", "btp", "tp"].map((c) =>
              `<option value="${c}" ${a.classification === c ? "selected" : ""}>${c.toUpperCase()}${c === "fp" ? " — false positive" : c === "btp" ? " — benign true positive" : " — true positive"}</option>`).join("")}
          </select>
          <input id="dAssignee" placeholder="Assign to…" value="${esc(a.assignee)}" />
          <button class="btn" id="dSave">Save triage</button>
          <button class="btn ghost" id="dEnrich">🔍 Enrich IOC</button>
        </div>
      </section>
      <section>
        <h3>Timeline</h3>
        ${timelineHTML(a)}
        <div class="row">
          <input id="dNote" placeholder="Add analyst note…" />
          <button class="btn" id="dAddNote">Add note</button>
        </div>
      </section>
      ${enrich.length ? `<section><h3>Enrichments</h3><pre class="json">${esc(JSON.stringify(a.enrichments, null, 2))}</pre></section>` : ""}
    </div>`;
  $("detailOverlay").classList.remove("hidden");

  $("detailClose").onclick = () => $("detailOverlay").classList.add("hidden");
  $("dSave").onclick = async () => {
    const note = $("dNote").value.trim();
    try {
      await api(`/api/alerts/${id}`, {
        method: "PATCH",
        body: JSON.stringify({
          status: $("dStatus").value,
          classification: $("dClassification").value || null,
          assignee: $("dAssignee").value.trim(),
          ...(note ? { note } : {}),
        }),
      });
      load(); openDetail(id);
    } catch (e) { alert(e.message); }
  };
  $("dAddNote").onclick = async () => {
    const note = $("dNote").value.trim();
    if (!note) return;
    try {
      await api(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ note }) });
      $("dNote").value = "";
      load(); openDetail(id);
    } catch (e) { alert(e.message); }
  };
  $("dEnrich").onclick = async () => {
    try {
      await api(`/api/alerts/${id}/enrich`, { method: "POST" });
      openDetail(id);
    } catch (e) { alert(e.message); }
  };
}

/* ---------- events ---------- */
$("refreshBtn").onclick = load;
["q", "fSeverity", "fStatus", "fSource"].forEach((id) =>
  $(id).addEventListener("input", () => {
    if (id === "q") clearTimeout(window._t);
    window._t = setTimeout(load, id === "q" ? 350 : 50);
  }));

$("loginBtn").onclick = () => $("loginOverlay").classList.remove("hidden");
$("loginCancel").onclick = () => $("loginOverlay").classList.add("hidden");
$("loginConfirm").onclick = () => {
  state.key = $("apiKeyInput").value.trim();
  localStorage.setItem("samp_api_key", state.key);
  $("loginOverlay").classList.add("hidden");
  load();
};
$("detailOverlay").addEventListener("click", (e) => {
  if (e.target === $("detailOverlay")) $("detailOverlay").classList.add("hidden");
});

load();