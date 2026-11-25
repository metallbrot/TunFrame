/* TunFrame operations dashboard: polls the run directory API and renders it. */
"use strict";
const $ = id => document.getElementById(id);
const TOKEN = document.querySelector('meta[name="tunframe-token"]').content;
const METRICS = [
  {key: "f1", label: "F1", max: 1, fmt: v => v.toFixed(3)},
  {key: "precision", label: "Precision", max: 1, fmt: v => v.toFixed(3)},
  {key: "recall", label: "Recall", max: 1, fmt: v => v.toFixed(3)},
  {key: "fpr", label: "FPR", fmt: v => v.toPrecision(3)},
  {key: "traffic_volume_up_bytes", label: "Leak up", fmt: TF.fmtBytes},
];
// Resource series keep their color across runs: color follows the entity.
const RESOURCE_ENTITIES = ["main.py", "resolver", "root-simulator", "tld-simulator", "dnscollector",
                           "pcap-replayer", "dnsexfiltrator-server", "dnsexfiltrator-client"];
const ENDED_BY = {transfer_complete: "transfer complete", all_detected: "all detected", timer: "timer",
                  log_ended: "log ended", interrupted: "interrupted", user_skip: "skipped from dashboard",
                  user_stop: "stopped from dashboard"};
const STATUS_ICON = {completed: "✓", running: "●", skipped: "⊘", failed: "✕", interrupted: "■", pending: "○", "not-run": "–", done: "✓"};
const HIDDEN_PARAMS = new Set(["password", "name"]);

const state = {
  runs: [], runId: null, run: null, skew: 0,
  metrics: {runId: null, offset: -1, samples: []},
  log: {tab: "run", runId: null, configKey: null, offsets: {run: -1, server: -1, client: -1}, text: {run: "", server: "", client: ""}},
  metric: METRICS[0], showTable: false, lastControlId: null, timer: null,
};

/* ---------- helpers ---------- */
async function getJSON(url, init) {
  const res = await fetch(url, Object.assign({cache: "no-store"}, init));
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${res.status}`);
  return body;
}
const now = () => Date.now() + state.skew;
const parseTime = s => s ? new Date(s).getTime() : null;
function statusHTML(status) {
  return `<span class="st st-${TF.esc(status)}"><span class="st-icon" aria-hidden="true">${STATUS_ICON[status] ?? "•"}</span> ${TF.esc(String(status).replace("-", " "))}</span>`;
}
function detectors(run) {
  const names = new Set();
  for (const c of run.configs || []) for (const d of c.detectors || []) names.add(d.detector);
  return [...names].sort();
}
const detectorColor = name => TF.series(detectors(state.run).indexOf(name));
function endedBy(entry) {
  const end = entry?.wartime_end;
  if (!end?.reason) return "–";
  const label = ENDED_BY[end.reason] ?? end.reason;
  if (end.transfer_completed === false) return `${label} · transfer incomplete`;
  return end.transfer_seconds != null ? `${label} (${end.transfer_seconds.toFixed(1)} s)` : label;
}
function toast(text) {
  const el = $("toast");
  el.textContent = text; el.hidden = false;
  clearTimeout(el._t); el._t = setTimeout(() => { el.hidden = true; }, 5000);
}
const latestSample = () => state.metrics.samples[state.metrics.samples.length - 1];

/* ---------- data ---------- */
async function loadRuns() {
  state.runs = await getJSON("/api/runs");
  const select = $("run-select");
  select.replaceChildren(...state.runs.map(r => {
    const o = document.createElement("option");
    o.value = r.id; o.textContent = `${r.name} · ${r.started} · ${r.status}`;
    return o;
  }));
  if (!state.runs.length) { state.runId = null; return; }
  if (!state.runId || !state.runs.some(r => r.id === state.runId)) state.runId = state.runs[0].id;
  select.value = state.runId;
}

async function loadRun() {
  const run = await getJSON(`/api/run/${encodeURIComponent(state.runId)}`);
  state.skew = parseTime(run.server_time) - Date.now();
  if (run.control && run.control.id !== state.lastControlId) {
    if (state.lastControlId !== null) {
      toast(run.control.accepted ? `Run acknowledged: ${run.control.action.replace("_", " ")}` : `Run rejected: ${run.control.action}`);
    }
    state.lastControlId = run.control.id;
  }
  state.run = run;
}

async function loadMetrics() {
  const m = state.metrics;
  if (m.runId !== state.runId) Object.assign(m, {runId: state.runId, offset: -1, samples: []});
  for (let i = 0; i < 10; i++) {
    const chunk = await getJSON(`/api/run/${encodeURIComponent(state.runId)}/metrics?offset=${m.offset}`);
    m.samples.push(...chunk.samples);
    m.offset = chunk.offset;
    if (chunk.offset >= chunk.size || !chunk.samples.length) break;
  }
  if (m.samples.length > 20000) m.samples.splice(0, m.samples.length - 20000);
}

async function loadLog() {
  const lg = state.log, configKey = state.run?.current?.name ?? null;
  if (lg.runId !== state.runId) {
    Object.assign(lg, {runId: state.runId, configKey, offsets: {run: -1, server: -1, client: -1}, text: {run: "", server: "", client: ""}});
  } else if (configKey !== lg.configKey) {
    lg.configKey = configKey;  // a new configuration: tool logs restart at its offset
    if (configKey) { lg.offsets.server = lg.offsets.client = -1; lg.text.server = lg.text.client = ""; }
  }
  const tab = lg.tab;
  const url = tab === "run" ? `/api/run/${encodeURIComponent(state.runId)}/log`
                            : `/api/run/${encodeURIComponent(state.runId)}/toollog?which=${tab}`;
  for (let i = 0; i < 10; i++) {
    const chunk = await getJSON(`${url}${url.includes("?") ? "&" : "?"}offset=${lg.offsets[tab]}`);
    lg.offsets[tab] = chunk.offset;
    if (chunk.text) lg.text[tab] = (lg.text[tab] + chunk.text).split("\n").slice(-3000).join("\n");
    if (chunk.offset >= chunk.size) break;
  }
  renderLog();
}

/* ---------- timing ---------- */
function eta(run) {
  const W = run.timing?.wartime_duration, P = run.timing?.peacetime_duration || 0;
  if (run.status !== "running" || !W) return null;
  const done = new Set((run.configs || []).map(c => c.name));
  const current = run.current?.name;
  const pending = (run.planned_configs || []).filter(n => !done.has(n) && n !== current).length;
  const t = now();
  const finished = (run.configs || []).filter(c => c.started && c.finished)
    .map(c => (parseTime(c.finished) - parseTime(c.started)) / 1000);
  const perConfig = finished.length ? finished.reduce((a, b) => a + b, 0) / finished.length : W + 15;
  let upper = pending * (W + 15), estimate = pending * perConfig;
  if (run.phase === "setup") { upper += P + W + 15; estimate += P + perConfig; }
  else if (run.phase === "peacetime") {
    const rest = Math.max(0, P - (t - parseTime(run.phase_started)) / 1000);
    upper += rest + (current ? 0 : W + 15); estimate += rest + (current ? 0 : perConfig);
  }
  if (current) {
    const windowStart = parseTime(run.current.window_started), configStart = parseTime(run.current.started);
    const windowRest = windowStart ? Math.max(0, W - (t - windowStart) / 1000) : W;
    upper += windowRest + 5;
    estimate += Math.max(windowStart ? 0 : 5, perConfig - (t - configStart) / 1000);
    estimate = Math.min(estimate, upper);
  }
  return {estimate: t + estimate * 1000, upper: t + upper * 1000};
}

function renderTimes() {
  $("clock").textContent = TF.fmtClock(new Date(now()));
  const run = state.run;
  if (!run) return;
  const start = parseTime(run.started), end = run.finished ? parseTime(run.finished) : now();
  $("k-elapsed").textContent = TF.fmtDuration((end - start) / 1000);
  $("k-started").textContent = `since ${TF.fmtClock(new Date(start))}`;
  const e = eta(run);
  if (e) {
    $("k-eta").textContent = TF.fmtClock(new Date(e.estimate));
    $("k-eta-sub").textContent = `≈ ${TF.fmtDuration((e.estimate - now()) / 1000)} left · latest ${TF.fmtClock(new Date(e.upper))}`;
  } else {
    $("k-eta").textContent = run.finished ? TF.fmtClock(new Date(parseTime(run.finished))) : "–";
    $("k-eta-sub").textContent = run.finished ? "finished" : "";
  }
  renderWindowMeter();
}

function renderWindowMeter() {
  const run = state.run, fill = $("window-fill"), label = $("window-label");
  if (!fill || !run?.current?.window_started || !run.timing?.wartime_duration) return;
  const elapsed = (now() - parseTime(run.current.window_started)) / 1000, W = run.timing.wartime_duration;
  fill.style.width = `${Math.min(100, 100 * elapsed / W)}%`;
  label.textContent = `window ${TF.fmtDuration(elapsed)} of max ${TF.fmtDuration(W)}`;
}

/* ---------- rendering ---------- */
function renderTop() {
  const run = state.run, running = run?.status === "running";
  $("live").hidden = !running;
  $("btn-stop").hidden = $("btn-skip").hidden = !running;
  $("btn-skip").disabled = !(running && run.phase === "wartime");
  const link = $("report-link");
  link.hidden = !run?.has_report;
  if (run?.has_report) link.href = `/runs/${encodeURIComponent(state.runId)}/report.html`;
}

function renderKPIs() {
  const run = state.run, s = latestSample();
  $("k-status").innerHTML = statusHTML(run.status || "running");
  $("k-phase").textContent = run.status === "running" ? `${run.phase}${run.phase_detail ? " · " + run.phase_detail : ""}`
                                                       : (run.status_reason || "");
  const total = (run.planned_configs || []).length, done = (run.configs || []).length;
  $("k-config").textContent = run.current ? `${run.current.index} / ${run.current.total}` : `${done} / ${total}`;
  $("k-config-name").textContent = run.current?.name || (run.status === "running" ? run.phase : "all finished");
  const ex = s?.exfil && run.current && s.config === run.current.name ? s.exfil : null;
  $("k-exfil").textContent = ex ? `${ex.percent.toFixed(1)} %` : "–";
  $("k-exfil-bar").style.width = `${ex ? ex.percent : 0}%`;
  $("k-exfil-bar").classList.toggle("done", !!ex?.saved);
  $("k-exfil-sub").textContent = ex ? (ex.saved ? "✓ file saved" : ex.file_size ? `of ${TF.fmtBytes(ex.file_size)}` : "waiting for init")
                                    : "no transfer running";
  if (s) {
    $("k-qps").textContent = TF.fmtCompact(s.dns.qps);
    const share = s.dns.queries ? 100 * s.dns.tunnel_queries / s.dns.queries : 0;
    $("k-qps-sub").textContent = `tunnel ${TF.fmtCompact(s.dns.tunnel_qps)}/s · ${share.toFixed(1)} % of queries`;
  } else { $("k-qps").textContent = "–"; $("k-qps-sub").textContent = "waiting for samples"; }
}

function configRows(run) {
  const byName = new Map((run.configs || []).map(c => [c.name, c]));
  const names = [...(run.planned_configs || [])];
  for (const c of run.configs || []) if (!names.includes(c.name)) names.push(c.name);
  return names.map(name => {
    const entry = byName.get(name);
    const status = entry ? entry.status : run.current?.name === name ? "running" : run.status === "running" ? "pending" : "not-run";
    return {name, status, entry};
  });
}

function renderCurrent() {
  const run = state.run, el = $("current"), cur = run.current;
  if (cur) {
    const params = Object.entries(cur.parameters || {}).filter(([k]) => !HIDDEN_PARAMS.has(k));
    el.innerHTML = `<div class="cur-name">${TF.esc(cur.name)}</div>
      <div class="muted">${statusHTML("running")} · configuration ${cur.index} of ${cur.total}</div>
      <div class="window-meter"><div class="meter"><div class="meter-fill" id="window-fill"></div></div>
      <div class="kpi-sub" id="window-label">${cur.window_started ? "" : "starting server and client…"}</div></div>
      <dl class="params">${params.map(([k, v]) => `<dt>${TF.esc(k)}</dt><dd class="mono">${TF.esc(Array.isArray(v) ? v.join(", ") : v ?? "–")}</dd>`).join("")}</dl>`;
    renderWindowMeter();
  } else {
    const rows = configRows(run), last = [...rows].reverse().find(r => r.entry);
    el.innerHTML = run.status === "running"
      ? `<div class="cur-name">${TF.esc(run.phase)}</div><div class="muted">No configuration window is running yet.</div>`
      : `<div class="cur-name">Run ${statusHTML(run.status)}</div><div class="muted">${TF.esc(run.status_reason || "")}</div>
         ${last ? `<div class="muted">Last configuration: ${TF.esc(last.name)} (${TF.esc(endedBy(last.entry))})</div>` : ""}`;
  }
  const dets = detectors(run), rows = configRows(run);
  $("all-count").textContent = `(${rows.filter(r => r.entry).length} of ${rows.length} finished)`;
  const head = `<tr><th>Configuration</th><th class="l">Status</th><th class="l">Ended by</th><th>Tunnel q.</th>`
    + dets.map(d => `<th><span class="swatch" style="background:${detectorColor(d)}"></span>${TF.esc(d)}</th>`).join("") + `<th class="l"></th></tr>`;
  $("config-table").innerHTML = head + rows.map(({name, status, entry}) => {
    const f1 = new Map((entry?.detectors || []).map(d => [d.detector, d.f1]));
    const reason = entry?.reason && status !== "completed" ? ` <span class="muted">${TF.esc(entry.reason)}</span>` : "";
    return `<tr class="${run.current?.name === name ? "is-current" : ""}"><td>${TF.esc(name)}</td><td class="l">${statusHTML(status)}${reason}</td>
      <td class="l">${TF.esc(endedBy(entry))}</td><td>${entry?.dataset_statistics?.tunnel_queries ?? "–"}</td>
      ${dets.map(d => `<td>${f1.get(d) != null ? f1.get(d).toFixed(3) : "–"}</td>`).join("")}
      <td class="l">${entry ? `<a href="/runs/${encodeURIComponent(state.runId)}/${TF.esc(entry.file)}" target="_blank" rel="noopener">json</a>` : ""}</td></tr>`;
  }).join("");
}

function sampleTime(s) { return parseTime(s.t); }

function renderTraffic() {
  const samples = state.metrics.samples;
  const markers = [];
  let prev = null;
  for (const s of samples) { if (s.config && s.config !== prev) markers.push({x: sampleTime(s)}); prev = s.config; }
  TF.line($("chart-dns"), {
    label: "DNS queries per second", height: 220, emptyText: "Waiting for metrics…", markers,
    series: [
      {name: "All queries", color: TF.series(0), points: samples.map(s => ({x: sampleTime(s), y: s.dns.qps}))},
      {name: "Tunnel queries", color: TF.series(1), points: samples.map(s => ({x: sampleTime(s), y: s.dns.tunnel_qps}))},
    ],
    headFor: x => {
      const s = samples.find(v => sampleTime(v) === x);
      return `${TF.fmtClock(new Date(x))} · ${s?.config || s?.phase || ""}`;
    },
  });
  const current = state.run.current?.name;
  const exfil = samples.filter(s => s.exfil && s.config === current);
  $("exfil-config").textContent = current || "";
  TF.line($("chart-exfil"), {
    label: "Transfer progress", height: 180, yMax: 100, yFmt: v => `${Math.round(v)} %`,
    emptyText: current ? "Waiting for the transfer to start…" : "No transfer running",
    series: [{name: "Transferred", color: TF.series(0), points: exfil.map(s => ({x: sampleTime(s), y: s.exfil.percent}))}],
  });
}

function renderResources() {
  const samples = state.metrics.samples;
  const seen = new Set(["main.py"]);
  for (const s of samples) for (const name of Object.keys(s.containers || {})) seen.add(name);
  const entities = RESOURCE_ENTITIES.filter(e => seen.has(e));
  const value = (s, e, key) => e === "main.py" ? (key === "cpu" ? s.host?.cpu : s.host?.rss_mb) : s.containers?.[e]?.[key === "cpu" ? "cpu" : "mem_mb"];
  const build = key => entities.map(e => ({
    name: e, color: TF.series(RESOURCE_ENTITIES.indexOf(e)),
    points: samples.filter(s => value(s, e, key) != null).map(s => ({x: sampleTime(s), y: value(s, e, key)})),
  }));
  TF.line($("chart-cpu"), {label: "CPU per container", height: 180, emptyText: "Waiting for metrics…", series: build("cpu"), alwaysLegend: true});
  TF.line($("chart-mem"), {label: "Memory per container", height: 180, emptyText: "Waiting for metrics…", series: build("mem"), alwaysLegend: true});
}

function renderResults() {
  const run = state.run, m = state.metric, dets = detectors(run);
  const configs = (run.configs || []).filter(c => (c.detectors || []).length);
  $("results-title").textContent = `Detection results · ${m.label}`;
  TF.bars($("chart-results"), {
    label: `${m.label} by configuration`, yMax: m.max, yFmt: m.max ? (v => v.toFixed(1)) : (m.key.includes("bytes") ? TF.fmtBytes : TF.fmtCompact),
    seriesNames: dets, colorOf: detectorColor,
    groups: configs.map(c => ({name: c.name, values: Object.fromEntries(c.detectors.map(d => [d.detector, d[m.key]]))})),
  });
  $("results-table").innerHTML = `<table><tr><th>Configuration</th>${dets.map(d => `<th>${TF.esc(d)}</th>`).join("")}</tr>`
    + configs.map(c => `<tr><td>${TF.esc(c.name)}</td>${dets.map(d => {
        const row = c.detectors.find(x => x.detector === d);
        return `<td>${row && row[m.key] != null ? TF.esc(m.fmt(Number(row[m.key]))) : "–"}</td>`;
      }).join("")}</tr>`).join("") + `</table>`;
  const byConfig = new Map(configs.map(c => [c.name, new Map(c.detectors.map(d => [d.detector, d.f1]))]));
  TF.heatmap($("chart-heat"), {label: "F1 by detector and configuration", rows: dets, cols: configs.map(c => c.name),
    value: (r, c) => byConfig.get(c)?.get(r) ?? null});
}

function renderBreakdown() {
  const s = latestSample();
  const rcodes = Object.entries(s?.rcodes || {}).filter(([k]) => k !== "-").sort((a, b) => b[1] - a[1]).slice(0, 6);
  TF.hbars($("rcodes"), rcodes.map(([k, v]) => ({label: k, value: v})));
  TF.hbars($("top-domains"), (s?.top_domains || []).map(([d, n, tunnel]) => ({label: d, value: n, note: tunnel ? "tunnel" : ""})));
}

function renderLog() {
  const el = $("log"), text = state.log.text[state.log.tab];
  if (el.textContent !== text) {
    el.textContent = text || (state.log.tab === "run" ? "No log lines yet." : "No output from this tool for the running configuration yet.");
    if ($("follow").checked) el.scrollTop = el.scrollHeight;
  }
}

function renderAll() {
  if (!state.run) return;
  renderTop(); renderKPIs(); renderTimes(); renderCurrent();
  renderTraffic(); renderResources(); renderResults(); renderBreakdown();
}

function renderEmpty() {
  $("k-status").textContent = "No runs";
  $("current").innerHTML = '<div class="muted">Start an experiment with <code>python3 main.py</code>.</div>';
  for (const id of ["chart-dns", "chart-exfil", "chart-cpu", "chart-mem", "chart-results", "chart-heat"]) TF.empty($(id), "No data yet");
}

/* ---------- loop and controls ---------- */
async function tick() {
  clearTimeout(state.timer);
  try {
    await loadRuns();
    if (state.runId) {
      await loadRun();
      await loadMetrics();
      renderAll();
      await loadLog();
    } else renderEmpty();
  } catch (e) { toast(`Dashboard: ${e.message}`); }
  state.timer = setTimeout(tick, state.run?.status === "running" ? 2000 : 8000);
}

async function control(action, question) {
  if (!confirm(question)) return;
  try {
    await getJSON(`/api/run/${encodeURIComponent(state.runId)}/control`, {
      method: "POST", headers: {"Content-Type": "application/json", "X-TunFrame-Token": TOKEN},
      body: JSON.stringify({action}),
    });
    toast(`Request sent: ${action.replace("_", " ")}`);
  } catch (e) { toast(`Request failed: ${e.message}`); }
}

$("btn-skip").addEventListener("click", () => control("skip_config",
  "Skip the running configuration?\nIts window is evaluated up to now and saved as interrupted; the run continues with the next configuration."));
$("btn-stop").addEventListener("click", () => control("stop_run",
  "Stop the run?\nThe running window is evaluated up to now, remaining configurations are skipped, and the report is written."));
$("metric-buttons").innerHTML = METRICS.map((m, i) => `<button data-i="${i}" aria-pressed="${i === 0}">${m.label}</button>`).join("");
$("metric-buttons").addEventListener("click", ev => {
  const b = ev.target.closest("button"); if (!b) return;
  state.metric = METRICS[+b.dataset.i];
  $("metric-buttons").querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b));
  if (state.run) renderResults();
});
$("table-toggle").addEventListener("click", () => {
  state.showTable = !state.showTable;
  $("table-toggle").setAttribute("aria-pressed", state.showTable);
  $("results-table").hidden = !state.showTable;
});
$("log-tabs").addEventListener("click", ev => {
  const b = ev.target.closest("button"); if (!b) return;
  state.log.tab = b.dataset.log;
  $("log-tabs").querySelectorAll("button").forEach(x => x.setAttribute("aria-selected", x === b));
  renderLog();
  if (state.runId) loadLog().catch(e => toast(`Dashboard: ${e.message}`));
});
$("run-select").addEventListener("change", ev => { state.runId = ev.target.value; state.lastControlId = null; tick(); });

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("theme-toggle").textContent = theme === "dark" ? "Light" : "Dark";
  try { localStorage.setItem("tunframe-theme", theme); } catch (e) { /* storage unavailable */ }
  if (state.run) renderAll();
}
$("theme-toggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
const themeParam = new URLSearchParams(location.search).get("theme");
let savedTheme = null;
try { savedTheme = localStorage.getItem("tunframe-theme"); } catch (e) { /* storage unavailable */ }
applyTheme(["light", "dark"].includes(themeParam) ? themeParam : savedTheme || "dark");

let lastWidth = 0, resizeTimer = null;
new ResizeObserver(([entry]) => {
  const w = Math.round(entry.contentRect.width);
  if (w === lastWidth) return;
  lastWidth = w; clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (state.run) renderAll(); }, 120);
}).observe(document.querySelector("main"));
setInterval(renderTimes, 1000);
tick();
