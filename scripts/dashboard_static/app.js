/* TunFrame operations dashboard: polls the run directory API and renders it. */
"use strict";
const $ = id => document.getElementById(id);
const TOKEN = document.querySelector('meta[name="tunframe-token"]').content;
const pct = v => `${v.toFixed(1)} %`, pct0 = v => `${v.toFixed(0)} %`;
// fmt: tables and tooltips; cell: heatmap cells; axis: y axis. lower: lower is better.
// ULV % / DLV %: share of the window's tunnel uplink / downlink payload that passed before
// the detector's alarm, i.e. how much of the file was uploaded when the transfer completed.
const METRICS = [
  {key: "f1", label: "F1", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "precision", label: "Precision", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "recall", label: "Recall", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "fpr", label: "FPR", lower: true, fmt: v => v.toPrecision(3), cell: v => v ? v.toPrecision(2) : "0"},
  {key: "ulv_percent", label: "ULV %", max: 100, lower: true, fmt: pct, cell: v => `${v.toFixed(0)}%`, axis: pct0},
  {key: "dlv_percent", label: "DLV %", max: 100, lower: true, fmt: pct, cell: v => `${v.toFixed(0)}%`, axis: pct0},
  {key: "traffic_volume_up_bytes", label: "Leak up", lower: true, fmt: TF.fmtBytes, cell: TF.fmtBytes, axis: TF.fmtBytes},
  {key: "runtime", label: "Runtime", lower: true, fmt: v => `${v.toFixed(1)} s`, cell: v => `${v.toFixed(1)}s`},
];
const axisFmt = m => m.axis || (m.max === 1 ? (v => v.toFixed(1)) : TF.fmtCompact);
// Resource series keep their color across runs: color follows the entity.
const RESOURCE_ENTITIES = ["main.py", "resolver", "root-simulator", "tld-simulator", "dnscollector",
                           "pcap-replayer", "dnsexfiltrator-server", "dnsexfiltrator-client"];
const ENDED_BY = {transfer_complete: "transfer complete", all_detected: "all detected", timer: "timer",
                  log_ended: "log ended", interrupted: "interrupted", user_skip: "skipped from dashboard",
                  user_stop: "stopped from dashboard"};
const STATUS_ICON = {completed: "✓", running: "●", skipped: "⊘", failed: "✕", interrupted: "■", pending: "○", "not-run": "–", done: "✓"};
const HIDDEN_PARAMS = new Set(["password", "name"]);

const state = {
  runs: [], runId: null, run: null, skew: 0, skewSet: false,
  metrics: {runId: null, offset: -1, samples: []},
  log: {tab: "run", runId: null, configKey: null, offsets: {run: -1, server: -1, client: -1}, text: {run: "", server: "", client: ""}},
  metric: METRICS[0], heatMetric: METRICS[0], detector: null, sweep: null,
  showTable: false, lastControlId: null, timer: null,
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
// Group the configurations by their origin (Baseline, each parameter sweep, Profiles),
// keeping the planned order. Falls back to one group when run.config_groups is absent.
function configGroups(run) {
  const meta = new Map((run.config_groups || []).map(g => [g.name, g]));
  const order = [], byGroup = new Map();
  for (const {name} of configRows(run)) {
    const g = meta.get(name)?.group || "Configurations";
    if (!byGroup.has(g)) { byGroup.set(g, []); order.push(g); }
    byGroup.get(g).push(name);
  }
  return order.map(g => ({group: g, kind: meta.get(byGroup.get(g)[0])?.kind, names: byGroup.get(g)}));
}
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
  // Set the clock offset once: server_time has second resolution, so recomputing
  // it every poll made the local clock jitter by up to a second.
  if (!state.skewSet && run.server_time) { state.skew = parseTime(run.server_time) - Date.now(); state.skewSet = true; }
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
  const byName = new Map(rows.map(r => [r.name, r]));
  const groups = configGroups(run), cols = 4 + dets.length + 1;
  $("all-count").textContent = `(${rows.filter(r => r.entry).length} of ${rows.length} finished)`;
  const head = `<tr><th>Configuration</th><th class="l">Status</th><th class="l">Ended by</th><th>Tunnel q.</th>`
    + dets.map(d => `<th><span class="swatch" style="background:${detectorColor(d)}"></span>${TF.esc(d)}</th>`).join("") + `<th class="l"></th></tr>`;
  const rowHTML = ({name, status, entry}) => {
    const f1 = new Map((entry?.detectors || []).map(d => [d.detector, d.f1]));
    const reason = entry?.reason && status !== "completed" ? ` <span class="muted">${TF.esc(entry.reason)}</span>` : "";
    return `<tr class="${run.current?.name === name ? "is-current" : ""}"><td>${TF.esc(name)}</td><td class="l">${statusHTML(status)}${reason}</td>
      <td class="l">${TF.esc(endedBy(entry))}</td><td>${entry?.dataset_statistics?.tunnel_queries ?? "–"}</td>
      ${dets.map(d => `<td>${f1.get(d) != null ? f1.get(d).toFixed(3) : "–"}</td>`).join("")}
      <td class="l">${entry ? `<a href="/runs/${encodeURIComponent(state.runId)}/${TF.esc(entry.file)}" target="_blank" rel="noopener">json</a>` : ""}</td></tr>`;
  };
  const body = groups.map(g => {
    const header = groups.length > 1
      ? `<tr class="group-row"><td class="l" colspan="${cols}">${TF.esc(g.group)}${g.kind === "sweep" ? ' <span class="muted small">sweep</span>' : ""}</td></tr>`
      : "";
    return header + g.names.map(n => rowHTML(byName.get(n))).join("");
  }).join("");
  $("config-table").innerHTML = head + body;
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

// Finished configurations in group order, with the group boundaries (null for one group).
function finishedConfigs(run) {
  const finished = new Map((run.configs || []).filter(c => (c.detectors || []).length).map(c => [c.name, c]));
  const configs = [], sections = [];
  for (const g of configGroups(run)) {
    const start = configs.length;
    for (const n of g.names) if (finished.has(n)) configs.push(finished.get(n));
    if (configs.length > start) sections.push({label: g.group, start, count: configs.length - start});
  }
  return {configs, sections: sections.length > 1 ? sections : null};
}
const valueOf = (config, det, key) => config.detectors.find(x => x.detector === det)?.[key] ?? null;
function meanOf(configs, det, key) {
  const v = configs.map(c => valueOf(c, det, key)).filter(x => x != null);
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
}
const show = (v, fmt) => v == null ? "–" : fmt(v);

function renderResults() {
  const run = state.run, m = state.metric, dets = detectors(run);
  const {configs, sections: groupSections} = finishedConfigs(run);
  $("results-title").textContent = `Detection results · ${m.label}${m.lower ? " (lower is better)" : ""}`;
  TF.bars($("chart-results"), {
    label: `${m.label} by configuration`, yMax: m.max, yFmt: axisFmt(m),
    seriesNames: dets, colorOf: detectorColor, sections: groupSections,
    groups: configs.map(c => ({name: c.name, values: Object.fromEntries(c.detectors.map(d => [d.detector, d[m.key]]))})),
  });
  $("results-table").innerHTML = `<table><tr><th>Configuration</th>${dets.map(d => `<th>${TF.esc(d)}</th>`).join("")}</tr>`
    + configs.map(c => `<tr><td>${TF.esc(c.name)}</td>${dets.map(d => {
        const row = c.detectors.find(x => x.detector === d);
        return `<td>${row && row[m.key] != null ? TF.esc(m.fmt(Number(row[m.key]))) : "–"}</td>`;
      }).join("")}</tr>`).join("") + `</table>`;
}

function renderHeat() {
  const run = state.run, m = state.heatMetric, dets = detectors(run);
  const {configs, sections} = finishedConfigs(run);
  const byName = new Map(configs.map(c => [c.name, c]));
  const values = configs.flatMap(c => dets.map(d => valueOf(c, d, m.key))).filter(v => v != null);
  $("heat-title").textContent = `Heatmap · ${m.label} by detector and configuration`;
  TF.heatmap($("chart-heat"), {
    label: `${m.label} by detector and configuration`, rows: dets, cols: configs.map(c => c.name), sections,
    max: m.max ?? Math.max(0, ...values), fmt: m.cell, note: m.lower ? "lower is better" : "higher is better",
    value: (r, c) => valueOf(byName.get(c), r, m.key),
  });
}

function renderDetectors() {
  const run = state.run, dets = detectors(run), {configs, sections} = finishedConfigs(run);
  const view = $("detector-view");
  if (!dets.length || !configs.length) {
    $("leaderboard").innerHTML = '<tr><td class="muted">No finished configuration yet</td></tr>';
    view.hidden = true;
    return;
  }
  view.hidden = false;
  const mean = (d, k) => meanOf(configs, d, k);
  const ranked = [...dets].sort((a, b) => (mean(b, "f1") ?? -1) - (mean(a, "f1") ?? -1));
  if (!dets.includes(state.detector)) state.detector = ranked[0];
  const det = state.detector, sw = d => `<span class="swatch" style="background:${detectorColor(d)}"></span>`;
  const detected = d => configs.filter(c => (valueOf(c, d, "tp") ?? 0) > 0).length;
  $("leaderboard").innerHTML = `<tr><th>#</th><th class="l">Detector</th><th class="l">Mean F1</th><th>Precision</th><th>Recall</th>
      <th>FPR</th><th>ULV %</th><th>DLV %</th><th>Detected</th><th>Runtime</th></tr>`
    + ranked.map((d, i) => {
      const f1 = mean(d, "f1");
      return `<tr data-det="${TF.esc(d)}" class="${d === det ? "is-selected" : ""}" tabindex="0"><td>${i + 1}</td>
        <td class="l">${sw(d)}${TF.esc(d)}</td>
        <td class="l mono">${show(f1, v => v.toFixed(3))}<span class="mini-meter" aria-hidden="true"><i style="width:${100 * (f1 || 0)}%"></i></span></td>
        <td>${show(mean(d, "precision"), v => v.toFixed(3))}</td><td>${show(mean(d, "recall"), v => v.toFixed(3))}</td>
        <td>${show(mean(d, "fpr"), v => v.toPrecision(3))}</td><td>${show(mean(d, "ulv_percent"), pct)}</td>
        <td>${show(mean(d, "dlv_percent"), pct)}</td><td>${detected(d)} / ${configs.length}</td>
        <td>${configs.reduce((a, c) => a + (valueOf(c, d, "runtime") || 0), 0).toFixed(1)} s</td></tr>`;
    }).join("");
  $("det-buttons").innerHTML = dets.map(d => `<button data-det="${TF.esc(d)}" aria-pressed="${d === det}">${sw(d)}${TF.esc(d)}</button>`).join("");
  $("det-name").innerHTML = `${sw(det)}${TF.esc(det)}`;
  const kpi = (label, value) => `<div class="mini-kpi"><div class="kpi-label">${label}</div><div class="kpi-value mono">${value}</div></div>`;
  $("det-kpis").innerHTML = kpi("Mean F1", show(mean(det, "f1"), v => v.toFixed(3)))
    + kpi("Mean recall", show(mean(det, "recall"), v => v.toFixed(3)))
    + kpi("Mean FPR", show(mean(det, "fpr"), v => v.toPrecision(3)))
    + kpi("Mean ULV %", show(mean(det, "ulv_percent"), pct))
    + kpi("Detected", `${detected(det)} / ${configs.length}`)
    + kpi("Time per line", show(mean(det, "avg_process_time_ms"), v => `${v.toPrecision(2)} ms`));
  const PRF = ["Precision", "Recall", "F1"], LEAK = ["ULV %", "DLV %"];
  TF.bars($("chart-det-prf"), {
    label: `Precision, recall and F1 of ${det}`, yMax: 1, yFmt: v => v.toFixed(1), seriesNames: PRF, sections,
    colorOf: n => TF.series(PRF.indexOf(n)),
    groups: configs.map(c => ({name: c.name, values: {Precision: valueOf(c, det, "precision"), Recall: valueOf(c, det, "recall"), F1: valueOf(c, det, "f1")}})),
  });
  TF.bars($("chart-det-leak"), {
    label: `Leaked share of ${det}`, yMax: 100, yFmt: pct0, seriesNames: LEAK, sections,
    colorOf: n => TF.series(LEAK.indexOf(n)),
    groups: configs.map(c => ({name: c.name, values: {"ULV %": valueOf(c, det, "ulv_percent"), "DLV %": valueOf(c, det, "dlv_percent")}})),
  });
  const cols = ["precision", "recall", "f1", "fpr", "ulv_percent", "dlv_percent", "tp", "fp", "fn", "tn", "traffic_volume_up_bytes", "runtime"];
  const fmts = {precision: v => v.toFixed(3), recall: v => v.toFixed(3), f1: v => v.toFixed(3), fpr: v => v.toPrecision(3),
                ulv_percent: pct, dlv_percent: pct, traffic_volume_up_bytes: TF.fmtBytes, runtime: v => `${v.toFixed(1)} s`};
  const groupOf = new Map((run.config_groups || []).map(g => [g.name, g.group]));
  let last = null;
  $("det-table").innerHTML = `<tr><th>Configuration</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>ULV %</th><th>DLV %</th>
      <th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Leak up</th><th>Runtime</th></tr>`
    + configs.map(c => {
      const g = groupOf.get(c.name), head = sections && g !== last ? `<tr class="group-row"><td class="l" colspan="13">${TF.esc(g || "")}</td></tr>` : "";
      last = g;
      return head + `<tr><td>${TF.esc(c.name)}</td>${cols.map(k => `<td>${show(valueOf(c, det, k), fmts[k] || String)}</td>`).join("")}</tr>`;
    }).join("");
}

function renderTradeoff() {
  const run = state.run, {configs} = finishedConfigs(run);
  TF.scatter($("chart-tradeoff"), {
    label: "Recall over false positive rate", yMax: 1, height: 260, xName: "FPR", yName: "Recall",
    xFmt: v => v === 0 ? "0" : v.toPrecision(2), yFmt: v => v.toFixed(1),
    xLabel: "False positive rate (lower is better)", yLabel: "Recall",
    series: detectors(run).map(d => ({name: d, color: detectorColor(d),
      points: configs.map(c => ({x: valueOf(c, d, "fpr"), y: valueOf(c, d, "recall"), label: c.name})).filter(p => p.x != null && p.y != null)})),
  });
}

// Sweeps of the run: [{name, parameter, items: [{config, value}]}] in planned order.
function sweepsOf(run) {
  const sweeps = new Map();
  for (const g of run.config_groups || []) {
    if (g.kind !== "sweep" || !g.parameter) continue;
    if (!sweeps.has(g.group)) sweeps.set(g.group, {name: g.group, parameter: g.parameter, items: []});
    sweeps.get(g.group).items.push({config: g.name, value: g.value});
  }
  return [...sweeps.values()];
}

function renderSweeps() {
  const run = state.run, m = state.metric, sweeps = sweepsOf(run);
  if (!sweeps.length) {
    $("sweep-buttons").innerHTML = ""; $("sweep-title").textContent = "Sweeps";
    return TF.empty($("chart-sweep"), "This run has no parameter sweep");
  }
  if (!sweeps.some(sw => sw.name === state.sweep)) state.sweep = sweeps[0].name;
  const sweep = sweeps.find(sw => sw.name === state.sweep);
  $("sweep-buttons").innerHTML = sweeps.length > 1
    ? sweeps.map(sw => `<button data-sweep="${TF.esc(sw.name)}" aria-pressed="${sw.name === sweep.name}">${TF.esc(sw.name)}</button>`).join("") : "";
  $("sweep-title").textContent = `Sweep ${sweep.name} · ${m.label} over ${sweep.parameter}`;
  const byName = new Map((run.configs || []).filter(c => (c.detectors || []).length).map(c => [c.name, c]));
  const numeric = sweep.items.every(it => typeof it.value === "number");
  const xOf = (it, i) => numeric ? it.value : i;
  const labels = sweep.items.map(it => String(it.value));
  TF.line($("chart-sweep"), {
    label: `${m.label} over ${sweep.parameter}`, height: 240, dots: true, alwaysLegend: false,
    yMax: m.max, yFmt: axisFmt(m), emptyText: "No finished configuration of this sweep yet",
    xFmt: x => numeric ? TF.fmtCompact(x) : (labels[Math.round(x)] ?? ""),
    xTickValues: sweep.items.length <= 12 ? sweep.items.map(xOf) : null,
    headFor: x => `${sweep.parameter} = ${numeric ? x : labels[Math.round(x)]}`,
    series: detectors(run).map(d => ({name: d, color: detectorColor(d),
      points: sweep.items.map((it, i) => ({x: xOf(it, i), y: byName.has(it.config) ? valueOf(byName.get(it.config), d, m.key) : null}))
        .filter(p => p.y != null)})),
  });
}

// Share of each category within the benign and within the tunnel side; the legend
// carries each side's count (queries or answer records), so 100 % reads as "all of them".
function shareBars(el, block, {numeric = false, binLabel = k => k, top = 8, unit = "queries"} = {}) {
  const b = block?.b || {}, t = block?.t || {};
  const sum = o => Object.values(o).reduce((a, v) => a + v, 0), tb = sum(b), tt = sum(t);
  let keys = [...new Set([...Object.keys(b), ...Object.keys(t)])];
  keys = numeric ? keys.sort((x, y) => +x - +y)
    : keys.sort((x, y) => ((b[y] || 0) / (tb || 1) + (t[y] || 0) / (tt || 1)) - ((b[x] || 0) / (tb || 1) + (t[x] || 0) / (tt || 1))).slice(0, top);
  const SIDES = [`Benign · ${TF.fmtCompact(tb)} ${unit}`, `Tunnel · ${TF.fmtCompact(tt)} ${unit}`];
  TF.bars(el, {
    label: `Share of ${unit} within benign and tunnel traffic`, seriesNames: SIDES, colorOf: n => TF.series(SIDES.indexOf(n)),
    yFmt: pct0, plotHeight: 140, emptyText: "Waiting for DNS details…",
    groups: keys.map(k => ({name: binLabel(k), values: {[SIDES[0]]: tb ? 100 * (b[k] || 0) / tb : null, [SIDES[1]]: tt ? 100 * (t[k] || 0) / tt : null}})),
  });
}

function renderRecords() {
  const detail = [...state.metrics.samples].reverse().find(s => s.dns_detail)?.dns_detail;
  shareBars($("chart-qtypes"), detail?.qtypes);
  shareBars($("chart-atypes"), detail?.answer_types, {unit: "answer records"});
  shareBars($("chart-qlen"), detail?.qname_len, {numeric: true, binLabel: k => `${k}–${+k + 9}`});
  shareBars($("chart-entropy"), detail?.entropy, {numeric: true, binLabel: k => `${(+k).toFixed(1)}–${(+k + 0.5).toFixed(1)}`});
  if (!detail) { $("dns-avg").innerHTML = '<tr><td class="muted">Waiting for DNS details…</td></tr>'; return; }
  const total = side => Object.values(detail.qtypes?.[side] || {}).reduce((a, v) => a + v, 0);
  const udp = side => { const p = detail.protocols?.[side] || {}, n = Object.values(p).reduce((a, v) => a + v, 0); return n ? 100 * (p.UDP || 0) / n : null; };
  const avg = (side, k) => detail.avg?.[side]?.[k] ?? null;
  const row = (label, f) => `<tr><td>${label}</td><td>${f("b")}</td><td>${f("t")}</td></tr>`;
  $("dns-avg").innerHTML = `<tr><th>Measure</th><th><span class="swatch" style="background:${TF.series(0)}"></span>Benign</th>
      <th><span class="swatch" style="background:${TF.series(1)}"></span>Tunnel</th></tr>`
    + row("Queries", s => TF.fmtCompact(total(s)))
    + row("Query size", s => show(avg(s, "query_bytes"), v => `${v.toFixed(0)} B`))
    + row("Response size", s => show(avg(s, "response_bytes"), v => `${v.toFixed(0)} B`))
    + row("Answers per response", s => show(avg(s, "answers_per_response"), v => v.toFixed(2)))
    + row("UDP share", s => show(udp(s), pct));
}

function renderBreakdown() {
  const s = latestSample();
  const rcodes = Object.entries(s?.rcodes || {}).filter(([k]) => k !== "-").sort((a, b) => b[1] - a[1]).slice(0, 6);
  TF.hbars($("rcodes"), rcodes.map(([k, v]) => ({label: k, value: v})));
  TF.hbars($("top-domains"), (s?.top_domains || []).map(([d, n, tunnel]) => ({label: d, value: n, note: tunnel ? "tunnel" : ""})));
}

function renderLog() {
  const el = $("log");
  const raw = state.log.text[state.log.tab]
    || (state.log.tab === "run" ? "No log lines yet." : "No output from this tool for the running configuration yet.");
  if (el.dataset.raw === raw) return;
  el.dataset.raw = raw;
  el.innerHTML = TF.ansiToHtml(raw);  // render the tools' ANSI colours
  if ($("follow").checked) el.scrollTop = el.scrollHeight;
}

function renderAll() {
  if (!state.run) return;
  renderTop(); renderKPIs(); renderTimes(); renderCurrent();
  renderTraffic(); renderResources(); renderResults(); renderBreakdown();
  renderHeat(); renderDetectors(); renderTradeoff(); renderSweeps(); renderRecords();
}

function renderEmpty() {
  $("k-status").textContent = "No runs";
  $("current").innerHTML = '<div class="muted">Start an experiment with <code>python3 main.py</code>.</div>';
  for (const id of ["chart-dns", "chart-cpu", "chart-mem", "chart-results", "chart-heat", "chart-tradeoff", "chart-sweep",
                    "chart-qtypes", "chart-atypes", "chart-qlen", "chart-entropy"]) TF.empty($(id), "No data yet");
  $("detector-view").hidden = true;
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
function metricButtons(id, key, render) {
  $(id).innerHTML = METRICS.map((m, i) => `<button data-i="${i}" aria-pressed="${i === 0}">${m.label}</button>`).join("");
  $(id).addEventListener("click", ev => {
    const b = ev.target.closest("button"); if (!b) return;
    state[key] = METRICS[+b.dataset.i];
    $(id).querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b));
    if (state.run) render();
  });
}
metricButtons("metric-buttons", "metric", () => { renderResults(); renderSweeps(); });
metricButtons("heat-buttons", "heatMetric", renderHeat);
function selectDetector(ev) {
  const el = ev.target.closest("[data-det]"); if (!el) return;
  state.detector = el.dataset.det;
  if (state.run) renderDetectors();
}
$("det-buttons").addEventListener("click", selectDetector);
$("leaderboard").addEventListener("click", selectDetector);
$("leaderboard").addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectDetector(ev); } });
$("sweep-buttons").addEventListener("click", ev => {
  const b = ev.target.closest("button"); if (!b) return;
  state.sweep = b.dataset.sweep;
  if (state.run) renderSweeps();
});
$("table-toggle").addEventListener("click", () => {
  state.showTable = !state.showTable;
  $("table-toggle").setAttribute("aria-pressed", state.showTable);
  $("table-toggle").textContent = state.showTable ? "Chart" : "Table";
  $("results-table").hidden = !state.showTable;
  $("chart-results").hidden = state.showTable;  // the chart's labels overlapped the table
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
