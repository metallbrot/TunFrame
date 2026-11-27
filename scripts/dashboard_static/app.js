/* TunFrame operations dashboard: polls the run directory API and renders it. */
"use strict";
const $ = id => document.getElementById(id);
const TOKEN = document.querySelector('meta[name="tunframe-token"]').content;
const pct = v => `${v.toFixed(1)} %`, pct0 = v => `${v.toFixed(0)} %`;
// fmt: tables and tooltips; cell: heatmap cells; axis: y axis. lower: lower is better.
// ULV %: how much of the exfiltrated file left before the detector's alarm (DNSExfiltrator mode:
// decoded file bytes over the size the tool announced; tunnel replay: share of the raw tunnel
// uplink). DLV %: the same share for the downlink. Net leak: file bytes before the alarm.
const METRICS = [
  {key: "f1", label: "F1", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "precision", label: "Precision", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "recall", label: "Recall", max: 1, fmt: v => v.toFixed(3), cell: v => v.toFixed(2)},
  {key: "fpr", label: "FPR", lower: true, fmt: v => v.toPrecision(3), cell: v => v ? v.toPrecision(2) : "0"},
  {key: "ulv_percent", label: "ULV %", max: 100, lower: true, fmt: pct, cell: v => `${v.toFixed(0)}%`, axis: pct0},
  {key: "dlv_percent", label: "DLV %", max: 100, lower: true, fmt: pct, cell: v => `${v.toFixed(0)}%`, axis: pct0},
  {key: "net_up_bytes", label: "Net leak", lower: true, fmt: TF.fmtBytes, cell: TF.fmtBytes, axis: TF.fmtBytes},
  {key: "traffic_volume_up_bytes", label: "Leak up", lower: true, fmt: TF.fmtBytes, cell: TF.fmtBytes, axis: TF.fmtBytes},
  {key: "runtime", label: "Runtime", lower: true, fmt: v => `${v.toFixed(1)} s`, cell: v => `${v.toFixed(1)}s`},
];
// Benign-only ranking columns (benign-only window: every alarm is a false positive). "tunnel":
// needs finished tunnel configurations. tunnel_fpr: mean FPR over them; change: tunnel minus benign.
const BENIGN_COLUMNS = [
  {key: "fpr", label: "FPR benign-only", fmt: v => fmtFpr(v), lower: true, meter: true},
  {key: "tunnel_fpr", label: "FPR with tunnel", fmt: v => fmtFpr(v), lower: true, tunnel: true,
   title: "mean FPR over the finished tunnel configurations"},
  {key: "change", label: "Change", fmt: v => (v > 0 ? "+" : "") + fmtFpr(v), lower: true, tunnel: true,
   title: "FPR with tunnel minus FPR benign-only"},
  {key: "fp", label: "FP domains", fmt: String, lower: true, title: "falsely flagged registered domains"},
  {key: "tn", label: "TN domains", fmt: String, title: "registered domains without an alarm"},
  {key: "fp_domains_per_hour", label: "FP / h", fmt: v => v.toFixed(1), lower: true, title: "falsely flagged domains per hour of the window"},
  {key: "allowlist_size", label: "Allowlist", fmt: v => TF.fmtCompact(v), title: "detector allowlist: peacetime alarms plus the global allowlist"},
];
// Configuration ranking columns: each finished tunnel configuration over all detectors.
// evasive: the sort direction that puts the most evasive configuration first (first click).
const CONFIG_COLUMNS = [
  {key: "mean_ulv", label: "Mean ULV %", fmt: pct, evasive: "desc", meter: 100,
   title: "share of the file that left before the alarm, mean over the detectors"},
  {key: "min_ulv", label: "Min ULV %", fmt: pct, evasive: "desc", title: "share that left even before the best detector's alarm"},
  {key: "mean_net", label: "Mean net leak", fmt: v => TF.fmtBytes(v), evasive: "desc",
   title: "file bytes before the alarm, mean over the detectors (DNSExfiltrator mode)"},
  {key: "file", label: "File", fmt: v => TF.fmtBytes(v), evasive: "desc", title: "file size the tool announced"},
  {key: "detected", label: "Detected by", evasive: "asc", title: "detectors that flagged a tunneling domain"},
  {key: "mean_f1", label: "Mean F1", fmt: v => v.toFixed(3), evasive: "asc"},
  {key: "tunnel_queries", label: "Tunnel q.", fmt: v => TF.fmtCompact(v), evasive: "desc"},
  {key: "duration", label: "Window", fmt: v => TF.fmtDuration(v), evasive: "desc", title: "length of the configuration's window"},
];
// Detector ranking columns: exfiltration volume first, then detection quality.
const RANK_COLUMNS = [
  {key: "ulv_percent", label: "ULV %", fmt: pct, lower: true, meter: 100},
  {key: "net_up_bytes", label: "Net leak", fmt: TF.fmtBytes, lower: true},
  {key: "f1", label: "Mean F1", fmt: v => v.toFixed(3), meter: 1},
  {key: "precision", label: "Precision", fmt: v => v.toFixed(3)},
  {key: "recall", label: "Recall", fmt: v => v.toFixed(3)},
  {key: "fpr", label: "FPR", fmt: v => v.toPrecision(3), lower: true},
  {key: "dlv_percent", label: "DLV %", fmt: pct, lower: true},
  {key: "detected", label: "Detected"},
  {key: "runtime", label: "Runtime", fmt: v => `${v.toFixed(1)} s`, lower: true},
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
  metric: METRICS[0], heatMetric: METRICS[0], sweepMetric: METRICS[0], detector: null, sweep: null,
  rankSort: {key: "ulv_percent", dir: "asc"},
  // Detectors card: "wartime" / "benign" ranking; null = automatic (benign until a tunnel configuration finished)
  detMode: null, benignSort: {key: "fpr", dir: "asc"},
  configSort: {key: "mean_ulv", dir: "desc"},   // configuration ranking: most exfiltrated first
  showTable: false, lastControlId: null, timer: null,
  followLatest: true,   // switch to a newly started run unless an older run was picked
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
// Decoded tunnel data of a window next to the file size the tools reported.
const NET_CHECK = {match: "✓", incomplete: "transfer incomplete", mismatch: "≠ tool size", unknown: ""};
function netVolume(stats) {
  if (stats?.tunnel_net_up_bytes == null) return "–";
  const size = stats.exfil_file_bytes ?? stats.exfil_file_bytes_server;
  const note = NET_CHECK[stats.net_volume_check] ?? "";
  return `${TF.fmtBytes(stats.tunnel_net_up_bytes)} / ${size != null ? TF.fmtBytes(size) : "?"}${note ? ` <span class="muted">${TF.esc(note)}</span>` : ""}`;
}
function toast(text) {
  const el = $("toast");
  el.textContent = text; el.hidden = false;
  clearTimeout(el._t); el._t = setTimeout(() => { el.hidden = true; }, 5000);
}
const latestSample = () => state.metrics.samples[state.metrics.samples.length - 1];
// Benign-only window (timing.benign_only_duration): runs between peacetime and the tunnel
// windows with benign traffic only, so every alarm is a false positive; it
// measures each detector's FPR without adversarial load. It is kept out of every tunnel
// aggregate (results, heatmap, ranking, trade-off) and shown in its own info box.
// A benign-only run (mode "benign_only") has this window and no tunnel windows.
const BENIGN = "benign_only";
const isBenignOnly = run => run?.mode === "benign_only";
const hasBenignWindow = run => (run?.planned_configs || []).includes(BENIGN) || (run?.configs || []).some(c => c.name === BENIGN);
const fmtFpr = v => v === 0 ? "0" : v.toPrecision(3);

/* ---------- data ---------- */
async function loadRuns() {
  state.runs = await getJSON("/api/runs");
  const select = $("run-select");
  select.replaceChildren(...state.runs.map(r => {
    const o = document.createElement("option");
    o.value = r.id; o.textContent = `${r.name} · ${r.started} · ${r.status}${r.mode === "benign_only" ? " · benign only" : ""}`;
    return o;
  }));
  if (!state.runs.length) { state.runId = null; return; }
  if (!state.runId || !state.runs.some(r => r.id === state.runId) || (state.followLatest && state.runId !== state.runs[0].id)) {
    state.runId = state.runs[0].id;
    state.lastControlId = null;
  }
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
// Maximum length of a window: the benign-only window has its own duration.
const windowMax = (run, name) => name === BENIGN ? run.timing?.benign_only_duration || 0 : run.timing?.wartime_duration;
function eta(run) {
  const W = run.timing?.wartime_duration, P = run.timing?.peacetime_duration || 0;
  if (run.status !== "running" || !W) return null;
  const done = new Set((run.configs || []).map(c => c.name));
  const current = run.current?.name;
  const pendingNames = (run.planned_configs || []).filter(n => !done.has(n) && n !== current);
  const t = now();
  const finished = (run.configs || []).filter(c => c.started && c.finished && c.name !== BENIGN)
    .map(c => (parseTime(c.finished) - parseTime(c.started)) / 1000);
  const perConfig = finished.length ? finished.reduce((a, b) => a + b, 0) / finished.length : W + 15;
  let upper = 0, estimate = 0;
  for (const n of pendingNames) {
    upper += windowMax(run, n) + 15;
    estimate += n === BENIGN ? windowMax(run, n) + 5 : perConfig;
  }
  if (run.phase === "setup") { upper += P + W + 15; estimate += P + perConfig; }
  else if (run.phase === "peacetime") {
    const rest = Math.max(0, P - (t - parseTime(run.phase_started)) / 1000);
    upper += rest + (current ? 0 : W + 15); estimate += rest + (current ? 0 : perConfig);
  }
  if (current) {
    const windowStart = parseTime(run.current.window_started), configStart = parseTime(run.current.started);
    const CW = windowMax(run, current), windowRest = windowStart ? Math.max(0, CW - (t - windowStart) / 1000) : CW;
    upper += windowRest + 5;
    estimate += current === BENIGN ? windowRest + 5 : Math.max(windowStart ? 0 : 5, perConfig - (t - configStart) / 1000);
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
  const W = run?.current ? windowMax(run, run.current.name) : null;
  if (!fill || !run?.current?.window_started || !W) return;
  const elapsed = (now() - parseTime(run.current.window_started)) / 1000;
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
                                    : run.current?.name === BENIGN ? "benign-only window · no tunnel traffic"
                                    : isBenignOnly(run) ? "benign-only run · no tunnel traffic" : "no transfer running";
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
  const groups = configGroups(run), cols = 5 + dets.length + 1;
  $("all-count").textContent = `(${rows.filter(r => r.entry).length} of ${rows.length} finished)`;
  const head = `<tr><th>Configuration</th><th class="l">Status</th><th class="l">Ended by</th><th>Tunnel q.</th><th class="l">Net / file</th>`
    + dets.map(d => `<th><span class="swatch" style="background:${detectorColor(d)}"></span>${TF.esc(d)}</th>`).join("") + `<th class="l"></th></tr>`;
  const rowHTML = ({name, status, entry}) => {
    // The benign-only window has no tunnel traffic: show its FPR instead of F1.
    const benign = name === BENIGN, key = benign ? "fpr" : "f1";
    const f1 = new Map((entry?.detectors || []).map(d => [d.detector, d[key]]));
    const reason = entry?.reason && status !== "completed" ? ` <span class="muted">${TF.esc(entry.reason)}</span>` : "";
    return `<tr class="${run.current?.name === name ? "is-current" : ""}"><td>${TF.esc(name)}</td><td class="l">${statusHTML(status)}${reason}</td>
      <td class="l">${TF.esc(endedBy(entry))}</td><td>${entry?.dataset_statistics?.tunnel_queries ?? "–"}</td>
      <td class="l">${netVolume(entry?.dataset_statistics)}</td>
      ${dets.map(d => `<td>${f1.get(d) != null ? (benign ? `<span class="muted small">FPR</span> ${fmtFpr(f1.get(d))}` : f1.get(d).toFixed(3)) : "–"}</td>`).join("")}
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

// Finished tunnel configurations in group order, with the group boundaries (null for one
// group). The benign-only window is left out (see renderBenignRanking).
function finishedConfigs(run) {
  const finished = new Map((run.configs || []).filter(c => (c.detectors || []).length && c.name !== BENIGN).map(c => [c.name, c]));
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

// Detectors card: the wartime ranking (tunnel configurations) or, for runs with a
// benign-only window, the benign-only ranking; a benign-only run has only the latter.
function renderDetectors() {
  const run = state.run, hasB = hasBenignWindow(run), only = isBenignOnly(run);
  const mode = only ? "benign" : !hasB ? "wartime"
    : state.detMode ?? (finishedConfigs(run).configs.length ? "wartime" : "benign");
  $("det-mode").hidden = !hasB || only;
  $("det-mode").querySelectorAll("button").forEach(b => b.setAttribute("aria-pressed", b.dataset.mode === mode));
  $("rank-benign").hidden = mode !== "benign";
  $("rank-wartime").hidden = mode !== "wartime";
  $("det-sub").textContent = mode === "benign"
    ? "benign-only window · false positive rate without adversarial load, every alarm is a false positive · click a column to sort"
    : "means over the finished configurations · click a column to sort, a row to select";
  if (mode === "benign") renderBenignRanking(); else renderWartimeRanking();
}

function renderWartimeRanking() {
  const run = state.run, dets = detectors(run), {configs, sections} = finishedConfigs(run);
  const view = $("detector-view");
  if (!dets.length || !configs.length) {
    $("leaderboard").innerHTML = '<tr><td class="muted">No finished configuration yet</td></tr>';
    view.hidden = true;
    return;
  }
  view.hidden = false;
  const mean = (d, k) => meanOf(configs, d, k);
  const detected = d => configs.filter(c => (valueOf(c, d, "tp") ?? 0) > 0).length;
  const runtime = d => configs.reduce((a, c) => a + (valueOf(c, d, "runtime") || 0), 0);
  const value = (d, col) => col.key === "detected" ? detected(d) : col.key === "runtime" ? runtime(d) : mean(d, col.key);
  // Default order: least exfiltrated volume first, then the best F1 (see RANK_COLUMNS).
  const {key, dir} = state.rankSort, sortCol = RANK_COLUMNS.find(c => c.key === key) || RANK_COLUMNS[0];
  const cmp = (a, b, col, direction) => {
    const va = value(a, col), vb = value(b, col);
    if (va == null || vb == null) return (va == null) - (vb == null);   // missing values last
    return direction === "asc" ? va - vb : vb - va;
  };
  const byKey = k => RANK_COLUMNS.find(c => c.key === k);
  const ranked = [...dets].sort((a, b) => cmp(a, b, sortCol, dir) || cmp(a, b, byKey("ulv_percent"), "asc")
    || cmp(a, b, byKey("f1"), "desc") || a.localeCompare(b));
  if (!dets.includes(state.detector)) state.detector = ranked[0];
  const det = state.detector, sw = d => `<span class="swatch" style="background:${detectorColor(d)}"></span>`;
  const head = RANK_COLUMNS.map(c => {
    const active = c.key === sortCol.key, arrow = active ? (dir === "asc" ? " ▲" : " ▼") : "";
    return `<th class="${c.align || ""}" aria-sort="${active ? (dir === "asc" ? "ascending" : "descending") : "none"}">
      <button class="sort" data-sort="${c.key}" title="Sort by ${c.label}${c.lower ? " (lower is better)" : ""}">${c.label}${arrow}</button></th>`;
  }).join("");
  $("leaderboard").innerHTML = `<tr><th>#</th><th class="l">Detector</th>${head}</tr>`
    + ranked.map((d, i) => `<tr data-det="${TF.esc(d)}" class="${d === det ? "is-selected" : ""}" tabindex="0"><td>${i + 1}</td>
        <td class="l">${sw(d)}${TF.esc(d)}</td>${RANK_COLUMNS.map(c => {
          const v = value(d, c);
          const meter = c.meter ? `<span class="mini-meter" aria-hidden="true"><i style="width:${Math.min(100, Math.max(0, 100 * (v || 0) / c.meter))}%"></i></span>` : "";
          return `<td class="${c.align || ""} mono">${c.key === "detected" ? `${v} / ${configs.length}` : show(v, c.fmt)}${meter}</td>`;
        }).join("")}</tr>`).join("");
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
  const cols = ["precision", "recall", "f1", "fpr", "ulv_percent", "dlv_percent", "tp", "fp", "fn", "tn", "net_up_bytes", "traffic_volume_up_bytes", "runtime"];
  const fmts = {precision: v => v.toFixed(3), recall: v => v.toFixed(3), f1: v => v.toFixed(3), fpr: v => v.toPrecision(3),
                ulv_percent: pct, dlv_percent: pct, net_up_bytes: TF.fmtBytes, traffic_volume_up_bytes: TF.fmtBytes, runtime: v => `${v.toFixed(1)} s`};
  const groupOf = new Map((run.config_groups || []).map(g => [g.name, g.group]));
  let last = null;
  $("det-table").innerHTML = `<tr><th>Configuration</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>ULV %</th><th>DLV %</th>
      <th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Net leak</th><th>Leak up (raw)</th><th>Runtime</th></tr>`
    + configs.map(c => {
      const g = groupOf.get(c.name), head = sections && g !== last ? `<tr class="group-row"><td class="l" colspan="14">${TF.esc(g || "")}</td></tr>` : "";
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
  const run = state.run, m = state.sweepMetric, sweeps = sweepsOf(run);
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

// Benign-only ranking: window figures and each detector's false positives, next to its
// mean FPR over the finished tunnel configurations (under adversarial load). Sortable.
function renderBenignRanking() {
  const run = state.run, only = isBenignOnly(run);
  const entry = (run.configs || []).find(c => c.name === BENIGN);
  const stats = entry?.dataset_statistics || {}, live = run.current?.name === BENIGN;
  const {configs: tunnel} = finishedConfigs(run);
  const P = run.timing?.peacetime_duration || 0;
  const tunnelFpr = d => tunnel.length ? meanOf(tunnel, d, "fpr") : null;
  const rows = (entry?.detectors || []).map(r => {
    const tf = tunnelFpr(r.detector);
    return {...r, tunnel_fpr: tf, change: tf != null && r.fpr != null ? tf - r.fpr : null};
  });
  const fprs = rows.map(r => r.fpr).filter(v => v != null);
  const maxFpr = Math.max(0, ...fprs);
  const windowSec = stats.window_seconds
    ?? (live && run.current.window_started ? (now() - parseTime(run.current.window_started)) / 1000 : null);
  const kpi = (label, value, sub = "") => `<div class="mini-kpi"><div class="kpi-label">${label}</div>
    <div class="kpi-value mono">${value}</div><div class="kpi-sub ellipsis">${sub}</div></div>`;
  const meanFpr = fprs.length ? fprs.reduce((a, b) => a + b, 0) / fprs.length : null;
  const meanTunnel = rows.map(r => r.tunnel_fpr).filter(v => v != null);
  const best = [...rows].sort((a, b) => (a.fpr ?? Infinity) - (b.fpr ?? Infinity) || a.detector.localeCompare(b.detector))[0];
  const status = entry ? endedBy(entry) : live ? "running" : run.status === "running" ? "pending" : "not run";
  $("benign-kpis").innerHTML =
      kpi("Window", show(windowSec, TF.fmtDuration), TF.esc(status))
    + kpi("Queries", show(stats.total_queries, TF.fmtCompact), stats.total_queries != null && windowSec
          ? `${(stats.total_queries / windowSec).toFixed(1)} / s` : "")
    + kpi("Benign domains", show(stats.unique_domains, TF.fmtCompact), "registered domains seen")
    + kpi("Allowlist", P > 0 ? "peacetime" : "global only", P > 0 ? `learned over ${TF.fmtDuration(P)}` : "no peacetime")
    + kpi("Lowest FPR", best ? fmtFpr(best.fpr ?? 0) : "–", best ? TF.esc(best.detector) : "")
    + kpi("Mean FPR", show(meanFpr, fmtFpr), meanTunnel.length
          ? `with tunnel ${fmtFpr(meanTunnel.reduce((a, b) => a + b, 0) / meanTunnel.length)}`
          : rows.length ? `over ${rows.length} detector${rows.length === 1 ? "" : "s"}` : "");
  const notes = [];
  if (!entry) notes.push(live ? "The window is running; the false positives per detector appear when it ends."
    : run.status === "running" ? "The benign-only window runs after peacetime, before the tunnel windows."
    : `No results for this window${run.status_reason ? `: ${run.status_reason}` : "."}`);
  else if (entry.status !== "completed")
    notes.push(`Window ${entry.status}${entry.reason ? `: ${entry.reason}` : ""}. The figures cover the partial window.`);
  if (stats.tunnel_queries > 0)
    notes.push(`${stats.tunnel_queries} queries to tunneling domains were seen in this window; they count as tunnel traffic, not as false positives.`);
  $("benign-note").hidden = !notes.length;
  $("benign-note").className = `note${stats.tunnel_queries > 0 || entry?.status === "failed" ? " warn" : ""}`;
  $("benign-note").textContent = notes.join(" ");
  if (!rows.length) { $("benign-table").innerHTML = ""; return; }

  const cols = BENIGN_COLUMNS.filter(c => !c.tunnel || !only);
  const {key, dir} = state.benignSort, sortCol = cols.find(c => c.key === key) || cols[0];
  const cmp = (a, b, k, direction) => {
    const va = a[k], vb = b[k];
    if (va == null || vb == null) return (va == null) - (vb == null);   // missing values last
    return direction === "asc" ? va - vb : vb - va;
  };
  rows.sort((a, b) => cmp(a, b, sortCol.key, dir) || cmp(a, b, "fpr", "asc") || a.detector.localeCompare(b.detector));
  const sw = d => `<span class="swatch" style="background:${detectorColor(d)}"></span>`;
  const file = `/runs/${encodeURIComponent(state.runId)}/${TF.esc(entry.file)}`;
  const head = cols.map(c => {
    const active = c.key === sortCol.key, arrow = active ? (dir === "asc" ? " ▲" : " ▼") : "";
    return `<th aria-sort="${active ? (dir === "asc" ? "ascending" : "descending") : "none"}">
      <button class="sort" data-bsort="${c.key}" title="${TF.esc(c.title || `Sort by ${c.label}`)}${c.lower ? " (lower is better)" : ""}">${c.label}${arrow}</button></th>`;
  }).join("");
  $("benign-table").innerHTML = `<tr><th>#</th><th class="l">Detector</th>${head}<th class="l">False alarms</th></tr>`
    + rows.map((r, i) => {
      const sample = r.false_positives_sample || [], more = (r.fp || 0) - sample.length;
      const list = r.fp ? `${TF.esc(sample.join(", "))}${more > 0 ? ` <a href="${file}" target="_blank" rel="noopener">+${more} more</a>` : ""}`
                        : '<span class="muted">none</span>';
      const cells = cols.map(c => {
        const meter = c.meter ? `<span class="mini-meter" aria-hidden="true"><i style="width:${maxFpr ? 100 * (r.fpr || 0) / maxFpr : 0}%"></i></span>` : "";
        return `<td class="mono">${show(r[c.key], c.fmt)}${meter}</td>`;
      }).join("");
      return `<tr><td>${i + 1}</td><td class="l">${sw(r.detector)}${TF.esc(r.detector)}</td>${cells}<td class="fp-list">${list}</td></tr>`;
    }).join("");
}

// A benign-only run has no tunnel windows: hide the views that only tunnel traffic fills.
function renderTunnelCards() {
  const only = isBenignOnly(state.run);
  for (const id of ["results-card", "heat-card", "configrank-card", "tradeoff-card", "sweeps-card"]) $(id).hidden = only;
}

// Configuration ranking: which finished tunnel configuration exfiltrated the most data
// across all detectors (mean and minimum ULV %, net leak, how many detectors caught it).
function renderConfigRanking() {
  const run = state.run, {configs} = finishedConfigs(run), dets = detectors(run);
  if (!configs.length) { $("config-rank").innerHTML = '<tr><td class="muted">No finished configuration yet</td></tr>'; return; }
  const groupOf = new Map((run.config_groups || []).map(g => [g.name, g]));
  const mean = v => v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
  const rows = configs.map(c => {
    const vals = k => dets.map(d => valueOf(c, d, k)).filter(v => v != null);
    const ulv = vals("ulv_percent"), stats = c.dataset_statistics || {};
    const ran = c.detectors.length;
    return {name: c.name, entry: c, group: groupOf.get(c.name),
            mean_ulv: mean(ulv), min_ulv: ulv.length ? Math.min(...ulv) : null, mean_net: mean(vals("net_up_bytes")),
            file: stats.exfil_file_bytes ?? stats.exfil_file_bytes_server ?? null,
            detected: c.detectors.filter(d => (d.tp ?? 0) > 0).length, ran, mean_f1: mean(vals("f1")),
            tunnel_queries: stats.tunnel_queries ?? null,
            duration: c.started && c.finished ? (parseTime(c.finished) - parseTime(c.started)) / 1000 : null};
  });
  const {key, dir} = state.configSort, sortCol = CONFIG_COLUMNS.find(c => c.key === key) || CONFIG_COLUMNS[0];
  const cmp = (a, b, k, direction) => {
    const va = a[k], vb = b[k];
    if (va == null || vb == null) return (va == null) - (vb == null);   // missing values last
    return direction === "asc" ? va - vb : vb - va;
  };
  rows.sort((a, b) => cmp(a, b, sortCol.key, dir) || cmp(a, b, "mean_ulv", "desc") || cmp(a, b, "mean_net", "desc")
    || a.name.localeCompare(b.name));
  const head = CONFIG_COLUMNS.map(c => {
    const active = c.key === sortCol.key, arrow = active ? (dir === "asc" ? " ▲" : " ▼") : "";
    return `<th aria-sort="${active ? (dir === "asc" ? "ascending" : "descending") : "none"}">
      <button class="sort" data-csort="${c.key}" title="${TF.esc(c.title || `Sort by ${c.label}`)}">${c.label}${arrow}</button></th>`;
  }).join("");
  $("config-rank").innerHTML = `<tr><th>#</th><th class="l">Configuration</th>${head}<th class="l">Ended by</th></tr>`
    + rows.map((r, i) => {
      const cells = CONFIG_COLUMNS.map(c => {
        const v = r[c.key];
        const text = c.key === "detected" ? `${v} / ${r.ran}` : show(v, c.fmt);
        const meter = c.meter ? `<span class="mini-meter" aria-hidden="true"><i style="width:${Math.min(100, Math.max(0, 100 * (v || 0) / c.meter))}%"></i></span>` : "";
        return `<td class="mono">${text}${meter}</td>`;
      }).join("");
      const group = r.group && r.group.group !== r.name ? ` <span class="muted small">${TF.esc(r.group.group)}</span>` : "";
      return `<tr><td>${i + 1}</td><td class="l">${TF.esc(r.name)}${group}</td>${cells}<td class="l">${TF.esc(endedBy(r.entry))}</td></tr>`;
    }).join("");
}

function renderLog() {
  const el = $("log");
  const raw = state.log.text[state.log.tab]
    || (state.log.tab === "run" ? "No log lines yet."
        : state.run?.status === "running" ? "No output from this tool in this run yet." : "No output from this tool in this run.");
  if (el.dataset.raw === raw) return;
  el.dataset.raw = raw;
  el.innerHTML = TF.ansiToHtml(raw);  // render the tools' ANSI colours
  if ($("follow").checked) el.scrollTop = el.scrollHeight;
}

function renderAll() {
  if (!state.run) return;
  renderTop(); renderKPIs(); renderTimes(); renderCurrent(); renderTunnelCards();
  renderTraffic(); renderResources(); renderResults(); renderBreakdown();
  renderHeat(); renderDetectors(); renderConfigRanking(); renderTradeoff(); renderSweeps(); renderRecords();
}

function renderEmpty() {
  $("k-status").textContent = "No runs";
  $("current").innerHTML = '<div class="muted">Start an experiment with <code>python3 main.py</code>.</div>';
  for (const id of ["chart-dns", "chart-cpu", "chart-mem", "chart-results", "chart-heat", "chart-tradeoff", "chart-sweep",
                    "chart-qtypes", "chart-atypes", "chart-qlen", "chart-entropy"]) TF.empty($(id), "No data yet");
  $("detector-view").hidden = true;
  $("det-mode").hidden = true;
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
metricButtons("metric-buttons", "metric", renderResults);
metricButtons("sweep-metric-buttons", "sweepMetric", renderSweeps);
metricButtons("heat-buttons", "heatMetric", renderHeat);
function selectDetector(ev) {
  const el = ev.target.closest("[data-det]"); if (!el) return;
  state.detector = el.dataset.det;
  if (state.run) renderDetectors();
}
$("det-buttons").addEventListener("click", selectDetector);
$("leaderboard").addEventListener("click", ev => {
  const sort = ev.target.closest("button.sort");
  if (sort) {
    const col = RANK_COLUMNS.find(c => c.key === sort.dataset.sort), same = state.rankSort.key === col.key;
    state.rankSort = {key: col.key, dir: same ? (state.rankSort.dir === "asc" ? "desc" : "asc")
                                               : (col.lower ? "asc" : "desc")};
    if (state.run) renderDetectors();
    return;
  }
  selectDetector(ev);
});
$("config-rank").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-csort]"); if (!b) return;
  const col = CONFIG_COLUMNS.find(c => c.key === b.dataset.csort), same = state.configSort.key === col.key;
  state.configSort = {key: col.key, dir: same ? (state.configSort.dir === "asc" ? "desc" : "asc") : col.evasive};
  if (state.run) renderConfigRanking();
});
$("det-mode").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-mode]"); if (!b) return;
  state.detMode = b.dataset.mode;
  if (state.run) renderDetectors();
});
$("benign-table").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-bsort]"); if (!b) return;
  const col = BENIGN_COLUMNS.find(c => c.key === b.dataset.bsort), same = state.benignSort.key === col.key;
  state.benignSort = {key: col.key, dir: same ? (state.benignSort.dir === "asc" ? "desc" : "asc") : (col.lower ? "asc" : "desc")};
  if (state.run) renderDetectors();
});
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
$("run-select").addEventListener("change", ev => {
  state.runId = ev.target.value; state.lastControlId = null;
  state.followLatest = state.runId === state.runs[0]?.id;   // picking the newest run follows new runs again
  tick();
});

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
