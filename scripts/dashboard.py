"""Local dashboard for TunFrame runs: live status, charts and log.

Serves the run directories written by ``main.py`` (see ``detection/reporting.py``)
on http://127.0.0.1:8050 and polls them, so a running experiment updates live.
Read-only; it never writes to the results directory.

Usage:
    python3 scripts/dashboard.py [--results DIR] [--port 8050]

Without ``--results`` the directory comes from ``output.logdir`` in
``config.yaml`` (default ``results``), as in ``main.py``.
"""
import argparse
import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_CHUNK = 64 * 1024


def default_results_dir() -> Path:
    """Resolve ``output.logdir`` from config.yaml the same way main.py does."""
    config_path = PROJECT_ROOT / "config.yaml"
    logdir = "results"
    if config_path.exists():
        try:
            import yaml
            cfg = yaml.safe_load(config_path.read_text()) or {}
            logdir = (cfg.get("output") or {}).get("logdir") or "results"
        except Exception:
            pass
    path = Path(logdir)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def read_run(run_dir: Path):
    try:
        return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_runs(results_dir: Path) -> list:
    runs = []
    if not results_dir.is_dir():
        return runs
    for run_dir in results_dir.iterdir():
        state = read_run(run_dir) if run_dir.is_dir() else None
        if state is None:
            continue
        runs.append({
            "id": run_dir.name,
            "name": state.get("name"),
            "status": state.get("status"),
            "phase": state.get("phase"),
            "started": state.get("started"),
            "updated": state.get("updated"),
            "configs": len(state.get("configs", [])),
            "planned": len(state.get("planned_configs", [])),
        })
    runs.sort(key=lambda r: r.get("started") or "", reverse=True)
    return runs


class DashboardHandler(BaseHTTPRequestHandler):
    results_dir: Path = None

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _send(self, status, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=HTTPStatus.OK):
        self._send(status, json.dumps(data, default=str).encode(), "application/json")

    def _not_found(self):
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _run_dir(self, run_id: str):
        run_dir = (self.results_dir / run_id).resolve()
        if run_dir.parent != self.results_dir.resolve() or not (run_dir / "run.json").exists():
            return None
        return run_dir

    def do_GET(self):
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        if not parts:
            return self._send(HTTPStatus.OK, PAGE.encode(), "text/html; charset=utf-8")
        if parts == ["api", "runs"]:
            return self._json(list_runs(self.results_dir))
        if len(parts) >= 3 and parts[:2] == ["api", "run"]:
            run_dir = self._run_dir(parts[2])
            if run_dir is None:
                return self._not_found()
            if len(parts) == 3:
                state = read_run(run_dir) or {}
                state["has_report"] = (run_dir / "report.html").exists()
                return self._json(state)
            if len(parts) == 4 and parts[3] == "log":
                return self._log(run_dir, parse_qs(url.query))
            return self._not_found()
        if len(parts) >= 3 and parts[0] == "runs":
            return self._static(parts[1], parts[2:])
        return self._not_found()

    def _log(self, run_dir: Path, query):
        log_path = run_dir / "run.log"
        size = log_path.stat().st_size if log_path.exists() else 0
        try:
            offset = int(query.get("offset", ["-1"])[0])
        except ValueError:
            offset = -1
        if offset < 0 or offset > size:
            offset = max(0, size - LOG_CHUNK)
        end = min(size, offset + LOG_CHUNK)
        text = ""
        if end > offset:
            with open(log_path, "rb") as f:
                f.seek(offset)
                text = f.read(end - offset).decode("utf-8", errors="replace")
        return self._json({"offset": end, "size": size, "text": text})

    def _static(self, run_id: str, rel_parts: list):
        run_dir = self._run_dir(run_id)
        if run_dir is None:
            return self._not_found()
        path = run_dir.joinpath(*rel_parts).resolve()
        if run_dir not in path.parents or not path.is_file():
            return self._not_found()
        types = {".html": "text/html; charset=utf-8", ".json": "application/json",
                 ".png": "image/png", ".log": "text/plain; charset=utf-8"}
        content_type = types.get(path.suffix)
        if content_type is None:
            return self._not_found()
        return self._send(HTTPStatus.OK, path.read_bytes(), content_type)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TunFrame Dashboard</title>
<style>
:root {
  color-scheme: light;
  --plane:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --baseline:#c3c2b7; --ring:rgba(11,11,11,0.10);
  --good:#006300; --warning:#8a5a00; --critical:#d03b3b;
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100; --s5:#e87ba4; --s6:#008300; --s7:#6250d6; --s8:#e34948;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --plane:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --baseline:#383835; --ring:rgba(255,255,255,0.10);
    --good:#0ca30c; --warning:#fab219; --critical:#e66767;
    --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --s5:#d55181; --s6:#0ca30c; --s7:#9085e9; --s8:#e66767;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --plane:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --baseline:#383835; --ring:rgba(255,255,255,0.10);
  --good:#0ca30c; --warning:#fab219; --critical:#e66767;
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --s5:#d55181; --s6:#0ca30c; --s7:#9085e9; --s8:#e66767;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--plane); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
header { display:flex; flex-wrap:wrap; gap:12px; align-items:center; padding:12px 16px; border-bottom:1px solid var(--ring); background:var(--surface); }
header h1 { font-size:16px; margin:0; flex:1 1 auto; }
header label { min-width:0; max-width:100%; display:flex; gap:6px; align-items:center; }
select { max-width:100%; min-width:0; }
select, button { font:inherit; color:var(--ink); background:var(--surface); border:1px solid var(--ring); border-radius:6px; padding:4px 8px; }
button[aria-pressed="true"] { background:var(--ink); color:var(--surface); }
main { max-width:1200px; margin:0 auto; padding:16px; display:grid; gap:16px; grid-template-columns:minmax(0,1fr); }
.card { background:var(--surface); border:1px solid var(--ring); border-radius:8px; padding:16px; min-width:0; }
.card h2 { font-size:14px; margin:0 0 12px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.card h2 .spacer { flex:1; }
.overview { display:flex; flex-wrap:wrap; gap:8px 32px; align-items:baseline; }
.overview .name { font-size:20px; font-weight:600; }
.muted { color:var(--ink-2); }
.progress { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--ink-2); min-height:18px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.badge { font-weight:600; }
.st-completed { color:var(--good); } .st-running { color:var(--ink); }
.st-skipped, .st-failed, .st-interrupted { color:var(--critical); } .st-pending, .st-not-run { color:var(--muted); }
.live-dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--good); margin-right:4px; animation:pulse 1.5s infinite; }
@keyframes pulse { 50% { opacity:.3; } }
@media (prefers-reduced-motion: reduce) { .live-dot { animation:none; } }
.table-wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }
th, td { padding:4px 8px; border-bottom:1px solid var(--grid); text-align:right; white-space:nowrap; }
th:first-child, td:first-child, .l { text-align:left; }
th { color:var(--ink-2); font-weight:600; }
.chart { position:relative; width:100%; }
.chart svg { display:block; width:100%; overflow:visible; }
.chart text { fill:var(--ink-2); font-size:11px; }
.legend { display:flex; flex-wrap:wrap; gap:4px 16px; margin:0 0 8px; color:var(--ink-2); font-size:12px; }
.swatch { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; vertical-align:-1px; }
.tooltip { position:absolute; pointer-events:none; background:var(--surface); color:var(--ink); border:1px solid var(--ring);
  border-radius:6px; padding:6px 8px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,.12); white-space:nowrap; display:none; z-index:2; }
pre.log { margin:0; max-height:420px; overflow:auto; font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--ink-2); white-space:pre-wrap; overflow-wrap:anywhere; }
.empty { color:var(--muted); }
a { color:var(--s1); }
</style>
</head>
<body>
<header>
  <h1>TunFrame Dashboard</h1>
  <label class="muted">Run <select id="run-select" aria-label="Run"></select></label>
  <span id="report-link"></span>
</header>
<main>
  <section class="card" aria-live="polite">
    <div class="overview">
      <span class="name" id="run-name">No runs yet</span>
      <span id="run-status" class="badge"></span>
      <span id="run-phase" class="muted"></span>
      <span id="run-times" class="muted"></span>
    </div>
    <div class="progress" id="run-progress"></div>
  </section>

  <section class="card">
    <h2>Configurations</h2>
    <div class="table-wrap"><table id="config-table"></table></div>
  </section>

  <section class="card">
    <h2>
      <span id="chart-title">Results by configuration</span><span class="spacer"></span>
      <span role="group" aria-label="Metric" id="metric-buttons"></span>
      <button id="table-toggle" aria-pressed="false">Table</button>
    </h2>
    <div class="legend" id="legend"></div>
    <div class="chart" id="chart"><div class="tooltip" id="tooltip"></div></div>
    <div class="table-wrap" id="chart-table" hidden></div>
  </section>

  <section class="card">
    <h2>Log <span class="spacer"></span><label class="muted"><input type="checkbox" id="follow" checked> Follow</label></h2>
    <pre class="log" id="log"></pre>
  </section>
</main>
<script>
const METRICS = [
  {key:"f1", label:"F1", max:1, fmt:v => v.toFixed(3)},
  {key:"precision", label:"Precision", max:1, fmt:v => v.toFixed(3)},
  {key:"recall", label:"Recall", max:1, fmt:v => v.toFixed(3)},
  {key:"fpr", label:"FPR", fmt:v => v.toPrecision(3)},
  {key:"traffic_volume_up_bytes", label:"Leak up", fmt:fmtBytes},
];
const state = {runs:[], runId:null, run:null, metric:METRICS[0], logOffset:-1, logRun:null, showTable:false, timer:null};
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function fmtBytes(v) {
  v = Number(v || 0);
  for (const unit of ["B","KB","MB","GB"]) {
    if (Math.abs(v) < 1000) return unit === "B" ? `${v.toFixed(0)} B` : `${v.toFixed(1)} ${unit}`;
    v /= 1000;
  }
  return `${v.toFixed(1)} TB`;
}
function statusLabel(status) {
  const icon = {completed:"✓", running:"", skipped:"⊘", failed:"✕", interrupted:"■", pending:"○", "not-run":"–"}[status] ?? "•";
  const dot = status === "running" ? '<span class="live-dot" aria-hidden="true"></span>' : "";
  return `<span class="badge st-${esc(status)}">${dot}${icon} ${esc(status.replace("-", " "))}</span>`;
}
async function getJSON(url) {
  const res = await fetch(url, {cache:"no-store"});
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}
function detectors(run) {
  const names = new Set();
  for (const c of run.configs || []) for (const d of c.detectors || []) names.add(d.detector);
  return [...names].sort();
}
const color = i => i < 8 ? `var(--s${i + 1})` : "var(--muted)";

async function loadRuns() {
  state.runs = await getJSON("/api/runs");
  const select = $("run-select");
  const current = state.runId;
  select.innerHTML = state.runs.map(r =>
    `<option value="${esc(r.id)}">${esc(r.name)} · ${esc(r.started)} · ${esc(r.status)}</option>`).join("");
  if (!state.runs.length) { state.runId = null; return; }
  if (!current || !state.runs.some(r => r.id === current)) state.runId = state.runs[0].id;
  select.value = state.runId;
}

async function loadRun() {
  if (!state.runId) { renderEmpty(); return; }
  state.run = await getJSON(`/api/run/${encodeURIComponent(state.runId)}`);
  renderOverview(); renderConfigs(); renderChart();
  await loadLog();
}

function renderEmpty() {
  $("run-name").textContent = "No runs yet";
  for (const id of ["run-status","run-phase","run-times","run-progress","legend","report-link"]) $(id).innerHTML = "";
  $("config-table").innerHTML = '<tr><td class="empty">Start an experiment with python3 main.py</td></tr>';
}

function renderOverview() {
  const r = state.run;
  $("run-name").textContent = r.name || state.runId;
  $("run-status").innerHTML = statusLabel(r.status || "running") + (r.status_reason ? ` <span class="muted">${esc(r.status_reason)}</span>` : "");
  $("run-phase").textContent = r.status === "running" ? `Phase: ${r.phase}${r.phase_detail ? " · " + r.phase_detail : ""}` : "";
  $("run-times").textContent = `Started ${r.started}` + (r.finished ? ` · finished ${r.finished}` : ` · updated ${r.updated}`);
  $("run-progress").textContent = r.progress || "";
  $("report-link").innerHTML = r.has_report ? `<a href="/runs/${encodeURIComponent(state.runId)}/report.html" target="_blank" rel="noopener">Static report</a>` : "";
}

function configRows(r) {
  const byName = new Map((r.configs || []).map(c => [c.name, c]));
  const names = [...(r.planned_configs || [])];
  for (const c of r.configs || []) if (!names.includes(c.name)) names.push(c.name);
  return names.map(name => {
    const entry = byName.get(name);
    let status = entry ? entry.status
      : (r.status === "running" && r.phase === "wartime" && (r.phase_detail === name || (!r.phase_detail && name === "wartime"))) ? "running"
      : r.status === "running" ? "pending" : "not-run";
    return {name, status, entry};
  });
}

function renderConfigs() {
  const r = state.run, dets = detectors(r);
  const head = `<tr><th>Configuration</th><th class="l">Status</th><th>Log lines</th><th>Tunnel queries</th>`
    + dets.map((d, i) => `<th><span class="swatch" style="background:${color(i)}"></span>${esc(d)} F1</th>`).join("") + `<th class="l">Details</th></tr>`;
  const rows = configRows(r).map(({name, status, entry}) => {
    const stats = entry?.dataset_statistics || {};
    const f1 = new Map((entry?.detectors || []).map(d => [d.detector, d.f1]));
    const cells = dets.map(d => `<td>${f1.has(d) && f1.get(d) != null ? f1.get(d).toFixed(3) : "–"}</td>`).join("");
    const link = entry ? `<a href="/runs/${encodeURIComponent(state.runId)}/${esc(entry.file)}" target="_blank" rel="noopener">json</a>` : "";
    const reason = entry?.reason && status !== "completed" ? ` <span class="muted">${esc(entry.reason)}</span>` : "";
    return `<tr><td>${esc(name)}</td><td class="l">${statusLabel(status)}${reason}</td><td>${stats.total_loglines ?? "–"}</td>`
      + `<td>${stats.tunnel_queries ?? "–"}</td>${cells}<td class="l">${link}</td></tr>`;
  }).join("");
  $("config-table").innerHTML = head + (rows || '<tr><td class="empty">No configurations yet</td></tr>');
}

function niceTicks(max) {
  if (max <= 0) return [0, 1];
  const step0 = max / 4, mag = 10 ** Math.floor(Math.log10(step0));
  const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= step0);
  const ticks = [];
  for (let v = 0; v <= max + step * 1e-9; v += step) ticks.push(+v.toPrecision(12));
  if (ticks[ticks.length - 1] < max) ticks.push(+(ticks[ticks.length - 1] + step).toPrecision(12));
  return ticks;
}

function renderChart() {
  const r = state.run, m = state.metric, dets = detectors(r);
  const configs = (r.configs || []).filter(c => (c.detectors || []).length);
  $("chart-title").textContent = `${m.label} by configuration`;
  $("legend").innerHTML = dets.length > 1 ? dets.map((d, i) => `<span><span class="swatch" style="background:${color(i)}"></span>${esc(d)}</span>`).join("") : "";
  const chart = $("chart"), tooltip = $("tooltip");
  chart.querySelector("svg")?.remove();
  renderChartTable(configs, dets, m);
  if (!configs.length) { chart.insertAdjacentHTML("afterbegin", '<svg height="40"><text x="0" y="24">No finished configuration yet</text></svg>'); return; }

  const width = Math.max(chart.clientWidth, 280), height = 280;
  const pad = {l:56, r:8, t:8, b:configs.some(c => c.name.length > 12) ? 96 : 28};
  const values = configs.flatMap(c => c.detectors.map(d => Number(d[m.key] || 0)));
  const ticks = m.max ? [0, 0.2, 0.4, 0.6, 0.8, 1] : niceTicks(Math.max(...values, 0));
  const yMax = ticks[ticks.length - 1] || 1;
  const plotW = width - pad.l - pad.r, plotH = height - pad.t - pad.b;
  const groupW = plotW / configs.length;
  const barW = Math.max(2, Math.min(24, (groupW * 0.8) / Math.max(dets.length, 1) - 2));
  const y = v => pad.t + plotH - (v / yMax) * plotH;
  let svg = `<svg viewBox="0 0 ${width} ${height}" height="${height}" role="img" aria-label="${esc(m.label)} by configuration">`;
  for (const t of ticks) {
    svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${y(t)}" y2="${y(t)}" stroke="var(--grid)" stroke-width="1"/>`;
    svg += `<text x="${pad.l - 6}" y="${y(t) + 4}" text-anchor="end">${esc(m.max ? t.toFixed(1) : m.fmt(t))}</text>`;
  }
  svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${y(0)}" y2="${y(0)}" stroke="var(--baseline)" stroke-width="1"/>`;
  configs.forEach((c, gi) => {
    const cx = pad.l + groupW * (gi + 0.5);
    const total = dets.length * (barW + 2) - 2;
    dets.forEach((d, di) => {
      const row = c.detectors.find(x => x.detector === d);
      const v = row ? Number(row[m.key] || 0) : 0;
      const x0 = cx - total / 2 + di * (barW + 2), top = y(v), base = y(0), h = base - top, rad = Math.min(4, h, barW / 2);
      const label = `${c.name} · ${d}: ${row ? m.fmt(v) : "no result"}`;
      if (h > 0.5) {
        svg += `<path d="M${x0},${base} V${top + rad} Q${x0},${top} ${x0 + rad},${top} H${x0 + barW - rad} Q${x0 + barW},${top} ${x0 + barW},${top + rad} V${base} Z" fill="${color(di)}"/>`;
      }
      svg += `<rect x="${x0 - 1}" y="${pad.t}" width="${barW + 2}" height="${plotH}" fill="transparent" data-tip="${esc(label)}"/>`;
    });
    const name = c.name.length > 24 ? c.name.slice(0, 23) + "…" : c.name;
    svg += pad.b > 28
      ? `<text transform="translate(${cx},${y(0) + 14}) rotate(-30)" text-anchor="end">${esc(name)}</text>`
      : `<text x="${cx}" y="${y(0) + 18}" text-anchor="middle">${esc(name)}</text>`;
  });
  svg += "</svg>";
  chart.insertAdjacentHTML("afterbegin", svg);
  chart.querySelectorAll("[data-tip]").forEach(el => {
    el.addEventListener("mousemove", ev => {
      const box = chart.getBoundingClientRect();
      tooltip.textContent = el.dataset.tip;
      tooltip.style.display = "block";
      const left = Math.min(ev.clientX - box.left + 12, box.width - tooltip.offsetWidth - 4);
      tooltip.style.left = `${Math.max(0, left)}px`;
      tooltip.style.top = `${ev.clientY - box.top - 36}px`;
    });
    el.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
  });
}

function renderChartTable(configs, dets, m) {
  const head = `<tr><th>Configuration</th>${dets.map(d => `<th>${esc(d)}</th>`).join("")}</tr>`;
  const rows = configs.map(c => `<tr><td>${esc(c.name)}</td>${dets.map(d => {
    const row = c.detectors.find(x => x.detector === d);
    return `<td>${row ? m.fmt(Number(row[m.key] || 0)) : "–"}</td>`;
  }).join("")}</tr>`).join("");
  $("chart-table").innerHTML = `<table>${head}${rows}</table>`;
}

async function loadLog() {
  if (state.logRun !== state.runId) { state.logRun = state.runId; state.logOffset = -1; $("log").textContent = ""; }
  for (let i = 0; i < 20; i++) {
    const chunk = await getJSON(`/api/run/${encodeURIComponent(state.runId)}/log?offset=${state.logOffset}`);
    state.logOffset = chunk.offset;
    if (chunk.text) appendLog(chunk.text);
    if (chunk.offset >= chunk.size) break;
  }
}
function appendLog(text) {
  const el = $("log");
  const lines = (el.textContent + text).split("\n");
  el.textContent = lines.slice(-3000).join("\n");
  if ($("follow").checked) el.scrollTop = el.scrollHeight;
}

async function tick() {
  clearTimeout(state.timer);
  try { await loadRuns(); await loadRun(); } catch (e) { $("run-progress").textContent = `Dashboard: ${e.message}`; }
  state.timer = setTimeout(tick, state.run?.status === "running" ? 2000 : 8000);
}

$("metric-buttons").innerHTML = METRICS.map((m, i) => `<button data-i="${i}" aria-pressed="${i === 0}">${m.label}</button>`).join(" ");
$("metric-buttons").addEventListener("click", ev => {
  const b = ev.target.closest("button"); if (!b) return;
  state.metric = METRICS[+b.dataset.i];
  $("metric-buttons").querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b));
  if (state.run) renderChart();
});
$("table-toggle").addEventListener("click", () => {
  state.showTable = !state.showTable;
  $("table-toggle").setAttribute("aria-pressed", state.showTable);
  $("chart-table").hidden = !state.showTable;
});
$("run-select").addEventListener("change", ev => { state.runId = ev.target.value; tick(); });
let lastWidth = 0;
new ResizeObserver(([entry]) => {
  const w = Math.round(entry.contentRect.width);
  if (w !== lastWidth) { lastWidth = w; if (state.run) renderChart(); }
}).observe($("chart"));
tick();
</script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the TunFrame dashboard on localhost.")
    parser.add_argument("--results", type=Path, default=None, help="results directory (default: output.logdir)")
    parser.add_argument("--port", type=int, default=8050)
    args = parser.parse_args()
    DashboardHandler.results_dir = (args.results or default_results_dir()).resolve()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"TunFrame dashboard: http://127.0.0.1:{args.port}  (results: {DashboardHandler.results_dir})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
