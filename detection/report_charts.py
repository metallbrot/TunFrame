"""Static charts and report.html for one run directory.

Reads ``run.json`` (see ``detection/reporting.py``) and writes:

- ``charts/f1_by_config.png``, ``charts/fpr_by_config.png``,
  ``charts/leakage_up_by_config.png``: one group of bars per configuration,
  one bar per detector.
- ``charts/sweep_<name>.png``: F1 over the swept parameter values, one line per
  detector, for every sweep in ``dnsexfiltrator.sweeps``.
- ``report.html``: run overview, the tables behind every chart, and the charts.

Colors follow the detector, not its rank: detectors take the categorical slots
in sorted name order, the same order the dashboard uses.

Usable on its own to (re)build a report: ``python -m detection.report_charts <run_dir>``.
"""
import html
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger('dns_detector')

# Categorical slots (validated reference palette, light mode), fixed order.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"


def detector_order(state: dict) -> list:
    """Detectors of the run in the order that assigns their colors."""
    names = {row["detector"] for c in state.get("configs", []) for row in c.get("detectors", [])}
    return sorted(names)


def _completed(state: dict) -> list:
    return [c for c in state.get("configs", []) if c.get("detectors")]


def _value(config: dict, detector: str, key: str):
    for row in config.get("detectors", []):
        if row["detector"] == detector:
            return row.get(key)
    return None


def fmt_bytes(value) -> str:
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1000:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def _style_axes(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE)
    ax.tick_params(colors=MUTED, labelcolor=INK_2, length=0)
    ax.yaxis.grid(True, color=GRID, linewidth=1)
    ax.set_axisbelow(True)


def _legend(ax, ncol: int) -> None:
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.02), ncol=min(ncol, 4), frameon=False,
              labelcolor=INK_2, handlelength=1.0, fontsize=9)


def _grouped_bars(plt, configs, detectors, key, title, path, y_formatter=None, ylim=None) -> None:
    import numpy as np

    n_cfg, n_det = len(configs), len(detectors)
    fig_w = max(6.0, min(18.0, 1.2 + n_cfg * (0.25 * n_det + 0.5)))
    fig, ax = plt.subplots(figsize=(fig_w, 3.6), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    _style_axes(ax)
    group = 0.8
    width = min(group / max(n_det, 1), 0.22)
    x = np.arange(n_cfg)
    for i, det in enumerate(detectors):
        values = [(_value(c, det, key) or 0) for c in configs]
        offset = (i - (n_det - 1) / 2) * width
        ax.bar(x + offset, values, width=width * 0.88, color=SERIES[i], label=det,
               edgecolor=SURFACE, linewidth=0)
    labels = [c["name"] for c in configs]
    # Rotate as soon as the labels would not fit side by side under their group.
    rotate = n_cfg > 1 and max(len(label) for label in labels) * 0.075 > fig_w / n_cfg
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30 if rotate else 0, ha="right" if rotate else "center",
                       rotation_mode="anchor" if rotate else "default", fontsize=9)
    if ylim:
        ax.set_ylim(*ylim)
    if y_formatter:
        ax.yaxis.set_major_formatter(y_formatter)
    ax.set_title(title, loc="left", color=INK, fontsize=11, pad=28 if n_det > 1 else 8)
    if n_det > 1:
        _legend(ax, n_det)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def _sweep_chart(plt, sweep, configs_by_name, detectors, path) -> bool:
    name, parameter = sweep.get("name", "unnamed_sweep"), sweep.get("parameter", "")
    points = []
    for value in sweep.get("values", []):
        config = configs_by_name.get(f"{name}_{parameter}_{value}")
        if config and config.get("detectors"):
            points.append((value, config))
    if len(points) < 2:
        return False
    numeric = all(isinstance(v, (int, float)) and not isinstance(v, bool) for v, _ in points)
    xs = [v for v, _ in points] if numeric else list(range(len(points)))
    fig, ax = plt.subplots(figsize=(6.5, 3.6), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    _style_axes(ax)
    for i, det in enumerate(detectors):
        ys = [_value(c, det, "f1") for _, c in points]
        ax.plot(xs, ys, color=SERIES[i], linewidth=2, marker="o", markersize=6,
                markeredgecolor=SURFACE, markeredgewidth=1.5, label=det)
    if not numeric:
        ax.set_xticks(xs)
        ax.set_xticklabels([str(v) for v, _ in points], fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel(parameter, color=INK_2, fontsize=9)
    ax.set_title(f"F1 over {parameter} (sweep {name})", loc="left", color=INK, fontsize=11,
                 pad=28 if len(detectors) > 1 else 8)
    if len(detectors) > 1:
        _legend(ax, len(detectors))
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return True


def render_charts(run_dir: Path, state: dict) -> list:
    """Write the PNG charts of a run; return their paths relative to ``run_dir``."""
    configs = _completed(state)
    detectors = detector_order(state)[:len(SERIES)]
    if not configs or not detectors:
        return []
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter
    except ImportError:
        logger.warning("[!] matplotlib is not installed; report.html is written without charts")
        return []

    charts_dir = run_dir / "charts"
    charts_dir.mkdir(exist_ok=True)
    plt.rcParams.update({"font.family": "sans-serif", "font.size": 9})
    written = []

    def bars(name, key, title, **kw):
        path = charts_dir / name
        _grouped_bars(plt, configs, detectors, key, title, path, **kw)
        written.append(f"charts/{name}")

    bars("f1_by_config.png", "f1", "F1 score by configuration", ylim=(0, 1.05))
    bars("fpr_by_config.png", "fpr", "False positive rate by configuration")
    bars("leakage_up_by_config.png", "traffic_volume_up_bytes",
         "Uplink leakage until first alarm by configuration",
         y_formatter=FuncFormatter(lambda v, _: fmt_bytes(v)))

    by_name = {c["name"]: c for c in configs}
    sweeps = ((state.get("complete_config") or {}).get("dnsexfiltrator") or {}).get("sweeps") or []
    for sweep in sweeps:
        name = f"sweep_{sweep.get('name', 'unnamed')}.png"
        if _sweep_chart(plt, sweep, by_name, detectors, charts_dir / name):
            written.append(f"charts/{name}")
    return written


_CSS = """
:root { color-scheme: light; --surface:#fcfcfb; --plane:#f9f9f7; --ink:#0b0b0b; --ink-2:#52514e;
  --muted:#898781; --grid:#e1e0d9; --ring:rgba(11,11,11,0.10); --good:#006300; --critical:#d03b3b; }
* { box-sizing: border-box; }
body { margin:0; background:var(--plane); color:var(--ink);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:32px 0 8px; }
.sub { color:var(--ink-2); margin:0 0 16px; }
.card { background:var(--surface); border:1px solid var(--ring); border-radius:8px; padding:16px; margin:12px 0; overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }
th, td { text-align:right; padding:4px 8px; border-bottom:1px solid var(--grid); white-space:nowrap; }
th:first-child, td:first-child, th.l, td.l { text-align:left; }
th { color:var(--ink-2); font-weight:600; }
.swatch { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; vertical-align:baseline; }
.status-completed { color:var(--good); } .status-failed, .status-skipped, .status-interrupted { color:var(--critical); }
img { max-width:100%; height:auto; display:block; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 16px; margin:0; }
dt { color:var(--ink-2); }
"""


def _status(status: str) -> str:
    icon = {"completed": "✓", "skipped": "⊘", "failed": "✕", "interrupted": "■"}.get(status, "•")
    return f'<span class="status-{html.escape(status)}">{icon} {html.escape(status)}</span>'


def render_html(run_dir: Path, state: dict, charts: list) -> Path:
    """Write ``report.html`` for the run and return its path."""
    e = html.escape
    detectors = detector_order(state)
    color = {d: SERIES[i] for i, d in enumerate(detectors[:len(SERIES)])}
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>TunFrame report: {e(str(state.get('name')))}</title><style>{_CSS}</style></head><body><main>"]
    parts.append(f"<h1>{e(str(state.get('name')))}</h1>")
    if state.get("description"):
        parts.append(f"<p class='sub'>{e(str(state['description']))}</p>")
    run_info = state.get("run_info") or {}
    commit = (run_info.get("git_commit") or "")[:10] + (" (dirty)" if run_info.get("git_dirty") else "")
    parts.append("<div class='card'><dl>"
                 f"<dt>Status</dt><dd>{_status(state.get('status', ''))} {e(state.get('status_reason') or '')}</dd>"
                 f"<dt>Started</dt><dd>{e(str(state.get('started')))}</dd>"
                 f"<dt>Finished</dt><dd>{e(str(state.get('finished')))}</dd>"
                 f"<dt>Commit</dt><dd>{e(commit)}</dd></dl></div>")

    configs = state.get("configs", [])
    parts.append("<h2>Configurations</h2><div class='card'><table><tr><th>Configuration</th>"
                 "<th class='l'>Status</th><th class='l'>Reason</th><th>Log lines</th><th>Tunnel queries</th><th class='l'>File</th></tr>")
    for c in configs:
        stats = c.get("dataset_statistics") or {}
        parts.append(f"<tr><td>{e(c['name'])}</td><td class='l'>{_status(c['status'])}</td>"
                     f"<td class='l'>{e(c.get('reason') or '')}</td><td>{stats.get('total_loglines', '')}</td>"
                     f"<td>{stats.get('tunnel_queries', '')}</td><td class='l'><a href='{e(c['file'])}'>{e(c['file'])}</a></td></tr>")
    parts.append("</table></div>")

    for chart in charts:
        parts.append(f"<div class='card'><img src='{e(chart)}' alt='{e(Path(chart).stem.replace('_', ' '))}'></div>")

    parts.append("<h2>Detector results</h2>")
    for c in configs:
        if not c.get("detectors"):
            continue
        parts.append(f"<div class='card'><strong>{e(c['name'])}</strong><table><tr><th>Detector</th><th>Precision</th>"
                     "<th>Recall</th><th>F1</th><th>FPR</th><th>TP</th><th>FP</th><th>FN</th>"
                     "<th>Leak up</th><th>Leak down</th><th>Runtime</th></tr>")
        for row in sorted(c["detectors"], key=lambda r: r["detector"]):
            swatch = f"<span class='swatch' style='background:{color[row['detector']]}'></span>" if row["detector"] in color else ""
            parts.append(
                f"<tr><td>{swatch}{e(row['detector'])}</td><td>{(row.get('precision') or 0):.3f}</td>"
                f"<td>{(row.get('recall') or 0):.3f}</td><td>{(row.get('f1') or 0):.3f}</td><td>{(row.get('fpr') or 0):.5f}</td>"
                f"<td>{row.get('tp', '')}</td><td>{row.get('fp', '')}</td><td>{row.get('fn', '')}</td>"
                f"<td>{fmt_bytes(row.get('traffic_volume_up_bytes'))}</td><td>{fmt_bytes(row.get('traffic_volume_down_bytes'))}</td>"
                f"<td>{(row.get('runtime') or 0):.1f} s</td></tr>")
        parts.append("</table></div>")
    if len(detectors) > len(SERIES):
        parts.append(f"<p class='sub'>Charts show the first {len(SERIES)} detectors; all are in the tables.</p>")
    parts.append("</main></body></html>")
    path = run_dir / "report.html"
    path.write_text("".join(parts), encoding="utf-8")
    return path


def build_report(run_dir) -> Path:
    """Render charts and report.html for a run directory."""
    run_dir = Path(run_dir)
    state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    charts = render_charts(run_dir, state)
    return render_html(run_dir, state, charts)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m detection.report_charts <run_dir>")
    print(build_report(sys.argv[1]))
