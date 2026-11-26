"""Static charts and report.html for one run directory.

Reads ``run.json`` (see ``detection/reporting.py``) and writes, every chart once
per theme (``<name>.png`` light, ``<name>-dark.png`` dark, the dashboard palette):

- ``charts/bars_<metric>.png``: one group of bars per configuration, one bar per
  detector (F1, recall, FPR, ULV%, uplink leakage).
- ``charts/heatmap_<metric>.png``: detector x configuration for every metric.
- ``charts/tradeoff.png``: recall over FPR, one point per detector and configuration.
- ``charts/sweep_<name>.png``: F1 and ULV% over the swept parameter values.
- ``report.html``: run overview, detector comparison, per-detector and
  per-configuration tables and the charts. Dark by default like the dashboard,
  with a light/dark toggle that shares the dashboard's stored choice.

Colors follow the detector, not its rank: detectors take the categorical slots
in sorted name order, the same order the dashboard uses.

Usable on its own to (re)build a report: ``python -m detection.report_charts <run_dir>``.
"""
import html
import json
import logging
import math
import struct
import sys
from pathlib import Path

logger = logging.getLogger('dns_detector')

# Tokens of the dashboard (scripts/dashboard_static/style.css), per theme.
THEMES = {
    "light": {
        "suffix": "", "surface": "#fcfcfb", "surface2": "#f2f1ed", "ink": "#0b0b0b", "ink2": "#52514e",
        "muted": "#898781", "grid": "#e1e0d9", "baseline": "#c3c2b7",
        "series": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"],
    },
    "dark": {
        "suffix": "-dark", "surface": "#1a1a19", "surface2": "#232321", "ink": "#f0efec", "ink2": "#c3c2b7",
        "muted": "#898781", "grid": "#2c2c2a", "baseline": "#383835",
        "series": ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"],
    },
}
SERIES = THEMES["light"]["series"]
# Sequential blue ramp (light to dark); the dark theme reverses it so low values recede.
HEAT = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5", "#2a78d6",
        "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"]

# key, label, fixed maximum (None: data maximum), formatter, lower is better
METRICS = [
    ("f1", "F1", 1.0, lambda v: f"{v:.2f}", False),
    ("precision", "Precision", 1.0, lambda v: f"{v:.2f}", False),
    ("recall", "Recall", 1.0, lambda v: f"{v:.2f}", False),
    ("fpr", "FPR", None, lambda v: f"{v:.3g}", True),
    ("ulv_percent", "ULV %", 100.0, lambda v: f"{v:.0f}%", True),
    ("dlv_percent", "DLV %", 100.0, lambda v: f"{v:.0f}%", True),
]
METRIC = {m[0]: m for m in METRICS}


def detector_order(state: dict) -> list:
    """Detectors of the run in the order that assigns their colors."""
    names = {row["detector"] for c in state.get("configs", []) for row in c.get("detectors", [])}
    return sorted(names)


def _group_meta(state: dict) -> dict:
    return {g["name"]: g for g in state.get("config_groups") or []}


# Window without tunnel traffic (timing.benign_only_duration); only its FPR is meaningful.
BENIGN_WINDOW = "benign_only"


def _benign_window(state: dict):
    """The run.json entry of the benign-only window, or None."""
    return next((c for c in state.get("configs", []) if c.get("name") == BENIGN_WINDOW), None)


def _completed(state: dict) -> list:
    """Tunnel configurations with detector results, in planned (grouped) order.

    The benign-only window is left out: it has no tunnel traffic, so recall,
    F1 and leakage carry no information (see ``_benign_section``).
    """
    order = {name: i for i, name in enumerate(state.get("planned_configs") or [])}
    configs = [c for c in state.get("configs", []) if c.get("detectors") and c.get("name") != BENIGN_WINDOW]
    return sorted(configs, key=lambda c: order.get(c["name"], len(order)))


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


def _fmt(value, digits=3) -> str:
    return "–" if value is None else f"{value:.{digits}f}"


def _pct(value) -> str:
    return "–" if value is None else f"{value:.1f} %"


def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


# -- chart helpers -------------------------------------------------------------

def _figure(plt, t, width, height, **kw):
    fig, ax = plt.subplots(figsize=(width, height), dpi=150, layout="constrained", **kw)
    fig.patch.set_facecolor(t["surface"])
    for a in (ax.flat if hasattr(ax, "flat") else [ax]):
        _style_axes(a, t)
    return fig, ax


def _style_axes(ax, t) -> None:
    ax.set_facecolor(t["surface"])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(t["baseline"])
    ax.tick_params(colors=t["muted"], labelcolor=t["ink2"], length=0)
    ax.yaxis.grid(True, color=t["grid"], linewidth=1)
    ax.set_axisbelow(True)


def _legend(fig, t, ncol: int) -> None:
    """Legend in its own band above the plot; constrained layout keeps it clear of labels."""
    fig.legend(loc="outside upper left", ncol=min(ncol, 5), frameon=False, labelcolor=t["ink2"],
               handlelength=1.0, fontsize=9)


def _config_labels(ax, labels, fig_w, n) -> None:
    rotate = n > 1 and max(len(label) for label in labels) * 0.075 > fig_w / n
    ax.set_xticks(range(n))
    ax.set_xticklabels([label if len(label) <= 32 else label[:31] + "…" for label in labels],
                       rotation=30 if rotate else 0, ha="right" if rotate else "center",
                       rotation_mode="anchor" if rotate else "default", fontsize=9)


def _grouped_bars(plt, t, configs, detectors, key, path, y_formatter=None, ylim=None) -> None:
    import numpy as np

    n_cfg, n_det = len(configs), len(detectors)
    fig_w = max(6.0, min(12.0, 1.2 + n_cfg * (0.25 * n_det + 0.5)))
    fig, ax = _figure(plt, t, fig_w, 3.8)
    width = min(0.8 / max(n_det, 1), 0.22)
    x = np.arange(n_cfg)
    for i, det in enumerate(detectors):
        values = [(_value(c, det, key) or 0) for c in configs]
        ax.bar(x + (i - (n_det - 1) / 2) * width, values, width=width * 0.88, color=t["series"][i],
               label=det, linewidth=0)
    _config_labels(ax, [c["name"] for c in configs], fig_w, n_cfg)
    if ylim:
        ax.set_ylim(*ylim)
    if y_formatter:
        ax.yaxis.set_major_formatter(y_formatter)
    if n_det > 1:
        _legend(fig, t, n_det)
    fig.savefig(path, facecolor=t["surface"])
    plt.close(fig)


def _heatmap(plt, t, configs, detectors, key, path) -> None:
    import numpy as np
    from matplotlib.colors import ListedColormap

    _, label, vmax, fmt, _ = METRIC[key]
    data = np.array([[(_value(c, d, key) if _value(c, d, key) is not None else np.nan) for c in configs]
                     for d in detectors], dtype=float)
    if vmax is None:
        vmax = float(np.nanmax(data)) if np.isfinite(data).any() and np.nanmax(data) > 0 else 1.0
    ramp = HEAT[::-1] if t["suffix"] else HEAT
    cmap = ListedColormap(ramp)
    cmap.set_bad(t["surface2"])
    fig_w = max(5.5, min(12.0, 2.0 + 0.75 * len(configs)))
    fig, ax = _figure(plt, t, fig_w, 1.4 + 0.42 * len(detectors))
    ax.yaxis.grid(False)
    ax.spines["bottom"].set_visible(False)
    image = ax.imshow(np.ma.masked_invalid(data), cmap=cmap, vmin=0, vmax=vmax, aspect="auto")
    for (r, c), v in np.ndenumerate(data):
        if math.isnan(v):
            text, ink = "–", t["muted"]
        else:
            step = round(max(0.0, min(1.0, v / vmax)) * (len(HEAT) - 1))
            idx = len(HEAT) - 1 - step if t["suffix"] else step
            text, ink = fmt(v), ("#ffffff" if idx >= 6 else "#0b0b0b")
        ax.text(c, r, text, ha="center", va="center", fontsize=8, color=ink)
    _config_labels(ax, [c["name"] for c in configs], fig_w, len(configs))
    ax.set_yticks(range(len(detectors)))
    ax.set_yticklabels(detectors, fontsize=9)
    bar = fig.colorbar(image, ax=ax, fraction=0.04, pad=0.01)
    bar.outline.set_visible(False)
    bar.ax.tick_params(colors=t["muted"], labelcolor=t["ink2"], length=0, labelsize=8)
    fig.savefig(path, facecolor=t["surface"])
    plt.close(fig)


def _tradeoff(plt, t, configs, detectors, path) -> bool:
    fig, ax = _figure(plt, t, 6.5, 4.0)
    plotted = False
    for i, det in enumerate(detectors):
        pts = [(_value(c, det, "fpr"), _value(c, det, "recall")) for c in configs]
        pts = [(x, y) for x, y in pts if x is not None and y is not None]
        if pts:
            plotted = True
            ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=48, color=t["series"][i],
                       edgecolors=t["surface"], linewidths=1.5, label=det, zorder=3)
    ax.xaxis.grid(True, color=t["grid"], linewidth=1)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("False positive rate (lower is better)", color=t["ink2"], fontsize=9)
    ax.set_ylabel("Recall (higher is better)", color=t["ink2"], fontsize=9)
    if len(detectors) > 1:
        _legend(fig, t, len(detectors))
    fig.savefig(path, facecolor=t["surface"])
    plt.close(fig)
    return plotted


def _sweep_points(sweep, configs_by_name):
    name, parameter = sweep.get("name", "unnamed_sweep"), sweep.get("parameter", "")
    points = []
    for value in sweep.get("values", []):
        config = configs_by_name.get(f"{name}_{parameter}_{value}")
        if config and config.get("detectors"):
            points.append((value, config))
    return points


def _sweep_chart(plt, t, sweep, configs_by_name, detectors, path) -> bool:
    points = _sweep_points(sweep, configs_by_name)
    if len(points) < 2:
        return False
    parameter = sweep.get("parameter", "")
    numeric = all(isinstance(v, (int, float)) and not isinstance(v, bool) for v, _ in points)
    xs = [v for v, _ in points] if numeric else list(range(len(points)))
    fig, axes = _figure(plt, t, 8.5, 3.4, ncols=2)
    for ax, key, ylim in ((axes[0], "f1", (0, 1.05)), (axes[1], "ulv_percent", (0, 105))):
        for i, det in enumerate(detectors):
            ys = [_value(c, det, key) for _, c in points]
            ys = [math.nan if y is None else y for y in ys]
            ax.plot(xs, ys, color=t["series"][i], linewidth=2, marker="o", markersize=6,
                    markeredgecolor=t["surface"], markeredgewidth=1.5, label=det if key == "f1" else None)
        if not numeric:
            ax.set_xticks(xs)
            ax.set_xticklabels([str(v) for v, _ in points], fontsize=9)
        ax.set_ylim(*ylim)
        ax.set_xlabel(parameter, color=t["ink2"], fontsize=9)
        ax.set_title(METRIC[key][1], loc="left", color=t["ink"], fontsize=10)
    if len(detectors) > 1:
        _legend(fig, t, len(detectors))
    fig.savefig(path, facecolor=t["surface"])
    plt.close(fig)
    return True


def _css_width(png: Path):
    """CSS pixel width that shows a 150 dpi PNG with 9 pt text at about 12 px."""
    try:
        with open(png, "rb") as f:
            width = struct.unpack(">I", f.read(24)[16:20])[0]
        return round(width * 96 / 150)
    except (OSError, struct.error):
        return None


def render_charts(run_dir: Path, state: dict) -> list:
    """Write the PNG charts of a run (light and dark).

    Returns:
        list: ``(section, title, base path, css width)`` per chart; ``<base>.png``
        is the light and ``<base>-dark.png`` the dark variant, relative to
        ``run_dir``. The width shows the image at its natural text size.
    """
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

    def chart(section, title, name, draw):
        ok = True
        for t in THEMES.values():
            ok = draw(t, charts_dir / f"{name}{t['suffix']}.png") is not False and ok
        if ok:
            written.append((section, title, f"charts/{name}", _css_width(charts_dir / f"{name}.png")))

    percent = FuncFormatter(lambda v, _: f"{v:.0f} %")
    bars = [("f1", "F1 by configuration", {"ylim": (0, 1.05)}),
            ("recall", "Recall by configuration", {"ylim": (0, 1.05)}),
            ("fpr", "False positive rate by configuration", {}),
            ("ulv_percent", "ULV % (share of the uploaded file before the alarm)",
             {"ylim": (0, 105), "y_formatter": percent}),
            ("net_up_bytes", "Net leakage: file bytes until first alarm",
             {"y_formatter": FuncFormatter(lambda v, _: fmt_bytes(v))}),
            ("traffic_volume_up_bytes", "Raw uplink leakage (query names) until first alarm",
             {"y_formatter": FuncFormatter(lambda v, _: fmt_bytes(v))})]
    for key, title, kw in bars:
        if any(_value(c, d, key) is not None for c in configs for d in detectors):
            chart("bars", title, f"bars_{key}",
                  lambda t, path, key=key, kw=kw: _grouped_bars(plt, t, configs, detectors, key, path, **kw))
    for key, label, _, _, lower in METRICS:
        if any(_value(c, d, key) is not None for c in configs for d in detectors):
            chart("heatmaps", f"{label}{' (lower is better)' if lower else ''}", f"heatmap_{key}",
                  lambda t, path, key=key: _heatmap(plt, t, configs, detectors, key, path))
    chart("tradeoff", "Recall over false positive rate (one point per configuration)", "tradeoff",
          lambda t, path: _tradeoff(plt, t, configs, detectors, path))

    by_name = {c["name"]: c for c in configs}
    sweeps = ((state.get("complete_config") or {}).get("dnsexfiltrator") or {}).get("sweeps") or []
    for sweep in sweeps:
        name = f"sweep_{sweep.get('name', 'unnamed')}"
        chart("sweeps", f"Sweep {sweep.get('name', '')}: F1 and ULV % over {sweep.get('parameter', '')}", name,
              lambda t, path, sweep=sweep: _sweep_chart(plt, t, sweep, by_name, detectors, path))
    return written


# -- HTML ----------------------------------------------------------------------

_CSS = """
:root { color-scheme: dark; --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#232321; --ink:#f0efec;
  --ink-2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --ring:rgba(255,255,255,0.10); --good:#0ca30c;
  --warning:#fab219; --critical:#e66767; --accent:#3987e5; }
:root[data-theme="light"] { color-scheme: light; --plane:#f9f9f7; --surface:#fcfcfb; --surface-2:#f2f1ed;
  --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781; --grid:#e1e0d9; --ring:rgba(11,11,11,0.10);
  --good:#006300; --warning:#8a5a00; --critical:#d03b3b; --accent:#2a78d6; }
* { box-sizing: border-box; }
body { margin:0; background:var(--plane); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
header { position:sticky; top:0; z-index:2; display:flex; gap:12px; align-items:center; padding:8px 16px;
  background:var(--surface); border-bottom:1px solid var(--ring); }
.brand { font-weight:700; letter-spacing:.12em; } .brand span { color:var(--accent); }
.spacer { flex:1; }
button { font:inherit; color:var(--ink); background:transparent; border:1px solid var(--ring); border-radius:6px;
  padding:4px 10px; cursor:pointer; }
main { max-width:1200px; margin:0 auto; padding:16px 16px 48px; }
h1 { font-size:22px; margin:8px 0 4px; } h2 { font-size:13px; letter-spacing:.08em; text-transform:uppercase;
  color:var(--ink-2); margin:28px 0 8px; } h3 { font-size:13px; margin:0 0 8px; color:var(--ink-2); font-weight:600; }
.sub { color:var(--ink-2); margin:0 0 12px; }
.card { background:var(--surface); border:1px solid var(--ring); border-radius:8px; padding:14px; margin:12px 0; overflow-x:auto; }
.charts { display:grid; grid-template-columns:repeat(auto-fit, minmax(min(100%, 520px), 1fr)); gap:12px; }
.charts .card { margin:0; }
.charts.wide { grid-template-columns:minmax(0, 1fr); }
table { border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }
th, td { text-align:right; padding:4px 8px; border-bottom:1px solid var(--grid); white-space:nowrap; }
th:first-child, td:first-child, th.l, td.l { text-align:left; }
th { color:var(--ink-2); font-weight:600; }
tr.group td { background:var(--surface-2); color:var(--ink-2); font-weight:700; font-size:11px; letter-spacing:.06em; text-transform:uppercase; }
tr.mean td { font-weight:600; border-top:2px solid var(--grid); }
.swatch { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; }
.status-completed { color:var(--good); } .status-skipped, .status-interrupted { color:var(--warning); }
.status-failed { color:var(--critical); }
.meter { display:inline-block; width:80px; height:6px; border-radius:3px; background:var(--surface-2);
  vertical-align:middle; margin-left:8px; overflow:hidden; }
.meter i { display:block; height:100%; background:var(--accent); }
img { max-width:100%; height:auto; display:block; }
:root:not([data-theme="light"]) img.light, :root[data-theme="light"] img.dark { display:none; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 16px; margin:0; }
dt { color:var(--ink-2); } dd { margin:0; }
a { color:var(--accent); }
"""

_THEME_JS = """
(function () {
  var root = document.documentElement, key = "tunframe-theme", param = new URLSearchParams(location.search).get("theme"), saved = null;
  try { saved = localStorage.getItem(key); } catch (e) {}
  function apply(theme) {
    root.dataset.theme = theme;
    var b = document.getElementById("theme-toggle"); if (b) b.textContent = theme === "dark" ? "Light" : "Dark";
    try { localStorage.setItem(key, theme); } catch (e) {}
  }
  apply(param === "light" || param === "dark" ? param : saved || "dark");
  document.addEventListener("DOMContentLoaded", function () {
    apply(root.dataset.theme);
    document.getElementById("theme-toggle").addEventListener("click", function () {
      apply(root.dataset.theme === "dark" ? "light" : "dark");
    });
  });
})();
"""

ENDED_BY = {"transfer_complete": "transfer complete", "all_detected": "all detected", "timer": "timer",
            "log_ended": "log ended", "interrupted": "interrupted", "user_skip": "skipped from dashboard",
            "user_stop": "stopped from dashboard"}


def _ended_by(config: dict) -> str:
    end = config.get("wartime_end") or {}
    if not end.get("reason"):
        return ""
    label = ENDED_BY.get(end["reason"], end["reason"])
    if end.get("transfer_completed") is False:
        return f"{label} · transfer incomplete"
    return f"{label} ({end['transfer_seconds']:.1f} s)" if end.get("transfer_seconds") is not None else label


NET_CHECK = {"match": "✓", "incomplete": "transfer incomplete", "mismatch": "≠ tool size", "unknown": ""}


def _net_volume(stats: dict) -> str:
    """Decoded tunnel data of a window next to the file size the tools reported."""
    if stats.get("tunnel_net_up_bytes") is None:
        return ""
    size = stats.get("exfil_file_bytes") or stats.get("exfil_file_bytes_server")
    note = NET_CHECK.get(stats.get("net_volume_check"), "")
    return f"{fmt_bytes(stats['tunnel_net_up_bytes'])} / {fmt_bytes(size) if size else '?'}" + (f" {note}" if note else "")


def _status(status: str) -> str:
    icon = {"completed": "✓", "skipped": "⊘", "failed": "✕", "interrupted": "■"}.get(status, "•")
    return f'<span class="status-{html.escape(status)}">{icon} {html.escape(status)}</span>'


def _img(base: str, alt: str, width=None) -> str:
    e = html.escape
    size = f" style='width:{width}px'" if width else ""
    return (f"<img class='dark' src='{e(base)}-dark.png' alt='{e(alt)}' loading='lazy'{size}>"
            f"<img class='light' src='{e(base)}.png' alt='{e(alt)}' loading='lazy'{size}>")


def _chart_cards(charts, section, wide=False) -> str:
    cards = [f"<div class='card'><h3>{html.escape(title)}</h3>{_img(base, title, width)}</div>"
             for sec, title, base, width in charts if sec == section]
    return f"<div class='charts{' wide' if wide else ''}'>{''.join(cards)}</div>" if cards else ""


def _benign_section(benign: dict, completed: list, detectors: list, swatch) -> str:
    """HTML of the benign-only baseline: each detector's FPR without and with tunnel traffic."""
    e = html.escape
    stats = benign.get("dataset_statistics") or {}
    rows = sorted(benign.get("detectors") or [], key=lambda r: (r.get("fpr") is None, r.get("fpr") or 0, r["detector"]))
    with_tunnel = bool(completed)
    parts = ["<h2>Benign-only baseline</h2><div class='card'>",
             f"<p class='sub'>{_status(benign.get('status', ''))} · ended by {e(_ended_by(benign))} · "
             f"{e(benign.get('reason') or '')} · {stats.get('total_queries', '–')} queries · "
             f"{stats.get('unique_domains', '–')} registered domains · "
             f"{stats.get('window_seconds', '–')} s</p>"]
    if stats.get("tunnel_queries"):
        parts.append(f"<p class='sub'>{stats['tunnel_queries']} queries to tunneling domains were seen in this window; "
                     "they count as tunnel traffic, not as false positives.</p>")
    parts.append("<table><tr><th class='l'>Detector</th><th>FPR benign-only</th>"
                 + ("<th>FPR with tunnel</th><th>Change</th>" if with_tunnel else "")
                 + "<th>FP domains</th><th>TN domains</th><th>FP / h</th><th>Allowlist</th><th class='l'>False alarms</th></tr>")
    for r in rows:
        d = r["detector"]
        tunnel_fpr = _mean([_value(c, d, "fpr") for c in completed]) if with_tunnel else None
        change = (tunnel_fpr - r["fpr"]) if tunnel_fpr is not None and r.get("fpr") is not None else None
        sample = r.get("false_positives_sample") or []
        more = (r.get("fp") or 0) - len(sample)
        per_hour = r.get("fp_domains_per_hour")
        parts.append(f"<tr><td class='l'>{swatch(d)}{e(d)}</td><td>{_fmt(r.get('fpr'), 5)}</td>"
                     + (f"<td>{_fmt(tunnel_fpr, 5)}</td><td>{'–' if change is None else f'{change:+.5f}'}</td>" if with_tunnel else "")
                     + f"<td>{r.get('fp', '–')}</td><td>{r.get('tn', '–')}</td>"
                     f"<td>{'–' if per_hour is None else f'{per_hour:.1f}'}</td><td>{r.get('allowlist_size', '–')}</td>"
                     f"<td class='l'>{e(', '.join(sample)) or 'none'}{f' (+{more} more)' if more > 0 else ''}</td></tr>")
    parts.append("</table><p class='sub'>Benign and wildcard traffic only, after peacetime and with the same "
                 "allowlists as the tunnel windows, so every alarm is a false positive. "
                 + ("FPR with tunnel: mean over the finished tunnel configurations; Change: with tunnel minus "
                    "benign-only. " if with_tunnel else "")
                 + f"Full false-alarm lists: <a href='{e(benign.get('file') or '')}'>{e(benign.get('file') or '')}</a>.</p></div>")
    return "".join(parts)


def render_html(run_dir: Path, state: dict, charts: list) -> Path:
    """Write ``report.html`` for the run and return its path."""
    e = html.escape
    detectors = detector_order(state)
    color = {d: SERIES[i] for i, d in enumerate(detectors[:len(SERIES)])}
    swatch = lambda d: f"<span class='swatch' style='background:{color[d]}'></span>" if d in color else ""
    groups = _group_meta(state)
    completed = _completed(state)
    name = e(str(state.get("name")))
    parts = [f"<!doctype html><html lang='en' data-theme='dark'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>TunFrame report: {name}</title><style>{_CSS}</style><script>{_THEME_JS}</script></head><body>"
             f"<header><div class='brand'>TUNFRAME <span>REPORT</span></div><span class='spacer'></span>"
             f"<button id='theme-toggle' aria-label='Toggle light and dark theme'>Light</button></header><main>"]
    parts.append(f"<h1>{name}</h1>")
    if state.get("description"):
        parts.append(f"<p class='sub'>{e(str(state['description']))}</p>")
    run_info = state.get("run_info") or {}
    commit = (run_info.get("git_commit") or "")[:10] + (" (dirty)" if run_info.get("git_dirty") else "")
    parts.append("<div class='card'><dl>"
                 f"<dt>Status</dt><dd>{_status(state.get('status', ''))} {e(state.get('status_reason') or '')}</dd>"
                 f"<dt>Started</dt><dd>{e(str(state.get('started')))}</dd>"
                 f"<dt>Finished</dt><dd>{e(str(state.get('finished')))}</dd>"
                 f"<dt>Commit</dt><dd>{e(commit)}</dd></dl></div>")

    benign = _benign_window(state)
    if benign and benign.get("detectors"):
        parts.append(_benign_section(benign, completed, detectors, swatch))

    # Detector comparison: mean of every metric over the finished configurations,
    # least exfiltrated volume first, then the best F1 (as the dashboard ranking).
    if completed and detectors:
        parts.append("<h2>Detector comparison</h2><div class='card'><table><tr><th>#</th><th class='l'>Detector</th>"
                     "<th>ULV %</th><th>Net leak</th><th>Mean F1</th><th>Precision</th><th>Recall</th><th>FPR</th>"
                     "<th>DLV %</th><th>Detected</th><th>Runtime</th></tr>")
        mean_of = lambda d, key: _mean([_value(c, d, key) for c in completed])
        last = float("inf")
        ranked = sorted(detectors, key=lambda d: (mean_of(d, "ulv_percent") if mean_of(d, "ulv_percent") is not None else last,
                                                  -(mean_of(d, "f1") or 0), d))
        for rank, d in enumerate(ranked, 1):
            col = lambda key: [_value(c, d, key) for c in completed]
            f1, net = _mean(col("f1")), _mean(col("net_up_bytes"))
            detected = sum(1 for c in completed if (_value(c, d, "tp") or 0) > 0)
            meter = f"<span class='meter'><i style='width:{100 * (f1 or 0):.0f}%'></i></span>"
            parts.append(f"<tr><td>{rank}</td><td class='l'>{swatch(d)}{e(d)}</td><td>{_pct(_mean(col('ulv_percent')))}</td>"
                         f"<td>{fmt_bytes(net) if net is not None else '–'}</td><td>{_fmt(f1)}{meter}</td>"
                         f"<td>{_fmt(_mean(col('precision')))}</td><td>{_fmt(_mean(col('recall')))}</td>"
                         f"<td>{_fmt(_mean(col('fpr')), 5)}</td><td>{_pct(_mean(col('dlv_percent')))}</td>"
                         f"<td>{detected} / {len(completed)}</td><td>{sum(v or 0 for v in col('runtime')):.1f} s</td></tr>")
        parts.append("</table><p class='sub'>Means over the finished configurations, ordered by ULV % (lower first), "
                     "then F1. ULV %: share of the exfiltrated "
                     "file that left before the detector's alarm (DNSExfiltrator mode: decoded data chunks over the file "
                     "size the tool announced; replay mode: share of the raw tunnel uplink). DLV %: the same for the "
                     "downlink. Lower is better.</p></div>")

    configs = state.get("configs", [])
    parts.append("<h2>Configurations</h2><div class='card'><table><tr><th>Configuration</th><th class='l'>Group</th>"
                 "<th class='l'>Status</th><th class='l'>Reason</th><th class='l'>Ended by</th><th>Log lines</th>"
                 "<th>Tunnel queries</th><th>Tunnel up</th><th class='l'>Net / file</th><th class='l'>File</th></tr>")
    for c in configs:
        stats = c.get("dataset_statistics") or {}
        group = groups.get(c["name"], {}).get("group", "")
        parts.append(f"<tr><td>{e(c['name'])}</td><td class='l'>{e(group)}</td><td class='l'>{_status(c['status'])}</td>"
                     f"<td class='l'>{e(c.get('reason') or '')}</td><td class='l'>{e(_ended_by(c))}</td>"
                     f"<td>{stats.get('total_loglines', '')}</td><td>{stats.get('tunnel_queries', '')}</td>"
                     f"<td>{fmt_bytes(stats['tunnel_up_bytes']) if stats.get('tunnel_up_bytes') is not None else ''}</td>"
                     f"<td class='l'>{e(_net_volume(stats))}</td>"
                     f"<td class='l'><a href='{e(c['file'])}'>{e(c['file'])}</a></td></tr>")
    parts.append("</table></div>")

    for section, title, wide in (("bars", "Metrics by configuration", True),
                                 ("heatmaps", "Heatmaps: detector × configuration", True),
                                 ("tradeoff", "Detection trade-off", False), ("sweeps", "Sweeps", False)):
        cards = _chart_cards(charts, section, wide)
        if cards:
            parts.append(f"<h2>{title}</h2>{cards}")

    if completed and detectors:
        parts.append("<h2>Per detector</h2>")
        for d in detectors:
            parts.append(f"<div class='card'><h3>{swatch(d)}{e(d)}</h3><table><tr><th>Configuration</th>"
                         "<th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>ULV %</th><th>DLV %</th>"
                         "<th>TP</th><th>FP</th><th>FN</th><th>Net leak</th><th>Leak up (raw)</th><th>Runtime</th></tr>")
            last_group = None
            for c in completed:
                group = groups.get(c["name"], {}).get("group")
                if group and group != last_group and len({g.get("group") for g in groups.values()}) > 1:
                    parts.append(f"<tr class='group'><td colspan='13'>{e(group)}</td></tr>")
                last_group = group
                v = lambda key: _value(c, d, key)
                parts.append(f"<tr><td>{e(c['name'])}</td><td>{_fmt(v('precision'))}</td><td>{_fmt(v('recall'))}</td>"
                             f"<td>{_fmt(v('f1'))}</td><td>{_fmt(v('fpr'), 5)}</td><td>{_pct(v('ulv_percent'))}</td>"
                             f"<td>{_pct(v('dlv_percent'))}</td><td>{v('tp') if v('tp') is not None else '–'}</td>"
                             f"<td>{v('fp') if v('fp') is not None else '–'}</td><td>{v('fn') if v('fn') is not None else '–'}</td>"
                             f"<td>{fmt_bytes(v('net_up_bytes')) if v('net_up_bytes') is not None else '–'}</td>"
                             f"<td>{fmt_bytes(v('traffic_volume_up_bytes'))}</td><td>{(v('runtime') or 0):.1f} s</td></tr>")
            mean = lambda key: _mean([_value(c, d, key) for c in completed])
            parts.append(f"<tr class='mean'><td>Mean</td><td>{_fmt(mean('precision'))}</td><td>{_fmt(mean('recall'))}</td>"
                         f"<td>{_fmt(mean('f1'))}</td><td>{_fmt(mean('fpr'), 5)}</td><td>{_pct(mean('ulv_percent'))}</td>"
                         f"<td>{_pct(mean('dlv_percent'))}</td><td></td><td></td><td></td><td></td><td></td><td></td></tr></table></div>")
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
