# Dashboard and report

## Live dashboard

```bash
python3 scripts/dashboard.py                              # http://127.0.0.1:8050
python3 scripts/dashboard.py --results ./results --port 8051
```

Without `--results` the results directory comes from `output.logdir` in `config.yaml`. The dashboard listens on `127.0.0.1` only and lists every run directory, so earlier runs stay browsable. It switches to a newly started run unless an older run was picked in the run selector (picking the newest run follows new runs again). Dark is the default theme; use the toggle or `?theme=light`.

The data comes from the run directory (see [Output](output.md)): `run.json` for state and results, `metrics.jsonl` for live metrics, which `main.py` writes every two seconds (DNS rates and record details from the collector log, transfer progress from the DNSExfiltrator server log, CPU and memory from `docker stats` every six seconds).

### Views

- **Key figures:** status and phase, running time, estimated end (from the average length of finished windows, plus the latest possible end), window `i / n`, DNSExfiltrator transfer progress, DNS queries per second and the tunnel share.
- **Current configuration:** the running window with its parameters and progress; all windows (status, how each ended, tunnel queries, net volume, F1 per detector; FPR for the benign-only window) in an expandable list.
- **DNS traffic:** queries per second, all vs. tunnel, over the run, with window boundaries.
- **CPU and memory:** per container and of `main.py`. A container appears once it runs; the DNSExfiltrator containers only exist from the first DNSExfiltrator configuration on.
- **Detection results:** any metric (F1, precision, recall, FPR, ULV %, DLV %, net leak, raw leak, runtime) per window and detector, as bars or a table. Windows are grouped by origin: tunnel replay, baseline, each sweep, profiles.
- **Heatmap:** detector × window for any metric.
- **Detectors**, with a *Wartime / Benign-only* switch in runs with a benign-only window:
  - *Wartime:* a ranking of all detectors over the finished tunnel windows (means), by default least exfiltrated volume (ULV %) first, then F1. Click a column header to sort, again to reverse. Selecting a detector shows its key figures, precision/recall/F1 and leaked share per window, and its full per-window table.
  - *Benign-only:* the benign-only window's length and how it ended, queries, benign registered domains, where the allowlists came from, lowest and mean FPR; per detector its FPR in the benign-only window, its mean FPR over the finished tunnel windows and the change, falsely flagged and TN domains, false-alarm domains per hour, allowlist size and up to ten falsely flagged domains (the full list is in the window's json). Sortable by every numeric column, lowest benign-only FPR first by default. The card opens on this view until the first tunnel window has finished; a benign-only run has only this view.
- **Configuration ranking:** which tunnel window exfiltrated the most data across all detectors: mean ULV % over the detectors (default order, most first), min ULV % (what left even before the best detector's alarm), mean net leak, file size, how many detectors flagged it, mean F1, tunnel queries, window length and how it ended. Click a column to sort; the first click puts the most evasive windows first.
- **Detection trade-off:** recall over FPR, one point per detector and tunnel window.
- **Sweeps:** any metric over each sweep's parameter values.
- **DNS breakdown and records:** response codes, the most queried registered domains (tunnel domains marked), and, benign vs. tunnel, the shares of query types, answer record types, query name lengths and subdomain entropy, plus average query and response sizes.
- **Logs:** the run log and the DNSExfiltrator server and client output of the run (cleared at every run start, copied into the run directory at its end, so a finished run shows its own output).

The benign-only window is never part of the tunnel views (results, heatmap, wartime ranking, configuration ranking, trade-off, sweeps). A benign-only run hides the views that need tunnel traffic.

### Controls

*Skip configuration* and *Stop run* (see [Run lifecycle](run-lifecycle.md#dashboard-controls)) ask for confirmation and write `control.json` into the running run's directory, which is the dashboard's only write. Requests carry a token embedded in the page and are only accepted from the dashboard's own origin.

## Static report

At the end of every run `main.py` writes `report.html` and its charts into the run directory. Rebuild them for any run directory with

```bash
python3 -m detection.report_charts results/<run>
```

The report has the same dark/light toggle as the dashboard and contains:

- run status, start, end and git commit,
- the **benign-only baseline** (if the run had a benign-only window): per detector its benign-only FPR, mean FPR with tunnel traffic and the change, FP and TN domains, false alarms per hour, allowlist size and example false alarms,
- the **detector comparison** (means over the tunnel windows, ordered by ULV %, then F1),
- the **configuration ranking** (as in the dashboard, ordered by mean ULV %),
- all windows with status, reason, how they ended and their traffic,
- charts in `charts/`, each as `<name>.png` (light) and `<name>-dark.png`: bars and heatmaps per metric, recall over FPR, and F1 and ULV % over each sweep,
- one table per detector with all its tunnel windows.

Charts need `matplotlib`; without it the report is written without them.
