# Output

Every run gets its own directory in `output.logdir`, named `<global.name>_<YYYYmmdd-HHMMSS>`:

```text
results/<name>_<timestamp>/
├── run.json              # run state, updated live: phase, progress, status and detector summary per window
├── run.log               # console log of the run
├── metrics.jsonl         # live metrics every 2 s: DNS rates, response codes, top domains, record types, transfer progress, CPU/memory
├── control.json          # requests from the dashboard (skip configuration, stop run), if any
├── exfil-server.log      # DNSExfiltrator server output of the run (copied at the end), if any
├── exfil-client.log      # DNSExfiltrator client output of the run (copied at the end), if any
├── configs/<window>.json # full results of one window
├── charts/*.png          # bars and heatmaps per metric, recall vs. FPR, sweeps; light and -dark
└── report.html           # static report with the charts and the tables behind them
```

Window files in `configs/` are named after the window: `benign_only.json`, `tunnel_replay.json`, one per DNSExfiltrator configuration (`baseline.json`, `<sweep>_<parameter>_<value>.json`, `<profile>.json`), or `wartime.json` for a run without any tunnel source.

A run that fails or is interrupted after setup still gets `run.json` with status `failed` or `interrupted`; windows that never started are listed with their reason.

## run.json

Replaced atomically, so the dashboard can read it while the run is going. Main fields:

| Field | Content |
| --- | --- |
| `status`, `status_reason` | `running`, `completed`, `interrupted` or `failed` |
| `mode` | `benign_only` for a benign-only run (no tunnel windows), otherwise `tunnel` |
| `phase`, `phase_detail`, `progress` | Current phase (`setup`, `peacetime`, `wartime`, `done`) and progress line |
| `planned_configs` | All windows in run order |
| `config_groups` | Group of every window: `Benign-only`, `Tunnel replay`, `Baseline`, the sweep name, or `Profiles`, with the sweep parameter and value |
| `configs` | One entry per finished window: status, reason, file, start and end, `dataset_statistics`, `wartime_end`, and a per-detector summary (main metrics, `fp_domains_per_hour`, `allowlist_size`, `total_alarms`, up to ten falsely flagged domains) |
| `current` | The running window: name, index, parameters, log offsets |
| `timing` | `wartime_duration`, `peacetime_duration`, `benign_only_duration` in seconds |
| `run_info`, `complete_config` | As in the window files |

## Window files

Each file in `configs/` contains `metadata` and `detectors`.

| Field | Content |
| --- | --- |
| `metadata.run_status` | `completed`, `interrupted`, `skipped` or `failed`, with a reason. Skipped and failed windows also get a file |
| `metadata.wartime_end` | How the window ended (`reason`: `transfer_complete`, `all_detected`, `timer`, `log_ended`, `interrupted`, `user_skip`, `user_stop`) and, with a watched DNSExfiltrator transfer, whether and after how many seconds it completed |
| `metadata.window_type` | `benign_only` for the benign-only window, otherwise `tunnel` |
| `metadata.experiment` | Name, description, start and end, durations |
| `metadata.traffic_config` | Benign and tunnel replay settings, the window's tunneling domains and those that appeared |
| `metadata.dnsexfiltrator_config` | The exact configuration of a DNSExfiltrator window |
| `metadata.dataset_statistics` | See below |
| `metadata.run_info` | Git commit and dirty flag, Python, library and Docker versions |
| `metadata.complete_config` | The full `config.yaml` |
| `detectors` | Per-detector results, see [Detectors and metrics](detectors.md#metrics) |

`dataset_statistics`:

- `total_loglines`, `total_queries`, `total_responses`, `unique_domains`,
- `tunnel_loglines`, `tunnel_queries`, `tunnel_responses`, `tunnel_percentage` (tunnel share of queries), `tunnel_up_bytes`, `tunnel_down_bytes`,
- `window_seconds`: the window's length (benign-only, tunnel replay and fallback windows),
- DNSExfiltrator windows: `tunnel_net_up_bytes` (decoded file bytes of all unique data chunks), `tunnel_init_queries`, `tunnel_data_queries`, `tunnel_dilution_queries`, `tunnel_retried_queries`, `init_encoding`, the archive size from the init (`exfil_file_bytes`) and from the server log (`exfil_file_bytes_server`), the size of the source file (`source_file_bytes`), and `net_volume_check`: `match` when the decoded data equals the announced size, `incomplete` when the transfer did not finish in the window, `mismatch` or `unknown` otherwise.
