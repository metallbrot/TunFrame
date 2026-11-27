# Run lifecycle

A run is

```text
setup → peacetime → benign-only window → tunnel replay window → DNSExfiltrator configurations → evaluation
```

Every phase between setup and evaluation is optional. Each window after peacetime is evaluated and saved on its own; the tunnel replay window and the DNSExfiltrator configurations are the *tunnel windows* (wartime).

## 1. Setup

`main.py`

1. checks the configuration (renamed keys abort, ignored keys warn, domains must be registered domains, see [Configuration](configuration.md#validation)),
2. creates the run directory (see [Output](output.md)),
3. stops all containers, clears the collector log and the DNSExfiltrator server and client logs,
4. generates the BIND configurations (see [Architecture](architecture.md#the-simulated-dns-hierarchy)),
5. starts the `essential` Docker profile and the live monitoring.

## 2. Peacetime (optional)

If `timing.peacetime_duration` > 0, the benign replay starts from the first packet of its pcap and every log line is fed to the detectors as benign. At the end of peacetime every domain a detector has alarmed on becomes part of that detector's allowlist, together with the global allowlist (`allowlist.global_allowlist_path`). Detector state learned in peacetime is kept; alarms and counters are cleared.

When peacetime ends, the benign replay is stopped and TunFrame counts how many packets it sent. It then cuts these packets off the front of the pcap with `editcap` (Wireshark, on the host), so every later window replays the part of the capture that follows the peacetime slice, each from its beginning. Without `editcap` later windows replay from packet 0 (a warning is logged).

## 3. Benign-only window (optional)

If `timing.benign_only_duration` > 0, a window named `benign_only` runs next. It behaves like a tunnel window, but without tunnel traffic: only the benign replay runs; the tunnel replay and the DNSExfiltrator client start only after it. Because there is no tunnel traffic, **every alarm is a false positive**: the window measures each detector's false positive rate under normal conditions, without adversarial load. Only FP, TN and FPR are meaningful for it.

- Detectors are prepared exactly as for the first tunnel window that follows: before the tunnel replay window they continue from peacetime; before a DNSExfiltrator configuration they are reset (allowlists kept).
- It replays the same benign segment as every tunnel window, so its FPR is directly comparable with the FPR under tunnel load.
- After it, alarms and counters are cleared so nothing carries over into the tunnel windows; detector state continues like live traffic.
- It is kept out of every tunnel aggregate (rankings, means, charts) and compared with the FPR under tunnel load instead, see [Dashboard and report](dashboard.md).
- Queries to a tunneling domain in this window (e.g. from a tool started by hand) are evaluated as tunnel traffic, and the dashboard warns about them.

A **benign-only run** is a benign-only window with neither `traffic.tunnel.replay` nor `dnsexfiltrator.enabled`: the run ends after that window.

## 4. Tunnel windows (wartime)

The benign replay runs in every tunnel window too, each time from the beginning of the segment after peacetime. Both tunnel sources can be used in the same run; they run one after the other, never at the same time.

### Tunnel replay window

If `traffic.tunnel.replay` is set, a window named `tunnel_replay` replays `traffic.tunnel.pcap` from its first packet. The tunnel replay starts and stops with the window, so it never overlaps a DNSExfiltrator window. The detectors continue from the previous phase (alarms and counters cleared after peacetime or the benign-only window). `traffic.tunnel.tunneling_domains` is the window's ground truth, and `traffic.tunnel.expansion_factor` estimates its net volume.

### DNSExfiltrator configurations

If `dnsexfiltrator.enabled` is set, one window runs per configuration (baseline, each sweep value, each profile), in that order. Before each configuration the detectors are reset (allowlists kept, `on_phase_reset()` called), the cached answers for its domains are flushed, and the DNSExfiltrator server and client are started for it (see [DNSExfiltrator](dnsexfiltrator.md#how-tunframe-runs-it)). The configuration's `domains` are the ground truth of its window.

### Without a tunnel source

If there is no benign-only window, no tunnel replay and no DNSExfiltrator, a single window named `wartime` runs without ground truth, e.g. for a tunneling tool started by hand.

### How a window ends

A window ends at the first of:

| Reason | When |
| --- | --- |
| `timer` | `timing.wartime_duration` (or `timing.benign_only_duration`) has passed |
| `all_detected` | every detector has flagged every tunneling domain of the window |
| `transfer_complete` | DNSExfiltrator mode with `dnsexfiltrator.stop_on_transfer_complete`: the server printed `File saved successfully`. TunFrame waits two seconds for the collector, then lets the detectors catch up with the log as it was at that moment, so every query of the transfer is evaluated |
| `log_ended` | the collector log reader stopped |
| `user_skip`, `user_stop` | *Skip configuration* or *Stop run* in the dashboard |
| `interrupted` | Ctrl+C |

Windows ended by `transfer_complete` differ in length; TN and FPR always refer to the window they were measured in. The results record how each window ended (`metadata.wartime_end`).

## 5. Evaluation

After every window each detector reports domain-level metrics for it (see [Detectors and metrics](detectors.md#metrics)), the console prints a results table, and a results file is written to `configs/<window>.json`. At the end of the run the console prints a summary (F1 per detector and configuration; FPR for the benign-only window), and `report.html` with its charts is written.

A configuration that could not run (server or client failed, no tunnel traffic, run stopped) still gets a results file with status `skipped` or `failed` and the reason. A run that fails or is interrupted after setup still gets a `run.json` with status `failed` or `interrupted`.

## Dashboard controls

The dashboard (see [Dashboard and report](dashboard.md)) can send two requests, which the run picks up from `control.json` in its directory:

- **Skip configuration**: the running window is evaluated up to now, saved as `interrupted`, and the run continues with the next window. A request made while a configuration is still starting applies as soon as its window opens; during setup and peacetime it is ignored.
- **Stop run**: the same for the running window; all remaining windows are saved as `skipped` and the run ends with status `interrupted`.
