# Behavior changes

Every change that alters a reported number or the way a run behaves, with the
old and the new definition. This file is the basis for the thesis erratum.
Entries are added in the commit that introduces the change.

## M1: True negatives exclude false negatives

- **Old**: `TN = all_domains - TP - FP`. A missed tunneling domain was counted
  as FN and as TN at the same time, so TP+FP+TN+FN exceeded the number of
  domains by the number of FNs.
- **New**: `TN = all_domains - TP - FP - FN`. Every registered domain falls into
  exactly one confusion-matrix class.
- **Affected outputs**: `tn`, `accuracy`, `fpr` (denominator FP+TN shrinks by
  |FN|). TP, FP, FN, precision and recall are unchanged.

## M2: FPR universe is the wartime window only

- **Old**: In replay (standard) mode, `main()` passed the set of domains seen
  during peacetime into the wartime evaluation, so peacetime-only domains were
  counted as TN. In DNSExfiltrator mode each config started from an empty set.
  The two modes therefore used different FPR denominators, and replay-mode FPR
  was deflated whenever peacetime was enabled.
- **New**: `run_wartime()` always builds the domain universe from the lines of
  its own window. TN, FPR, accuracy and `unique_domains` refer only to
  registered domains seen during that wartime (or that config's wartime) in
  both modes. The `alldomains` parameter of `run_wartime()` was removed.
- **Affected outputs**: `tn`, `fpr`, `accuracy`, `total_unique_domains`,
  `dataset_statistics.unique_domains` in replay mode with peacetime > 0.

## M3: Uplink leakage counts the full query payload

- **Old**: For a missed tunneling query, `lv_up` grew by the length of the
  last subdomain label only, and only if the subdomain had at least two
  labels. Single-label payloads (the current DNSExfiltrator request layout)
  contributed 0 bytes; multi-label payloads were under-counted.
- **New**: `lv_up` grows by the byte length of all labels left of the
  registered domain, without the separating dots
  (`feature_extraction.query_payload_bytes`). Example:
  `seq.abcdef.tunnel.com` adds 9 bytes; `abcdef.tunnel.com` adds 6 bytes.
- **Affected outputs**: `traffic_volume_up_bytes`,
  `estimated_real_traffic_up_bytes` (ULV in the thesis).

## M4: Downlink leakage derived from answer records

- **Old**: For a missed tunneling response, `lv_down` grew by a flat 4 bytes
  if the record type was A, regardless of the number of answers or the rcode.
  Responses of any other type added 0 bytes.
- **New**: `lv_down` grows by the RDATA volume of all answer records
  (`feature_extraction.answer_payload_bytes`): A 4 B, AAAA 16 B,
  CNAME/NS/PTR/DNAME the wire size of the target name, MX 2 B plus the name.
  Fallback for every other type (TXT, SVCB, NULL, ...): the UTF-8 length of
  DNS-collector's textual `rdata`, which approximates the payload and ignores
  length octets. Responses without answers add 0 bytes.
- **Affected outputs**: `traffic_volume_down_bytes` (DLV in the thesis). For
  single-answer A responses the value is unchanged.

## M5: Tunnel and missed counts refer to queries

- **Old**: `tunneling_missed`, the count passed as "tunnel queries", and the
  console lines "Total tunnel queries seen" / "Tunnel queries missed" counted
  query and response lines alike (about twice the real query count).
  `tunnel_percentage` was tunnel lines divided by all lines.
- **New**:
  - `tunneling_missed` counts missed tunneling queries only; missed responses
    are in the new `tunneling_missed_responses`.
  - Results add `tunneling_queries` and `tunneling_responses`;
    `tunneling_loglines` keeps its meaning (all tunneling lines).
  - `dataset_statistics` adds `total_queries`, `total_responses`,
    `tunnel_queries`, `tunnel_responses`; `total_loglines` and
    `tunnel_loglines` keep counting lines.
  - `tunnel_percentage` = tunnel queries / all queries × 100.
  - `run_wartime()` returns a sixth element with these counts.
- **Affected outputs**: `tunneling_missed`, `tunnel_percentage`, console text.

## M6: Average processing time per detect() call

- **Old**: `avg_process_time_ms` = time spent in `detect()` divided by all
  processed lines, including allowlisted lines that never reached `detect()`.
- **New**: `avg_process_time_ms` = time spent in `detect()` divided by the new
  counter `detect_calls` (lines that reached `detect()`). `processed_lines` is
  unchanged.
- **Affected outputs**: `avg_process_time_ms` (higher whenever allowlists are
  in use); new key `detect_calls`.

## M7: Detectors are reset at every DNSExfiltrator config boundary

- **Old**: The same detector instances ran all configs without a reset.
  Alarms, `processed_lines`, runtime, missed counts and leakage accumulated.
  Once every detector had flagged the tunnel domain, every later config
  stopped after its first log line, and the carried-over alarm was scored as
  a false positive when no tunnel line had been read.
- **New**: Before each config, `main.py` calls `phase_reset()` on every
  detector. It clears alarms, counters, runtime and leakage and keeps the
  peacetime allowlist. Detectors can clear internal state (windows, trackers)
  by overriding the new `on_phase_reset()` hook; the default does nothing.
- **Affected outputs**: every per-config results file after the first config
  of a run.
- **Caveat**: detectors that do not override `on_phase_reset()` still carry
  their internal state across configs.

## M8: Phase timers are cancelled when a phase ends

- **Old**: Each phase started a fire-and-forget thread that set the stop event
  after the phase duration. When a phase ended early, its thread kept running
  and later set the stop event during the next DNSExfiltrator config, cutting
  that config short. `run_peacetime()`/`run_wartime()` also cleared the stop
  event after the timer had been armed.
- **New**: `main.PhaseTimer` wraps `threading.Timer`. Every phase cancels its
  timer in a `finally` block, so no stale timer can stop a later phase. The run
  loops no longer clear the event themselves; `main.py` clears it before arming
  the timer.
- **Affected outputs**: wartime length (and therefore every metric) of configs
  that followed an early-ending config.

## M9: Log reader no longer sleeps after every line

- **Old**: `readjson()` slept 10 ms after every line, capping ingestion at
  roughly 80-100 lines/s before any detector cost. With benign replay at
  realistic rates, each wall-clock phase evaluated only an early slice of the
  logged traffic and discarded the unread rest.
- **New**: Buffered lines are read back to back; the reader sleeps 10 ms only
  when no new data is available.
- **Affected outputs**: `total_loglines`, all line and query counts, and every
  metric of phases whose log grew faster than ~80 lines/s. Results become a
  function of the traffic actually generated in the phase window rather than
  of the reader speed.

## M10: Benign replay starts once and is never restarted

- **Old**: `run_peacetime_phase()` started the benign (and wildcard) replay even
  when peacetime was 0, and `run_wartime_phase()` started a second replay of
  the same pcap from packet 0. Neither was ever stopped. With peacetime > 0,
  wartime therefore repeated the traffic that had built the allowlist (biasing
  FPR downward) on top of the still-running peacetime replay; with peacetime 0,
  two copies of the replay ran in parallel.
- **New**: `main.start_replay()` starts each traffic source at most once per
  run. The peacetime phase starts replays only when peacetime > 0. Wartime
  continues a running replay (the unseen remainder of the capture) and only
  starts it if no peacetime replay exists. Peacetime thus consumes the first
  slice of the capture and wartime the following one, matching thesis
  section 3.4.
- **Affected outputs**: all benign-traffic metrics (FP, TN, FPR, line counts)
  of every run with benign replay enabled. Wildcard replay: see C6.

## M11: Allowlisted tunneling traffic is accounted separately

- **Old**: Lines of a tunneling domain that was on a detector's allowlist
  skipped all accounting. Leakage and missed counts read 0 although the
  traffic passed uninspected.
- **New**: The detection decision is unchanged (allowlisted lines still never
  reach `detect()` and cannot raise alarms). Such lines are counted in new
  result keys: `allowlisted_tunnel_lines`, `allowlisted_tunnel_queries`,
  `allowlisted_tunnel_responses`, `allowlisted_tunnel_up_bytes`,
  `allowlisted_tunnel_down_bytes`. Leakage there uses the same definitions as
  M3/M4. `tunneling_missed`, `traffic_volume_up_bytes` and
  `traffic_volume_down_bytes` keep covering inspected traffic only.
- **Affected outputs**: new keys only; existing values unchanged.

## M12: Stop event checked on every loop iteration

- **Old**: `readjson(timeout_seconds=60, max_timeouts=2)` yielded nothing for
  60 s on an idle log, so a phase could overrun its configured duration by up
  to 60 s (a stored 30 s wartime ran 60 s). After two consecutive timeouts
  (~120 s idle) the generator ended, and the phase stopped early with
  "Log ended" regardless of its configured duration.
- **New**: `readjson(log_file, poll_interval=0.05, max_idle_seconds=None)`
  yields `None` after every idle poll, so the phase loops check their stop
  event at least every 50 ms. The generator no longer ends on idle by
  default; phases end through their timer or early stop only.
- **Affected outputs**: phase duration and `actual_runtime`; slow-rate runs
  without background traffic no longer end after two idle minutes.

## M13: No 20 s wait after peacetime; legacy evaluate() removed

- **Old**: After peacetime, `main.py` waited up to 20 s for `peacetime_done`,
  which only the unused legacy `evaluate()` could set, then logged
  "Peacetime cleanup timed out". Every run with peacetime lost 20 s between
  peacetime and wartime, during which background replay kept running unread.
- **New**: `run_peacetime()` sets `peacetime_done` itself when it returns.
  The legacy threaded `detection.evaluate.evaluate()` (dead code that called a
  nonexistent `reset()`) was removed.
- **Affected outputs**: `actual_runtime`; wartime now starts right after
  peacetime.

## M14: Log is read from offsets instead of being truncated

- **Old**: Wartime and every DNSExfiltrator config truncated `dnslogs.json`
  while DNS-collector kept it open without O_APPEND. The collector's next write
  landed at its old offset, leaving a NUL-filled prefix (1.6 MB in the audited
  log). The first event after each truncation was glued to the NULs and
  dropped, and lines read before the collector finished writing them were
  silently dropped as invalid JSON.
- **New**: The log is truncated only at setup, while the collector is stopped.
  Each phase records the end of the file (`readfile.log_end_offset()`) before
  starting traffic and reads from that byte offset. `readjson()` keeps
  incomplete lines until their newline arrives, skips a partial line at the
  start offset, strips NUL padding, and reopens the file if it is truncated or
  replaced.
- **Affected outputs**: line counts (no events lost at phase starts or on
  partial writes). Wartime in replay mode now begins with the events logged
  after the wartime start offset instead of an emptied file.

## C1: Expansion factor per configuration, passed in memory

- **Old**: `Detector.evaluate()` re-read `config.yaml` from disk and divided
  ULV by the single global `traffic.tunnel.expansion_factor` for every
  DNSExfiltrator config, including encoding sweeps.
- **New**: The factor is passed in memory (`run_wartime(..., expansion_factor)`
  → `Detector.evaluate(..., expansion_factor)`). DNSExfiltrator configs use an
  explicit `expansion_factor` key if given, otherwise the factor of their
  encoding: base32 1.6, base32map 4.8, base64 4/3, hex 2.0 (unknown: 1.0 with a
  warning). Replay mode keeps `traffic.tunnel.expansion_factor`. The value used
  is stored per detector as `expansion_factor`.
- **Affected outputs**: `estimated_real_traffic_up_bytes` for DNSExfiltrator
  configs whose encoding factor differs from the global value (all configs
  with the current `config.yaml`, which sets 1).

## C2: Profiles inherit the baseline; parameter names are validated

- **Old**: Sweep configs inherited the baseline, but profiles were filled from
  hard-coded defaults. Profiles without `domains` (all three in `config.yaml`)
  got an empty domain list and could not run, and every value a profile did
  not set (for example `throttle` 10 instead of the baseline's 0) silently
  differed from the baseline. Sweep parameter names were not checked; a typo
  re-ran the baseline under a sweep name.
- **New**: Baseline ← `DNSEXFIL_DEFAULTS`; sweeps and profiles ← filled
  baseline (deep-copied). Unknown parameter names in the baseline, a sweep's
  `parameter` or a profile raise `ValueError` at startup.
- **Affected outputs**: profile configs now run with the baseline's domains
  and unspecified values.

## C3: Every configuration leaves a results file with a status

- **Old**: A failed DNSExfiltrator readiness check skipped the whole wartime
  and wrote no results file; a config that hit a `continue` (server or client
  not starting) left no trace outside the console log.
- **New**: Every results file carries `metadata.run_status`
  (`{"status": "completed" | "skipped" | "failed", "reason": ...}`).
  Skipped or failed configs are written by `save_status_result()` as
  `results_<name>_<config>_<status>_<ts>.json` with an empty `detectors` list.
- **Affected outputs**: new key `run_status`; additional result files for
  skipped configs. Analysis scripts should filter on
  `run_status.status == "completed"`.

## C4: Results files are self-contained

- **Old**: A per-config results file identified its DNSExfiltrator parameters
  only through its file name and carried no code or tool versions.
- **New**: Every results file adds `metadata.dnsexfiltrator_config` (the filled
  config dict, including `expansion_factor_used`; `null` in replay mode) and
  `metadata.run_info`: git commit, dirty flag (tracked files), Python version,
  versions of tldextract, fqdn and PyYAML, Docker and Docker Compose versions.
- **Affected outputs**: new metadata keys only.
- **Not covered**: pcap/allowlist hashes, the tldextract public-suffix-list
  snapshot and Docker image digests (`:latest` tags) are still not recorded.

## C5: DNSExfiltrator domains are validated at startup

- **Old**: BIND forwarders were generated from
  `traffic.tunnel.tunneling_domains` only. A DNSExfiltrator config domain
  missing from that list was silently forwarded to the public resolver while
  the evaluation still used it as ground truth; empty domain lists ran anyway.
- **New**: `run_setup()` calls `validate_dnsexfil_domains()` before any Docker
  command. A config without domains or with a domain outside
  `traffic.tunnel.tunneling_domains` (case-insensitive) aborts the run with a
  `ValueError` listing every offending config.
- **Affected outputs**: none for valid configurations; invalid ones no longer
  start.

## C6: Wildcard replay also runs during wartime (decision: option A)

- **Old**: The wildcard pcap was replayed only from the peacetime phase. With
  peacetime 0 it started anyway (see M10) and was never stopped; wartime never
  started it, although the README says benign, wildcard and tunnel traffic run
  together.
- **New**: `run_wartime_phase()` starts the wildcard replay if it is enabled,
  or continues the one started in peacetime (via `start_replay()`, never a
  restart). Implementation and README now agree: all enabled sources run
  during wartime.
- **Affected outputs**: wartime benign-side metrics (FP, TN, FPR) of runs with
  `traffic.wildcard.enabled: true`.

## C7: Global allowlist parsing and path resolution

- **Old**: Every raw line of the file was an allowlist entry: no splitting, no
  lowercasing, no whitespace or comment handling. A raw Tranco CSV
  (`rank,domain`) matched nothing. The path was resolved against the working
  directory.
- **New**: `load_global_allowlist(path, base_dir)` resolves relative paths
  against the directory of `config.yaml`, raises `FileNotFoundError` for a
  missing file, and parses one domain per line, CSV (last domain-like column,
  e.g. Tranco `rank,domain`), tab/space-separated columns and `#` comments.
  Entries are lowercased without a trailing dot.
- **Affected outputs**: allowlist content (and thus FP/TN/FPR) whenever the
  file was not already a clean, lowercase, one-domain-per-line list.

## C8: Configuration keys match the documentation

- **Old**: README and `example_config.yaml` documented `timing.duration`
  (ignored: wartime silently defaulted to 60 min), peacetime in seconds with
  default 0 (code: minutes, default wartime/3), `detector.names` (code:
  `detectors.active`; all detectors ran), and `output.logdir`,
  `traffic.tunnel.docker`, `traffic.tunnel.toolname`,
  `allowlist.local_allowlist_dir`, none of which `main.py` read.
- **New**:
  - `timing.duration` or `detector.names` in the config abort the run with a
    hint to the correct key.
  - `output.logdir` is implemented (relative to `config.yaml`; default
    `results`).
  - `traffic.tunnel.docker`, `traffic.tunnel.toolname` and
    `allowlist.local_allowlist_dir` are not implemented and log an "ignored"
    warning.
  - README and `example_config.yaml` document the keys, units and defaults the
    code actually uses (peacetime in minutes, default wartime/3).
- **Affected outputs**: result location if `output.logdir` was set to a
  non-default path; configs using renamed keys no longer run.

## C9: Thesis/code deviations recorded

- No behavior change. Unused events from the old threaded controller were
  removed; deviations between thesis and code are recorded in `DEVRECORD.md`
  (controller design, missing "file exfiltrated" stop criterion as an open
  design decision, root simulator placement, leakage excluding the triggering
  query, FQDN filtering).

## D1: Durations are formatted in whole seconds

- **Old**: `format_duration()` operated on floats and produced strings such as
  `1.0m4.435775000000007s`.
- **New**: The value is rounded to whole seconds first (`1m4s`, `1m`, `2h`).
- **Affected outputs**: `metadata.experiment.wartime_duration`,
  `peacetime_duration`, `actual_runtime` strings and console output.

## D4: One reset API in the detector base class

- **Old**: `Detector.full_reset()` and `Detector.phase_reset()` duplicated the
  same field list (no shadowing, as the audit claim had it); the removed
  legacy `evaluate()` called a nonexistent `reset()`.
- **New**: `Detector.reset(clear_allowlist=False, reset_state=True)` is the
  single implementation; `__init__` uses it too. Callers:
  `generate_allowlists()` → `reset(clear_allowlist=True, reset_state=False)`
  (same effect as the old `full_reset()`), config boundaries in `main.py` →
  `reset()` (same effect as the old `phase_reset()` from M7).
- **Affected outputs**: none. API change: detectors calling `full_reset()` or
  `phase_reset()` must call `reset()` (no local detector does).

## D6: Domains are compared case-insensitively everywhere

- **Old**: `run_wartime()` lowercased domains for ground truth and the domain
  universe, but `process_line()`, allowlist checks and most detectors used the
  raw registered domain, and configured tunneling domains were not lowercased.
  A mixed-case query or config domain could split TP/FP accounting or never be
  labelled as tunnel traffic.
- **New**: `feature_extraction.get_registered_domain()` returns the normalized
  form (`normalize_domain()`: lowercase, no trailing dot). Configured tunneling
  domains (global and per DNSExfiltrator config) are normalized the same way;
  the global allowlist already is (C7).
- **Affected outputs**: none for all-lowercase traffic and configs (the
  audited log had no mixed-case names); otherwise TP/FP/FN and tunnel counts.
