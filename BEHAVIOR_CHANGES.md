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
