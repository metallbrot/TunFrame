# Detectors and metrics

## Writing a detector

1. Create a directory under `detection/detectors/` named after the method, with a `detector.py` in it. (The contents of `detection/detectors/` are not versioned.)
2. In `detector.py`, subclass `Detector` from [`detection/detector_base/detector_base.py`](../detection/detector_base/detector_base.py) and implement `detect(logline)`. Add the registered domain (eTLD+1) to `self.alarms` when it should raise an alarm.
3. Optionally override `on_phase_reset()` to clear internal state (windows, trackers, sketches) when the detector is reset between windows (see [Lifecycle](#lifecycle)).

```python
from detection.detector_base.detector_base import Detector
from detection.detector_base.feature_extraction import get_registered_domain, extract_subdomain_string, shannon_entropy


class HighEntropy(Detector):
    def detect(self, logline: dict):
        if shannon_entropy(extract_subdomain_string(logline)) > 4.0:
            self.alarms.add(get_registered_domain(logline))
```

Only concrete `Detector` subclasses defined in `detector.py` itself are loaded; imported helper classes are ignored. `detectors.active` selects detectors by directory name. A listed detector that is missing or fails to load aborts the run; without the list, every detector is loaded and failing ones are skipped with their traceback.

### Log lines

`detect()` receives one parsed DNS-collector event per query or response the resolver saw, e.g. `dns.qname` (its subdomain labels in the case set by [`global.subdomain_case`](configuration.md#global), by default as captured), `dns.qtype`, `dns.flags.qr` (response), `dns.rcode`, `dns.resource-records.an` (answers), `network.query-ip`, `dnstap.timestamp-rfc3339ns`. [`detection/detector_base/feature_extraction.py`](../detection/detector_base/feature_extraction.py) has helpers for them, among others `get_fqdn`, `get_registered_domain`, `extract_subdomain_string`, `shannon_entropy`, `is_response`, `extract_record_type`, `extract_ttl`, `extract_packet_size`, `extract_query_ip`, `extract_timestamp`, `get_txt_content`, `query_payload_bytes` and `answer_payload_bytes`.

Registered domains are computed with `tldextract` against the ICANN section of the Public Suffix List snapshot bundled with the pinned `tldextract` version (private suffixes are not suffixes); ground truth, allowlists and alarms all use this key.

### What reaches `detect()`

Events without a query name or with an invalid name are skipped for all detectors. For every other line, per detector:

1. If its registered domain is in the detector's **allowlist**, `detect()` is not called. Tunnel traffic skipped this way is counted separately (`allowlisted_tunnel_*`) and counts as leaked.
2. If the detector has **already flagged** the domain in the current phase, `detect()` is not called either; the decision for that domain is final (counted as `alarmed_lines_skipped`).
3. Otherwise `detect()` runs and its time is measured.

## Lifecycle

| Moment | What happens to each detector |
| --- | --- |
| Run start | Fresh instance; empty allowlist |
| Peacetime | Sees all lines as benign |
| End of peacetime | Its alarms become its allowlist, together with the global allowlist. Alarms and counters are cleared; internal state is kept |
| Benign-only window | Before it: reset (allowlist kept, `on_phase_reset()` called) if a DNSExfiltrator configuration follows directly, otherwise unchanged. After it: alarms and counters cleared, state kept |
| Tunnel replay window | Continues from the previous phase |
| Each DNSExfiltrator configuration | Reset before it: alarms, counters and timing cleared, allowlist kept, `on_phase_reset()` called |

Alarms are therefore always per window: a domain flagged in one window is inspected again in the next.

## Metrics

After every window `Detector.evaluate()` classifies every registered domain seen in that window (the window's domain universe; domains of other phases never count):

| Class | Domains |
| --- | --- |
| TP | flagged tunneling domains |
| FP | flagged domains that are not tunneling domains |
| FN | tunneling domains seen in the window but not flagged |
| TN | all other domains seen in the window |

Tunneling domains are the window's ground truth (see [Run lifecycle](run-lifecycle.md#4-tunnel-windows-wartime)) that actually appeared in it; if no tunnel traffic appeared, there are none. Alarms on allowlisted domains are discarded.

From these: `precision`, `recall` (= `tpr`), `f1`, `fpr` = FP / (FP + TN), `accuracy`. All are 0 when undefined. The lists `alarms_raised`, `true_positives_list`, `false_positives_list` and `false_negatives_list` are stored as well.

### Leakage

| Field | Meaning |
| --- | --- |
| `traffic_volume_up_bytes` | Query payload (all subdomain label bytes) of tunnel queries that passed before the detector flagged their domain; the alarming line itself is not counted |
| `traffic_volume_down_bytes` | Answer RDATA bytes of tunnel responses before the alarm |
| `allowlisted_tunnel_*` | Lines, queries, responses and bytes of tunnel traffic that the allowlist kept from the detector |
| `net_up_bytes` | DNSExfiltrator windows: file bytes of the unique data chunks that passed before the alarm, decoded exactly from the traffic (see [DNSExfiltrator](dnsexfiltrator.md#what-the-metrics-read-from-the-traffic)); `net_volume_method: "decoded"` |
| `estimated_real_traffic_up_bytes` | Equal to `net_up_bytes` in DNSExfiltrator windows; otherwise `traffic_volume_up_bytes / expansion_factor` (`net_volume_method: "expansion_factor"`) |
| `ulv_percent` | Uplink leaked share. DNSExfiltrator: `net_up_bytes` over the file size the client announced (`ulv_basis: "file"`), i.e. how much of the zipped, encrypted file left before the alarm. Otherwise the share of the window's raw tunnel uplink (`ulv_basis: "tunnel_payload"`) |
| `dlv_percent` | Downlink leaked share of the window's raw tunnel answer bytes |

Allowlisted tunnel traffic counts as leaked in `ulv_percent` and `dlv_percent`. Both are `null` when the window had no tunnel traffic to relate to.

### Benign-only window

There is no tunnel traffic, so every alarm is a false positive and FP, TN and `fpr` are the meaningful figures. Each detector additionally gets `fp_domains_per_hour`: falsely flagged registered domains per hour of the window.

### Performance

`runtime` (seconds spent in `detect()`), `avg_process_time_ms` (per `detect()` call), `processed_lines`, `detect_calls`, `alarmed_lines_skipped`, `total_loglines`, plus the allowlist size and the detector-specific part of the allowlist (`unique_allowlist`).
