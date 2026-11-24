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
