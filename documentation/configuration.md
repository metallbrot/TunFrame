# Configuration

All settings are in `config.yaml` in the project root (not versioned); [`example_config.yaml`](../example_config.yaml) is a complete template. Durations are in **minutes**. Relative paths are resolved against the directory of `config.yaml`, except `traffic.pcap_path`, which is relative to the project root.

## Global

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `global.name` | string | Name of the run, used for the run directory | `experiment` |
| `global.description` | string | Free text, stored with the results | none |
| `global.public_resolver` | IP | Resolver for all names that are not routed to the tunnel server | `1.1.1.1` |
| `global.subdomain_case` | string | Letter case of the subdomain labels (left of the registered domain) in the events the detectors receive, emulating where they observe DNS: `preserve` (as captured: the case the client sent, which is what a sensor on the client-to-resolver hop sees, like TunFrame's collector), `lowercase` (a log pipeline that normalises names), `uppercase` (control condition), or `0x20` (each letter's case randomised, as seen upstream of a resolver using DNS 0x20 encoding, e.g. at the egress or authoritative side). The 0x20 pattern is derived from the name, so a name always gets the same pattern (reproducible runs, query and response agree). The traffic itself is not changed. Ground truth, allowlists and payload accounting compare case-insensitively. Write `"0x20"` quoted; an unquoted `0x20` is read as the number 32 and also accepted. Any other value aborts the run | `preserve` |

## Detectors

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `detectors.active` | list of strings | Directory names under `detection/detectors/` to load. A listed detector that is missing or fails to load aborts the run | all detectors (failing ones are skipped) |

## Timing

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `timing.wartime_duration` | number | Maximum length of each tunnel window (the tunnel replay window and every DNSExfiltrator configuration) | `60` |
| `timing.peacetime_duration` | number | Length of peacetime, in which the detectors' allowlists are learned; `0` disables it | `wartime_duration / 3` |
| `timing.benign_only_duration` | number | Length of the benign-only window between peacetime and the tunnel windows (no tunnel traffic; measures the FPR without adversarial load); `0` disables it. Use the value of `timing.wartime_duration` for a window as long as each tunnel window | `0` |

See [Run lifecycle](run-lifecycle.md) for what happens in each phase.

## Allowlist

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `allowlist.global_allowlist_path` | path | Global allowlist, e.g. the Tranco top 1M. One domain per line, CSV such as `rank,domain`, tab or space separated columns, `#` comments. Entries are reduced to their registered domain (`ads.example.net` allowlists `example.net`). A missing file aborts the run | none |

Lines of allowlisted domains never reach a detector. Do not allowlist a tunneling domain: it could never be detected (its traffic is reported separately and counts as leaked).

## Traffic

### Benign traffic

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `traffic.pcap_path` | path | Directory with all pcap files, mounted into the replayer | `./pcaps` |
| `traffic.benign.enabled` | bool | Replay benign DNS traffic | `false` |
| `traffic.benign.pcap` | string | File name of the benign pcap in `pcap_path` | — |
| `traffic.benign.pps` | int | Replay rate in packets per second; unset or `0` keeps the original timing | original timing |

### Tunnel traffic

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `traffic.tunnel.replay` | bool | Replay `traffic.tunnel.pcap` in its own window, `tunnel_replay`, after the benign-only window and before the DNSExfiltrator configurations. Can be combined with DNSExfiltrator | `false` |
| `traffic.tunnel.pcap` | string | File name of the tunnel pcap | — |
| `traffic.tunnel.pps` | int | Replay rate in packets per second | original timing |
| `traffic.tunnel.tunneling_domains` | list of strings | The tunnel domains contained in the replayed pcap: the ground truth of the tunnel replay window. Required with `replay`, ignored otherwise (a log line says so). Never used for the resolver configuration | `[]` |
| `traffic.tunnel.tunnel_server_ip` | IP | Address the simulated TLD forwards the routed domains to; must lie in `192.168.0.0/16` (`server-network`) and match the tunnel server container | `192.168.4.4` |
| `traffic.tunnel.expansion_factor` | number | Ratio of encoded query characters to payload bytes of the replayed tunnel, used to estimate its net volume (tunnel replay window only) | `1` |

Each tunneling domain must be a registered domain (eTLD+1 per the ICANN section of the Public Suffix List; private suffixes such as `duckdns.org` do not count), e.g. `example.co.uk`, not `tunnel.example.co.uk`.

### DNSExfiltrator

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `dnsexfiltrator.enabled` | bool | DNSExfiltrator mode: generate live tunnel traffic, one window per configuration | `false` |
| `dnsexfiltrator.stop_on_transfer_complete` | bool | End a window once the server reports the file as saved; `timing.wartime_duration` stays the upper bound | `true` |
| `dnsexfiltrator.baseline` | mapping | The configuration named `baseline`; the base of all sweeps and profiles | defaults below |
| `dnsexfiltrator.sweeps` | list | One configuration per value of one parameter, see below | `[]` |
| `dnsexfiltrator.profiles` | list | Named configurations that change several parameters at once | `[]` |

Parameters of a configuration and their defaults (see [DNSExfiltrator](dnsexfiltrator.md) for their effect on the traffic):

| Parameter | Client option | Description | Default |
| --- | --- | --- | --- |
| `file` | file argument | File to exfiltrate, in the client's `/data` (`docker/dnsexfiltrator-client/data/`); an absolute host path is copied there (replacing a different file of the same name) | `/data/synthetic_cc_data_100.csv` |
| `password` | password argument | RC4 key shared by client and server | `tunframe` |
| `throttle` | `t=` | Fixed wait between queries, ms | `10` |
| `throttle_random` | `tr=` | Additional random wait, `0` to n ms | `0` |
| `label_max_size` | `l=` | Maximum label length, 1–63. `base32map` needs at least 12, `base32` and `hex` at least 4 | `63` |
| `encoding` | `e=` | `base32`, `base32map` or `hex` (`base64` is no longer supported) | `base32` |
| `dilution` | `dil=` | Dilution queries before each data query | `0` |
| `domains` | domain file | Domains the transfer is spread over, at least one, each a registered domain. They are routed to the tunnel server and are the configuration's ground truth | `[]` |
| `expansion_factor` | — | Only used if the net volume cannot be decoded from the traffic | derived from `encoding`: base32 1.6, base32map 4.8, hex 2.0 |

**Baseline.** Inherits every unset parameter from the defaults. If the `baseline` block is missing or empty, no `baseline` configuration runs (sweeps and profiles still inherit the defaults); if there are no configurations at all, one configuration named `default` runs with the defaults.

**Sweeps.** `{name, parameter, values}`: one configuration per value, named `<name>_<parameter>_<value>`, with that parameter set on top of the baseline. The extra parameter `domain_count` spreads the transfer over the first N domains of the sweep's own `domains` list (default: the baseline's `domains`).

**Profiles.** `{name, <parameters>}`: unset parameters come from the baseline.

The configurations run in the order baseline, sweeps, profiles; the dashboard groups them the same way.

## Output

| Key | Type | Description | Default |
| --- | --- | --- | --- |
| `output.logdir` | path | Directory for the run directories | `results` |

## Validation

The run aborts before any container starts when

- a renamed key is set: `timing.duration` (use `timing.wartime_duration`), `detector.names` (use `detectors.active`),
- `traffic.tunnel.replay` is set without `traffic.tunnel.tunneling_domains`, or a tunneling domain is not a registered domain,
- a DNSExfiltrator configuration has no domains or a domain that is not a registered domain,
- a DNSExfiltrator block uses an unknown parameter, a sweep an unknown `parameter`, or a `domain_count` outside 1 to the size of its domain list,
- a sweep has a key other than `name`, `parameter`, `values` and `domains`, or no non-empty `values` list,
- two DNSExfiltrator configurations get the same name (e.g. a profile named `baseline`, or two sweeps that produce the same `<name>_<parameter>_<value>`),
- `timing.benign_only_duration` is negative, or a DNSExfiltrator configuration is named `benign_only` (with a benign-only window) or `tunnel_replay` (with a tunnel replay),
- a detector listed in `detectors.active` is missing or fails to load,
- the global allowlist file does not exist.

The keys `traffic.wildcard` (wildcard pcaps are no longer supported; merge such traffic into the benign pcap), `traffic.tunnel.docker`, `traffic.tunnel.toolname` and `allowlist.local_allowlist_dir` are ignored with a warning. Any other key that TunFrame does not read (usually a typo such as `timing.wartime_duraton`) is ignored with a warning too, so check the start of the console log.

## Examples

### Tunnel replay without benign traffic

```yaml
timing:
  wartime_duration: 120
  peacetime_duration: 0

allowlist:
  global_allowlist_path: "./allowlists/tranco.txt"

traffic:
  pcap_path: "./pcaps"
  tunnel:
    replay: true
    pcap: "tunnel.pcap"
    tunneling_domains: ["example.com"]
```

### Every phase: peacetime, benign-only window, tunnel replay, DNSExfiltrator

Start from `example_config.yaml` (DNSExfiltrator and benign traffic enabled) and set

```yaml
timing:
  wartime_duration: 30         # per tunnel window
  peacetime_duration: 20
  benign_only_duration: 30     # as long as one tunnel window

traffic:
  tunnel:
    replay: true               # tunnel_replay window before the DNSExfiltrator configurations
    pcap: "iodine.pcap"
    tunneling_domains: ["example.com"]
```

### Benign-only run

Measures the false positive rate without adversarial load only; the run ends after the benign-only window.

```yaml
timing:
  peacetime_duration: 20
  benign_only_duration: 60

allowlist:
  global_allowlist_path: "./allowlists/tranco.txt"

traffic:
  pcap_path: "./pcaps"
  benign:
    enabled: true
    pcap: "benign.pcap"
    pps: 20
  tunnel:
    replay: false

dnsexfiltrator:
  enabled: false
```
