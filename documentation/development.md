# Development

## Project structure

```text
TunFrame/
├── main.py                        # Controller: setup, phases, windows, evaluation, results
├── example_config.yaml            # Template for config.yaml (config.yaml itself is not versioned)
├── requirements.txt
├── config/
│   ├── dns_config_generator.py    # BIND configs and rndc keys from the templates
│   └── templates/                 # resolver, root and TLD named.conf templates
├── detection/
│   ├── evaluate.py                # Detector loading, peacetime and wartime loops, allowlists
│   ├── exfil_payload.py           # Decodes DNSExfiltrator traffic: init, data, dilution, net volume
│   ├── reporting.py               # Run directory: run.json, run.log, configs/
│   ├── monitoring.py              # Live metrics (metrics.jsonl) and dashboard control requests
│   ├── report_charts.py           # Charts and report.html of a run
│   ├── detector_base/
│   │   ├── detector_base.py       # Detector base class and metrics
│   │   ├── feature_extraction.py  # Helpers for DNS-collector events, eTLD+1 handling
│   │   ├── metrics.py             # TPR / FPR helpers
│   │   └── readfile.py            # Follows the DNS-collector JSON log
│   └── detectors/                 # One directory per detection method (not versioned)
├── docker/
│   ├── docker-compose.yml         # Resolver, simulated root/TLD, collector, replayer, DNSExfiltrator
│   ├── dnsexfiltrator-client/     # Client source and image; data/ holds the files to exfiltrate
│   ├── dnsexfiltrator-server/     # Server image; volume/ holds the server script
│   ├── dnsexfiltrator-tests/      # Protocol test suites for the tool
│   ├── dns-collector/             # Collector config; logs/ holds dnslogs.json
│   └── pcap-replayer/             # tcpreplay image
├── documentation/                 # This documentation
└── scripts/
    ├── dashboard.py               # Live dashboard (http://127.0.0.1:8050)
    ├── dashboard_static/          # Dashboard page, styles and charts
    └── repro_harness.py           # Offline checks of the harness (no Docker)
```

## Offline checks

```bash
python3 scripts/repro_harness.py
```

Runs about sixty checks against the controller, the detector base class, the metrics, the run directory, the report, the monitoring and the dashboard server without Docker. Each prints `PASS` or `FAIL` with the values it saw; the script exits non-zero if any check fails. Run it after every change to `main.py`, `detection/` or `scripts/`.

## DNSExfiltrator test suites

`docker/dnsexfiltrator-tests/` holds two suites from the protocol review of the tool:

```bash
cd docker/dnsexfiltrator-tests
python3 -m unittest test_contract_differential -v   # 22 contract tests
python3 test_phase_d_fixes.py                        # 5 checks of the fixes
```

Both are self-contained Python re-implementations of the client and server logic; they do not run the C# client or the server script. They were written before base64 was removed and before the sequence number moved into its own label, so they model that earlier protocol. See the suite's [README](../docker/dnsexfiltrator-tests/README.md).

## Dependencies

`tldextract` is pinned in both `requirements.txt` and `docker/dnsexfiltrator-server/requirements.txt`: the Public Suffix List snapshot bundled with that version defines the registered domains (eTLD+1) used for ground truth, allowlists, alarms and the server's domain check. Change both pins together.

Optional on the host: `editcap` (Wireshark) to cut the peacetime part off the benign pcap, see [Run lifecycle](run-lifecycle.md#2-peacetime-optional).

## Adding a tunneling tool

Pre-recorded tunnel traffic needs no integration: replay it in the tunnel replay window (`traffic.tunnel.replay`, `traffic.tunnel.pcap`, `traffic.tunnel.tunneling_domains`).

A live tool needs:

1. separate client and server images,
2. both containers in `docker/docker-compose.yml`, the client on `client-network` (querying the resolver at `172.16.0.2`), the server on `server-network` at `traffic.tunnel.tunnel_server_ip` (within `192.168.0.0/16`),
3. integration in `main.py` like DNSExfiltrator: its domains passed to `generate_all_configs` so they are routed to the server, a window per run of the tool with the tool's domains as ground truth, and starting and stopping the tool per window.

`traffic.tunnel.tunneling_domains` does not route anything; it only declares the domains of a replayed pcap.
