# TunFrame

TunFrame is a benchmarking framework for evaluating DNS tunneling detection methods against adversarial evasion techniques. It runs an isolated DNS environment in Docker, generates benign and tunnel traffic, feeds every query and response to the detectors under test, and measures how well and how early they detect the tunnel and how much data leaks before they do.

> Developed as part of the bachelor's thesis *"Evaluating adversarial evasion of DNS Tunneling Detection"*.

## What a run does

```text
setup → peacetime → benign-only window → tunnel replay window → DNSExfiltrator configurations → evaluation
```

- **Peacetime** replays benign traffic; whatever a detector flags becomes part of its allowlist.
- **Benign-only window** replays benign traffic only: every alarm is a false positive, so it measures each detector's false positive rate without adversarial load.
- **Tunnel replay window** replays a recorded tunnel pcap alongside the benign traffic.
- **DNSExfiltrator configurations** exfiltrate a file live with a modified [DNSExfiltrator](documentation/dnsexfiltrator.md), one window per configuration (baseline, parameter sweeps, attacker profiles), alongside the benign traffic.
- **Evaluation** reports per window and detector the domain-level confusion matrix, precision, recall, F1, FPR, and the share of the file that left before the first alarm (ULV %).

Every phase is optional. A live dashboard follows the run, and every run ends with a static report.

## Prerequisites

- Python ≥ 3.9
- Docker with Docker Compose
- Optional: `editcap` (part of Wireshark) on the host, so later windows continue the benign pcap after the part replayed in peacetime

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp example_config.yaml config.yaml
```

Then:

1. Put your pcaps (benign traffic, optionally a tunnel recording) into `pcaps/`.
2. For DNSExfiltrator runs, put the files to exfiltrate into `docker/dnsexfiltrator-client/data/` (e.g. `synthetic_cc_data_100.csv`).
3. Add your detectors under `detection/detectors/<name>/detector.py` (see [Detectors and metrics](documentation/detectors.md)).
4. Optionally provide a global allowlist, e.g. the Tranco list in `allowlists/`.
5. Edit `config.yaml` (see [Configuration](documentation/configuration.md)).

## Running

```bash
python3 main.py                     # runs the experiment described in config.yaml (fixed path, next to main.py)
python3 scripts/dashboard.py        # live dashboard on http://127.0.0.1:8050 (second terminal)
```

Results go to `results/<name>_<timestamp>/`: one JSON file per window, the run state, the live metrics, the logs, charts and `report.html` (see [Output](documentation/output.md)).

Offline checks of the harness (no Docker needed):

```bash
python3 scripts/repro_harness.py
```

## Documentation

| Page | Contents |
| --- | --- |
| [Architecture](documentation/architecture.md) | Docker services, networks, the simulated DNS hierarchy |
| [Run lifecycle](documentation/run-lifecycle.md) | Every phase and window, how windows end, dashboard controls |
| [Configuration](documentation/configuration.md) | Every `config.yaml` key, validation, examples |
| [DNSExfiltrator](documentation/dnsexfiltrator.md) | The modified exfiltration tool and how TunFrame drives it |
| [Detectors and metrics](documentation/detectors.md) | Writing a detector, its lifecycle, every metric |
| [Dashboard and report](documentation/dashboard.md) | The live dashboard and `report.html` |
| [Output](documentation/output.md) | The run directory and the results files |
| [Development](documentation/development.md) | Project structure, tests, adding a tunneling tool |

## Credits

The exfiltration tool is [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) by Arno0x, as modified by Kristijan Žiža for Žiža, K., Tadić, P. & Vuletić, P., *DNS exfiltration detection in the presence of adversarial attacks and modified exfiltrator behaviour*, Int. J. Inf. Secur. (2023), <https://doi.org/10.1007/s10207-023-00723-w>, and further adapted for TunFrame. Please cite the paper if you use the tool.
