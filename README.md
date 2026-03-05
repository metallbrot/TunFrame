# TunFrame
This repository contains the code and documentation for TunFrame, a framework designed to benchmark DNS tunneling detection methods against evasion techniques. The goal of TunFrame is to provide a standardized environment for evaluating the effectiveness of various detection methods under comparable conditions. The framework was developed for the bachelor's thesis "Evaluating adversarial evasion of DNS Tunneling Detection".

## Setup

### 1. Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the framework

Edit the `config.yaml` file to specify the parameters for your test run. Refer to the "Configuring the Framework" section below for details on each parameter.

## Adding a Detection Method

To add a new DNS tunneling detection method to TunFrame, follow these steps:

1. Create a new directory under `detection/detectors` with the name of your method.
2. Implement the detection logic in a Python file within that directory. It should follow the interface defined in `detection/detector_base/detector_base.py`.

## Adding a Tunneling Tool

To add a new DNS tunneling tool to TunFrame, follow these steps:

1. Containerize your tunneling tool using Docker, creating separate containers for the client and server.
2. Specify the server domain(s) and IP address in the `config.yaml` file.
3. Add the docker images to the `docker-compose.yaml` file, ensuring they are connected to the appropriate networks (e.g., "client-network" for the client and "server-network" for the server).

## Configuring the Framework

The framework can be configured using the `config.yaml` file.

### Global Settings

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `global.name` | string | Name of test run | `TunFrame` |
| `global.description` | string | Description of test run | `No description.` |
| `global.public_resolver` | IP | IP address of public resolver used for resolving non-tunneling DNS requests | `1.1.1.1` |

### Timing Settings

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `timing.duration` | int | Duration of test run in seconds | `100` |
| `timing.peacetime_duration` | int | Duration of peacetime (without tunneling) in seconds before starting experiments | `0` |

### Allowlist Settings

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `allowlist.global_allowlist_path` | path | Path to global allowlist file (e.g., Tranco top domains) | `./allowlists/tranco.txt` |
| `allowlist.local_allowlist_dir` | path | Directory containing local allowlist files for different detector configurations | `./allowlists/local` |

### Traffic Settings

#### General

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `traffic.pcap_path` | path | Directory containing PCAP files | `./pcaps` |

#### Benign Traffic

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `traffic.benign.enabled` | bool | Enable benign DNS traffic injection | `false` |
| `traffic.benign.pcap` | string | Filename of benign traffic PCAP | `benign.pcap` |
| `traffic.benign.pps` | int | Packets per second for benign traffic replay | `10000` |

#### Wildcard Traffic

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `traffic.wildcard.enabled` | bool | Enable wildcard DNS traffic injection | `false` |
| `traffic.wildcard.pcap` | string | Filename of wildcard DNS PCAP | `wildcard.pcap` |
| `traffic.wildcard.pps` | int | Packets per second for wildcard traffic replay | `1000` |

#### Tunnel Traffic

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `traffic.tunnel.replay` | bool | Enable replay mode (replay from PCAP file instead of live generation) | `false` |
| `traffic.tunnel.docker` | bool | Enable Docker-based tunneling tool execution | `false` |
| `traffic.tunnel.pcap` | string | Filename of DNS tunneling traffic PCAP (used in replay mode) | `tunnel.pcap` |
| `traffic.tunnel.pps` | int | Packets per second for tunnel traffic replay | `10` |
| `traffic.tunnel.toolname` | string | Name of DNS tunneling tool used (e.g., `dnscat2`, `iodine`, `dnsexfiltrator`) | `Tunnel` |
| `traffic.tunnel.tunneling_domains` | list[string] | List of domains used by the tunneling tool | `["tunnel.com"]` |
| `traffic.tunnel.tunnel_server_ip` | IP | IP address of the DNS tunnel server (must be in `192.168.0.0/16` range) | `192.168.3.3` |
| `traffic.tunnel.expansion_factor` | int | Data expansion factor for DNS tunneling (applied to tunneled data size) | `1` |

### Output Settings

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `output.logdir` | path | Directory for storing benchmark results and logs | `results` |

## Running the Framework

To run the TunFrame framework, execute the following command:

```bash
(.venv) python3 main.py
```

![TunFrame Architecture](./documentation/docker_architecture.svg)
