# TunFrame documentation

Start with the [project README](../README.md) for setup and a first run. These pages cover the details.

| Page | Contents |
|---|---|
| [Architecture](architecture.md) | Docker services, networks, the simulated DNS hierarchy, how traffic is captured |
| [Run lifecycle](run-lifecycle.md) | Setup, peacetime, benign-only window, wartime windows, evaluation; how windows end; dashboard controls |
| [Configuration](configuration.md) | Every `config.yaml` key, validation rules, example configurations |
| [DNSExfiltrator](dnsexfiltrator.md) | The modified exfiltration tool: protocol, client and server options, how TunFrame drives it, known limitations |
| [Detectors and metrics](detectors.md) | Writing a detector, its lifecycle, every metric in the results |
| [Dashboard and report](dashboard.md) | The live dashboard and the static `report.html` |
| [Output](output.md) | The run directory and the fields of every results file |
| [Development](development.md) | Project structure, offline checks, the DNSExfiltrator test suites, adding a tunneling tool |

`docker_architecture.png` in this folder is the architecture diagram used on the [Architecture](architecture.md) page.
