"""Live monitoring of a run for the dashboard.

``MetricsSampler`` appends one JSON sample every ``interval`` seconds to the
run's ``metrics.jsonl``: DNS rates from the collector log, response codes and
top domains, the DNSExfiltrator transfer progress from the server log, and CPU
and memory of this process and of the Docker containers.

``ControlWatcher`` reads ``control.json`` (written by the dashboard) and hands
new requests to a callback.

Both run in daemon threads, only read the logs, and never influence what the
detectors see.
"""
import json
import os
import re
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from detection.detector_base.feature_extraction import get_fqdn, get_registered_domain, is_response
from detection.detector_base.readfile import log_end_offset, readjson

_ANSI = re.compile(rb"\x1b\[[0-9;]*m")
_PERCENT = re.compile(rb"\]\s*([0-9]+(?:\.[0-9]+)?)%")
_FILE_SIZE = re.compile(rb"File size: ([0-9]+) bytes")
_SAVED = b"File saved successfully"
_MEM_UNITS = {"B": 1 / 1e6, "KiB": 1024 / 1e6, "MiB": 1.048576, "GiB": 1073.741824,
              "kB": 1e-3, "MB": 1.0, "GB": 1e3}


def parse_mem_mb(text: str) -> float:
    """Parse the used part of docker stats' MemUsage ("12.3MiB / 7.6GiB") in MB."""
    match = re.match(r"\s*([0-9.]+)\s*([A-Za-z]+)", text or "")
    if not match:
        return 0.0
    return float(match.group(1)) * _MEM_UNITS.get(match.group(2), 1.0)


def container_stats(names) -> dict:
    """CPU percent and memory (MB) per container, from one ``docker stats`` call."""
    if not names:
        return {}
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", *names],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    stats = {}
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        try:
            cpu = float(str(row.get("CPUPerc", "0")).rstrip("%") or 0)
        except ValueError:
            cpu = 0.0
        stats[row.get("Name", "?")] = {"cpu": round(cpu, 1), "mem_mb": round(parse_mem_mb(row.get("MemUsage")), 1)}
    return stats


class ExfilProgress:
    """Follow the DNSExfiltrator server log from a byte offset and report progress."""

    def __init__(self, server_log: Path, start_offset: int):
        self.path = Path(server_log)
        self.offset = start_offset
        self.percent = 0.0
        self.file_size = None
        self.saved = False
        self._tail = b""

    def poll(self) -> dict:
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
        except OSError:
            chunk = b""
        if chunk:
            self.offset += len(chunk)
            text = _ANSI.sub(b"", self._tail + chunk)
            self._tail = text[-200:]  # a marker may straddle two reads
            percents = _PERCENT.findall(text)
            if percents:
                self.percent = max(self.percent, float(percents[-1]))
            size = _FILE_SIZE.findall(text)
            if size:
                self.file_size = int(size[-1])
            if _SAVED in text:
                self.saved = True
                self.percent = 100.0
        return {"percent": round(self.percent, 1), "file_size": self.file_size, "saved": self.saved}


class MetricsSampler:
    """Write a metrics sample every ``interval`` seconds to ``report.metrics_path``.

    Args:
        report: RunReport of the run (state for phase/config, output path).
        dns_log: DNS collector log (JSON lines).
        tunnel_domains: Registered tunneling domains (ground truth).
        containers: Docker container names for resource statistics.
        interval: Seconds between samples.
        resource_interval: Seconds between ``docker stats`` calls.
    """

    TOP_DOMAINS = 8

    def __init__(self, report, dns_log: Path, tunnel_domains, containers,
                 interval: float = 2.0, resource_interval: float = 6.0):
        self.report = report
        self.dns_log = Path(dns_log)
        self.tunnel_domains = set(tunnel_domains or ())
        self.containers = list(containers)
        self.interval = interval
        self.resource_interval = resource_interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._exfil = None
        self._containers = {}
        self._threads = [threading.Thread(target=self._run, daemon=True),
                         threading.Thread(target=self._run_resources, daemon=True)]
        self._started = time.monotonic()
        self._cpu = (time.monotonic(), sum(os.times()[:2]))
        self.totals = Counter()
        self.rcodes = Counter()
        self.top = Counter()
        self.unique = set()

    def start(self) -> "MetricsSampler":
        for thread in self._threads:
            thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=20)

    def watch_exfil(self, server_log=None, start_offset: int = 0) -> None:
        """Follow transfer progress from ``start_offset``; ``None`` stops following."""
        with self._lock:
            self._exfil = ExfilProgress(server_log, start_offset) if server_log else None

    # -- sampling -----------------------------------------------------------

    def _host(self) -> dict:
        now, cpu = time.monotonic(), sum(os.times()[:2])
        last_now, last_cpu = self._cpu
        self._cpu = (now, cpu)
        cpu_percent = 100.0 * (cpu - last_cpu) / max(now - last_now, 1e-6)
        rss_mb = None
        try:
            out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())],
                                 capture_output=True, text=True, timeout=5, check=False).stdout.strip()
            rss_mb = round(int(out) / 1024, 1) if out else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        return {"cpu": round(cpu_percent, 1), "rss_mb": rss_mb}

    def _run_resources(self) -> None:
        while not self._stop.is_set():
            stats = container_stats(self.containers)
            with self._lock:
                self._containers = stats
            self._stop.wait(self.resource_interval)

    def _count(self, event: dict, interval: Counter) -> None:
        if get_fqdn(event) is None:
            return
        domain = get_registered_domain(event)
        tunnel = domain in self.tunnel_domains
        if is_response(event):
            interval["r"] += 1
            interval["tr"] += tunnel
            self.rcodes[str((event.get("dns") or {}).get("rcode", "?"))] += 1
        else:
            interval["q"] += 1
            interval["tq"] += tunnel
            if domain:
                self.top[domain] += 1
                self.unique.add(domain)

    def _run(self) -> None:
        reader = readjson(str(self.dns_log), start_offset=log_end_offset(self.dns_log))
        last = time.monotonic()
        try:
            while not self._stop.is_set():
                interval = Counter()
                deadline = time.monotonic() + self.interval
                while time.monotonic() < deadline and not self._stop.is_set():
                    event = next(reader)
                    if event is None:
                        self._stop.wait(min(0.2, max(0.0, deadline - time.monotonic())))
                        continue
                    self._count(event, interval)
                now = time.monotonic()
                self._write(interval, now - last)
                last = now
        finally:
            reader.close()

    def _write(self, interval: Counter, seconds: float) -> None:
        self.totals.update(interval)
        with self._lock:
            exfil = self._exfil.poll() if self._exfil else None
            containers = dict(self._containers)
        state = self.report.state
        seconds = max(seconds, 1e-6)
        sample = {
            "t": datetime.now().isoformat(timespec="seconds"),
            "elapsed": round(time.monotonic() - self._started, 1),
            "phase": state.get("phase"),
            "config": state.get("phase_detail") or None,
            "dns": {
                "queries": interval["q"], "responses": interval["r"],
                "tunnel_queries": interval["tq"], "tunnel_responses": interval["tr"],
                "qps": round(interval["q"] / seconds, 2),
                "tunnel_qps": round(interval["tq"] / seconds, 2),
                "total_queries": self.totals["q"], "total_tunnel_queries": self.totals["tq"],
                "unique_domains": len(self.unique),
            },
            "rcodes": dict(self.rcodes),
            "top_domains": [[d, n, d in self.tunnel_domains] for d, n in self.top.most_common(self.TOP_DOMAINS)],
            "exfil": exfil,
            "host": self._host(),
            "containers": containers,
        }
        with open(self.report.metrics_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample) + "\n")


class ControlWatcher:
    """Hand new dashboard requests from ``control.json`` to ``on_action``.

    The dashboard writes ``{"id": n, "action": ..., "requested": ...}``; every
    id is handled once and acknowledged in run.json (``control``).
    """

    ACTIONS = ("skip_config", "stop_run")

    def __init__(self, report, on_action, poll_interval: float = 0.5):
        self.report = report
        self.on_action = on_action
        self.poll_interval = poll_interval
        self._last_id = self._read().get("id", 0)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "ControlWatcher":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def _read(self) -> dict:
        try:
            return json.loads(self.report.control_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval):
            request = self._read()
            request_id = request.get("id", 0)
            if not isinstance(request_id, int) or request_id <= self._last_id:
                continue
            self._last_id = request_id
            action = request.get("action")
            accepted = action in self.ACTIONS
            if accepted:
                self.on_action(action)
            self.report.update(control={
                "id": request_id, "action": action, "accepted": accepted,
                "handled": datetime.now().isoformat(timespec="seconds"),
            })
