"""Per-run report directory.

Every run writes one directory ``<results>/<name>_<YYYYmmdd-HHMMSS>/``::

    run.json             run state, updated live: phase, progress, one entry per
                         window with its status and detector summary
    run.log              console log of the run (without progress lines)
    metrics.jsonl        one sample every few seconds: DNS rates, response codes,
                         top domains, exfiltration progress, CPU and memory
    control.json         requests from the dashboard (skip configuration, stop run)
    exfil-server.log     DNSExfiltrator server output of the run (copied at the end)
    exfil-client.log     DNSExfiltrator client output of the run (copied at the end)
    configs/<name>.json  full results of one window (benign_only, tunnel_replay,
                         one per DNSExfiltrator configuration, or wartime)
    charts/*.png         static charts (written at the end of the run)
    report.html          static report embedding the charts

``run.json`` is replaced atomically, so the dashboard can read it while the
run is still going.
"""
import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path

# Per-detector values copied into run.json; the full result stays in configs/.
SUMMARY_KEYS = (
    "precision", "recall", "f1", "fpr", "accuracy",
    "tp", "fp", "tn", "fn",
    "traffic_volume_up_bytes", "traffic_volume_down_bytes",
    "estimated_real_traffic_up_bytes", "net_up_bytes", "net_volume_method",
    "ulv_percent", "ulv_basis", "dlv_percent",
    "runtime", "avg_process_time_ms", "processed_lines",
    "fp_domains_per_hour", "allowlist_size", "total_alarms",
)
# Falsely flagged domains copied into run.json per detector (the full list is in configs/).
FALSE_POSITIVE_SAMPLE = 10

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def slug(text) -> str:
    """Return ``text`` as a file-name-safe string."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text)).strip("_") or "run"


def write_json_atomic(path: Path, data) -> None:
    """Write JSON so that readers never see a half-written file."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)


def summarize_detectors(results) -> list:
    """Reduce full detector results to the values shown in run.json."""
    summary = []
    for result in results or []:
        row = {"detector": result.get("detector_name", "unknown")}
        row.update({key: result.get(key) for key in SUMMARY_KEYS})
        row["false_positives_sample"] = sorted(result.get("false_positives_list") or [])[:FALSE_POSITIVE_SAMPLE]
        summary.append(row)
    return summary


class RunReport:
    """State and files of one run.

    Args:
        results_root: Directory that holds all run directories.
        name: Experiment name (``global.name``).
        description: Experiment description, if any.
        run_info: Code and tool versions (see ``main.get_run_info``).
        complete_config: The full configuration of the run.
    """

    PROGRESS_INTERVAL = 1.0  # seconds between run.json writes for progress

    def __init__(self, results_root: Path, name: str, description=None,
                 run_info=None, complete_config=None):
        started = datetime.now()
        base = f"{slug(name)}_{started:%Y%m%d-%H%M%S}"
        run_dir = Path(results_root) / base
        suffix = 2
        while run_dir.exists():
            run_dir = Path(results_root) / f"{base}-{suffix}"
            suffix += 1
        self.dir = run_dir
        self.configs_dir = run_dir / "configs"
        self.charts_dir = run_dir / "charts"
        self.log_path = run_dir / "run.log"
        self.configs_dir.mkdir(parents=True)
        self.charts_dir.mkdir()

        self._lock = threading.Lock()
        self._last_progress_write = 0.0
        self.state = {
            "name": name,
            "description": description,
            "status": "running",
            "status_reason": "",
            "phase": "setup",
            "phase_detail": "",
            "phase_started": started.isoformat(timespec="seconds"),
            "started": started.isoformat(timespec="seconds"),
            "finished": None,
            "updated": started.isoformat(timespec="seconds"),
            "progress": "",
            "planned_configs": [],
            "configs": [],
            "timing": {},
            "current": None,
            "control": None,
            "run_info": run_info,
            "complete_config": complete_config,
        }
        self._write()

    # -- state updates -----------------------------------------------------

    def set_planned_configs(self, names) -> None:
        """Record the configurations the run will try, in order."""
        with self._lock:
            self.state["planned_configs"] = list(names)
        self._write()

    def update(self, **fields) -> None:
        """Set top-level run.json fields (timing, current, control)."""
        with self._lock:
            self.state.update(fields)
        self._write()

    @property
    def metrics_path(self) -> Path:
        return self.dir / "metrics.jsonl"

    @property
    def control_path(self) -> Path:
        return self.dir / "control.json"

    def set_phase(self, phase: str, detail: str = "") -> None:
        """Record the current phase (setup, peacetime, wartime, evaluation)."""
        with self._lock:
            self.state["phase"] = phase
            self.state["phase_detail"] = detail
            self.state["phase_started"] = datetime.now().isoformat(timespec="seconds")
            self.state["progress"] = ""
        self._write()

    def set_progress(self, text: str) -> None:
        """Record the latest progress line; written at most once per second."""
        with self._lock:
            self.state["progress"] = text
        now = time.monotonic()
        if now - self._last_progress_write >= self.PROGRESS_INTERVAL:
            self._last_progress_write = now
            self._write()

    def config_file(self, config_name: str) -> Path:
        """Return an unused results path for a configuration."""
        path = self.configs_dir / f"{slug(config_name)}.json"
        suffix = 2
        while path.exists():
            path = self.configs_dir / f"{slug(config_name)}-{suffix}.json"
            suffix += 1
        return path

    def record_config(self, config_name: str, status: str, reason: str, file: Path,
                      results=None, dataset_statistics=None, dnsexfil_config=None,
                      started=None, finished=None, wartime_end=None) -> None:
        """Add or replace the run.json entry of one configuration."""
        entry = {
            "name": config_name,
            "status": status,
            "reason": reason,
            "file": str(Path(file).relative_to(self.dir)),
            "started": started.isoformat(timespec="seconds") if started else None,
            "finished": (finished or datetime.now()).isoformat(timespec="seconds"),
            "dataset_statistics": dataset_statistics,
            "dnsexfiltrator_config": dnsexfil_config,
            "wartime_end": wartime_end,
            "detectors": summarize_detectors(results),
        }
        with self._lock:
            configs = [c for c in self.state["configs"] if c["name"] != config_name]
            configs.append(entry)
            self.state["configs"] = configs
        self._write()

    def finish(self, status: str, reason: str = "") -> None:
        """Mark the run as finished (completed, interrupted or failed)."""
        with self._lock:
            self.state["status"] = status
            self.state["status_reason"] = reason
            self.state["phase"] = "done"
            self.state["phase_detail"] = ""
            self.state["progress"] = ""
            self.state["current"] = None
            self.state["finished"] = datetime.now().isoformat(timespec="seconds")
        self._write()

    def _write(self) -> None:
        with self._lock:
            self.state["updated"] = datetime.now().isoformat(timespec="seconds")
            write_json_atomic(self.dir / "run.json", self.state)


class ReportLogHandler(logging.Handler):
    """Mirror the console log into ``run.log`` and progress lines into run.json.

    Progress records (``extra={'progress': True}``) overwrite each other on the
    console; here they only update ``run.json`` so the log stays readable.
    """

    def __init__(self, report: RunReport):
        super().__init__(level=logging.INFO)
        self.report = report
        self._file = open(report.log_path, "a", encoding="utf-8")
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            message = _ANSI.sub("", self.format(record))
            if getattr(record, "progress", False):
                self.report.set_progress(message.strip())
                return
            stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            for line in message.strip("\n").split("\n"):
                self._file.write(f"{stamp} {line}\n" if line else "\n")
            self._file.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        try:
            self._file.close()
        finally:
            super().close()
