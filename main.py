import subprocess
import time
import json
import re
import shlex
import yaml
from pathlib import Path, PurePosixPath
import sys
import threading
import logging
import warnings
from datetime import datetime
import shutil
import copy

# Suppress sklearn version warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.evaluate import load_detectors, run_peacetime, run_wartime, generate_allowlists, save_results, load_global_allowlist, wartime_stop_event, transfer_complete_event, request_wartime_stop, reset_wartime_stop, peacetime_stop_event, peacetime_done, cfg_safe_get, format_duration
from detection.detector_base.readfile import readjson, log_end_offset
from detection.detector_base.feature_extraction import normalize_name, normalize_tunneling_domains, get_registered_domain
from config.dns_config_generator import generate_all_configs, BIND_SERVERS, RNDC_CONTAINER_KEY_PATH
from detection.reporting import RunReport, ReportLogHandler
from detection.monitoring import MetricsSampler, ControlWatcher
from detection.exfil_payload import DNSExfilPayload
from detection.report_charts import build_report, fmt_bytes

CONFIG_PATH = PROJECT_ROOT / "config.yaml"
DOCKER_PATH = PROJECT_ROOT / "docker"
DOCKER_COMPOSE_FILE = DOCKER_PATH / "docker-compose.yml"
DOCKER_ENV_FILE = DOCKER_PATH / ".env"
CONFIG_TEMPLATE_DIR = PROJECT_ROOT / "config" / "templates"
RESULTS_DIR = PROJECT_ROOT / "results"
REPORT = None  # RunReport of the current run, created in run_setup
DETECTOR_PATH = PROJECT_ROOT / "detection" / "detectors"
LOGFILE = DOCKER_PATH / "dns-collector" / "logs" / "dnslogs.json"
# DNSExfiltrator server output, appended across configurations (see docker_exec_bg_logged).
SERVER_LOG = DOCKER_PATH / "dnsexfiltrator-server" / "volume" / "logs" / "server.log"
CLIENT_LOG = DOCKER_PATH / "dnsexfiltrator-client" / "data" / "logs" / "client.log"
MONITORED_CONTAINERS = ("resolver", "root-simulator", "tld-simulator", "dnscollector", "pcap-replayer",
                        "dnsexfiltrator-server", "dnsexfiltrator-client")

class UnifiedOutputHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.last_progress_length = 0
        self._lock = threading.Lock()
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            is_progress = getattr(record, 'progress', False)

            with self._lock:
                if is_progress:
                    padded_msg = msg.ljust(self.last_progress_length)
                    sys.stdout.write(f"\r{padded_msg}")
                    sys.stdout.flush()
                    self.last_progress_length = len(msg)
                else:
                    if self.last_progress_length > 0:
                        sys.stdout.write("\r" + " " * self.last_progress_length + "\r")
                        self.last_progress_length = 0
                    sys.stdout.write(msg + "\n")
                    sys.stdout.flush()
        except Exception:
            self.handleError(record)

logger = logging.getLogger('dns_detector')
logger.setLevel(logging.INFO)
logger.handlers.clear()

console_handler = UnifiedOutputHandler()
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

logger.propagate = False


def banner(title: str, width: int = 60) -> None:
    """Log a section heading."""
    logger.info("\n" + "=" * width)
    logger.info(title)
    logger.info("=" * width)


def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return yaml.safe_load(f)


def write_docker_env(pcap_dir):
    DOCKER_ENV_FILE.write_text(f"PCAP_PATH={pcap_dir}\n")


def compose_up(profile):
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "--profile", profile,
        "up",
        "-d",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"[!] Docker compose up failed for profile {profile}")
        logger.error(f"[!] stdout: {result.stdout}")
        logger.error(f"[!] stderr: {result.stderr}")
        raise RuntimeError(f"Docker compose up failed for profile {profile}")
    return result


def compose_down():
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "--profile", "*",
        "down"
    ]
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"[!] Docker compose down returned code {result.returncode}")
            if result.stderr:
                logger.warning(f"[!] Error: {result.stderr.strip()}")
        else:
            logger.info("[+] Docker containers stopped successfully")
    except Exception as e:
        logger.error(f"[!] Failed to run docker compose down: {e}")


def docker_exec(container: str, *docker_cmd: str, check: bool = True):
    cmd = ["docker", "exec", container] + list(docker_cmd)
    subprocess.run(cmd, check=check)


def docker_exec_bg_logged(container: str, logfile: str, *tool_cmd: str, check: bool = False,
                          pty: bool = False):
    """Start a tool detached in ``container`` with its output made visible again.

    The dnsexfiltrator containers run ``sleep infinity`` as their main process, so
    a plain ``docker exec -d`` would have Docker discard the tool's stdout/stderr
    and ``docker logs`` (which follows PID 1) would show nothing. This wraps the
    tool in a POSIX ``sh -c`` that tees the combined output both to ``logfile``
    (on a bind-mounted path, so it persists on the host) and to the container's
    PID 1 stdout (``/proc/1/fd/1``), so it reappears in ``docker logs`` and the
    Docker Desktop logs panel. ``init: true`` on both containers makes PID 1 the
    init process whose fd 1 is the container's log stream.

    ``sh`` on both images is dash, so the POSIX pipe form is used rather than bash
    process substitution.

    With ``pty=True`` the tool runs under ``script`` on a pseudo-terminal. The
    mono client block-buffers stdout and drops its colours when its output is a
    plain pipe; a PTY makes it line-buffer and emit ANSI colours, so the log
    streams live and in colour (``TERM=xterm`` is passed for the colour support).
    The command is passed through the ``TUNFRAME_CMD`` environment variable so no
    quoting of it leaks into the ``script -c`` string.
    """
    inner = " ".join(shlex.quote(a) for a in tool_cmd)
    log_dir = str(PurePosixPath(logfile).parent)
    # The PTY path passes the command via an env var so that ``script -c`` (which
    # re-parses it through ``sh -c``) sees the quoting intact; the direct path
    # keeps the command inline so dash parses the quoting itself.
    run = 'script -qec "$TUNFRAME_CMD" /dev/null' if pty else inner
    wrapped = (
        f"mkdir -p {shlex.quote(log_dir)}; "
        f"{run} 2>&1 | tee -a {shlex.quote(logfile)} > /proc/1/fd/1"
    )
    env = ["-e", f"TUNFRAME_CMD={inner}", "-e", "TERM=xterm"] if pty else []
    cmd = ["docker", "exec", "-d", *env, container, "sh", "-c", wrapped]
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def flush_tunnel_cache(domains) -> bool:
    """Drop cached answers for the tunnel domains on every simulated BIND server.

    DNSExfiltrator sends byte-identical queries when file, password and
    encoding stay the same, and its server answers the init query with a TTL.
    Without a flush, the next configuration's init is answered from the cache
    with the previous session's ACK: the new server never sees it and the
    client aborts with WrongAck. Only the tunnel domains are flushed; cached
    benign answers stay.

    Returns:
        bool: True if every flush succeeded.
    """
    ok = True
    for server in BIND_SERVERS:
        for domain in domains:
            result = subprocess.run(
                ["docker", "exec", server, "rndc", "-k", RNDC_CONTAINER_KEY_PATH,
                 "-s", "127.0.0.1", "flushtree", str(domain)],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                ok = False
                logger.warning(f"[!] Could not flush cached {domain} answers on {server}: "
                               f"{(result.stderr or result.stdout).strip()}")
    return ok


def check_process_running(container: str, process_name: str, expect_running: bool = True) -> bool:
    """Check if a process is running in a Docker container.
    
    Args:
        container: Docker container name
        process_name: Process name or pattern to search for
        expect_running: If True, logs error when not running; if False, logs info
    
    Returns:
        True if process is running, False otherwise
    """
    try:
        cmd = ["docker", "exec", container, "ps", "aux"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        is_running = process_name in result.stdout
        
        if not is_running and expect_running:
            # Get container logs for debugging
            try:
                logs_cmd = ["docker", "logs", container]
                logs_result = subprocess.run(logs_cmd, capture_output=True, text=True, check=False)
                if logs_result.stdout:
                    logger.error(f"[!] Container {container} logs (last 500 chars):\n{logs_result.stdout[-500:]}")
            except Exception:
                pass
            
            # Also show what processes ARE running
            if result.stdout:
                logger.error(f"[!] Processes in {container}: {result.stdout.strip()}")
        
        return is_running
    except Exception as e:
        logger.debug(f"[!] Error checking process {process_name} in {container}: {e}")
        return False


def tunnel_traffic_seen(start_offset: int, tunneling_domains: set, settle_seconds: float = 3.0) -> bool:
    """Return True if a query/response for a tunneling domain was logged since
    ``start_offset``.

    The DNSExfiltrator client is a one-shot exfiltration: for a small input
    file it finishes in about a second, long before the pre-wartime liveness
    gate runs, so a client that is no longer running has usually *finished*,
    not crashed. This reads the DNS log from the offset recorded before the
    client started and looks for traffic to a ground-truth tunneling domain,
    which proves the client actually ran. It rescans until such a line appears
    or ``settle_seconds`` elapse, so it tolerates both collector lag and the
    continuous benign traffic that keeps the log growing.
    """
    if not tunneling_domains:
        return False
    deadline = time.monotonic() + settle_seconds
    while True:
        end = log_end_offset(LOGFILE)
        if end > start_offset:
            try:
                with open(LOGFILE, "rb") as f:
                    f.seek(start_offset)
                    data = f.read(end - start_offset)
                for raw in data.split(b"\n"):
                    raw = raw.strip(b"\x00 \t\r\n")
                    if not raw:
                        continue
                    try:
                        event = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if get_registered_domain(event) in tunneling_domains:
                        return True
            except OSError as e:
                logger.debug(f"[!] tunnel_traffic_seen read error: {e}")
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def replay_fire_and_forget(pcap: str, pps: int, label: str):
    """Start tcpreplay in the replayer container without waiting for it."""
    if not pcap:
        logger.warning(f"[-] Skipping {label} replay (disabled)")
        return
    
    cmd = ["tcpreplay"]
    if pps is None or pps <= 0:
        logger.info(f"[+] Firing {label} replay at original speed from {pcap}")
        cmd.extend(["-i", "replay0", pcap])
    else:
        logger.info(f"[+] Firing {label} replay: {pps} PPS from {pcap}")
        cmd.extend([f"--pps={pps}", "-i", "replay0", pcap])
    
    docker_exec("pcap-replayer", *cmd, check=False)


# Traffic sources whose replay has been started in this run. tcpreplay keeps
# running until it reaches the end of the pcap or the containers stop.
_started_replays = set()


def start_replay(label: str, pcap: str, pps) -> bool:
    """Start a fire-and-forget tcpreplay at most once per run and traffic source.

    A replay started during peacetime keeps running into wartime, so wartime
    sees the continuation of the capture instead of a restart from packet 0.

    Args:
        label: Traffic source name (``benign``, ``wildcard``, ``tunnel``).
        pcap: Pcap file name inside the pcap directory.
        pps: Replay rate in packets per second; None or <= 0 for original timing.

    Returns:
        bool: True if a new replay was started, False if it was already running.
    """
    if label in _started_replays:
        logger.info(f"[+] {label} replay already running since an earlier phase, continuing it")
        return False
    _started_replays.add(label)
    threading.Thread(target=replay_fire_and_forget, args=(pcap, pps, label), daemon=True).start()
    return True


# ---------------------------------------------------------------------------
# Managed replays for the peacetime -> wartime split.
#
# Unlike the fire-and-forget continuous stream above, these replays are started
# and stopped explicitly. Peacetime replays a pcap, is stopped, and reports how
# many packets it actually sent; wartime then resumes the SAME pcap right after
# that packet (via ``prepare_wartime_segment``), so wartime never reuses the
# benign traffic the allowlist was learned from, and every DNSExfiltrator config
# window sees the identical wartime segment.
#
# Each label writes tcpreplay's output to its own logfile inside the replayer
# container; ``exec tcpreplay`` replaces the wrapping shell so the only matching
# process is tcpreplay itself, stopped with ``pkill -INT -x tcpreplay`` (SIGINT
# makes tcpreplay flush its final "Actual: N packets sent" stats before exiting).
# ---------------------------------------------------------------------------
REPLAY_LOG_DIR = "/tmp/tunframe-replays"


def _replay_logfile(label: str) -> str:
    return f"{REPLAY_LOG_DIR}/{label}.log"


def managed_replay_start(label: str, pcap: str, pps) -> None:
    """Start a tcpreplay in the replayer container, detached, capturing its stats."""
    if not pcap:
        logger.warning(f"[-] Skipping {label} replay (no pcap)")
        return
    rate = "" if (pps is None or pps <= 0) else f"--pps={pps} "
    logfile = _replay_logfile(label)
    inner = (
        f"mkdir -p {REPLAY_LOG_DIR} && cd /app && "
        f"exec tcpreplay {rate}-i replay0 {pcap} > {logfile} 2>&1"
    )
    rate_desc = "original speed" if not rate else f"{pps} PPS"
    logger.info(f"[+] Starting {label} replay ({rate_desc}) from {pcap}")
    subprocess.run(
        ["docker", "exec", "-d", "pcap-replayer", "sh", "-c", inner], check=False
    )


def managed_replay_stop_all() -> None:
    """Stop every tcpreplay in the replayer container with SIGINT so stats flush."""
    subprocess.run(
        ["docker", "exec", "pcap-replayer", "pkill", "-INT", "-x", "tcpreplay"],
        capture_output=True, text=True, check=False,
    )


def managed_replay_packets_sent(label: str) -> int:
    """Return the packet count tcpreplay reported for ``label`` (0 if unknown)."""
    res = subprocess.run(
        ["docker", "exec", "pcap-replayer", "cat", _replay_logfile(label)],
        capture_output=True, text=True, check=False,
    )
    match = re.search(r"Actual:\s+(\d+)\s+packets", res.stdout or "")
    return int(match.group(1)) if match else 0


def prepare_wartime_segment(label: str, pcap: str, packets_sent: int, host_pcap_dir: Path) -> str:
    """Return the pcap basename wartime should replay for ``label``.

    When peacetime sent ``packets_sent`` packets, slice them off the front with
    ``editcap`` so wartime starts at the packet after peacetime stopped. Returns
    the original pcap unchanged when there was no peacetime, when ``editcap`` is
    unavailable, or when slicing fails (wartime then replays from packet 0).
    """
    if not pcap or not packets_sent or packets_sent <= 0:
        return pcap
    editcap = shutil.which("editcap")
    if not editcap:
        logger.warning(
            f"[!] editcap not found on host; {label} wartime replays from packet 0 "
            f"(cannot skip the {packets_sent} peacetime packets)"
        )
        return pcap
    src = host_pcap_dir / pcap
    if not src.exists():
        logger.warning(f"[!] {label} pcap {src} not found; cannot slice, replaying from packet 0")
        return pcap
    segment = f"{src.stem}__wartime_segment.pcap"
    dst = host_pcap_dir / segment
    try:
        # editcap <in> <out> 1-N  deletes packets 1..N, keeping N+1..end.
        subprocess.run(
            [editcap, str(src), str(dst), f"1-{packets_sent}"],
            check=True, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, OSError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        logger.warning(f"[!] editcap failed for {label}: {detail}; wartime replays from packet 0")
        return pcap
    if not dst.exists() or dst.stat().st_size == 0:
        logger.warning(f"[!] {label} wartime segment is empty (peacetime consumed the whole pcap?)")
        return pcap
    logger.info(f"[+] {label}: skipping {packets_sent} peacetime packets; wartime replays {segment}")
    return segment


# Ratio of encoded query characters to raw payload bytes per encoding
# (thesis section 2.3.1). Used to estimate the real data volume from ULV.
ENCODING_EXPANSION_FACTORS = {
    'base32': 8 / 5,       # 1.6
    'base32map': 3 * 8 / 5,  # 4.8: each Base32 character becomes a 3-letter word
    'base64': 4 / 3,
    'hex': 2.0,
}


def config_expansion_factor(config: dict) -> float:
    """Return the expansion factor for one DNSExfiltrator configuration.

    An explicit ``expansion_factor`` in the configuration wins; otherwise the
    factor is derived from its ``encoding``.

    Args:
        config: Filled DNSExfiltrator configuration.

    Returns:
        float: Expansion factor (1.0 for an unknown encoding, with a warning).
    """
    if config.get('expansion_factor') is not None:
        return float(config['expansion_factor'])
    encoding = str(config.get('encoding', '')).lower()
    if encoding not in ENCODING_EXPANSION_FACTORS:
        logger.warning(f"[!] Unknown encoding '{encoding}', using expansion factor 1.0")
        return 1.0
    return ENCODING_EXPANSION_FACTORS[encoding]


class PhaseTimer:
    """Cancellable timer that sets a phase stop event after a duration.

    Every phase must cancel its timer when it ends, also when it ends early
    (all tunnels detected, log ended, error). A cancelled timer can no longer
    set the event, so it cannot cut a later phase short.

    Args:
        event: Stop event to set when the duration has elapsed.
        duration: Phase duration in seconds.
    """

    def __init__(self, event: threading.Event, duration: float):
        self._timer = threading.Timer(duration, event.set)
        self._timer.daemon = True

    def start(self) -> "PhaseTimer":
        """Start the timer and return self."""
        self._timer.start()
        return self

    def cancel(self) -> None:
        """Cancel the timer; a no-op if it already fired."""
        self._timer.cancel()


class TransferWatcher:
    """Signal the end of a DNSExfiltrator transfer from the server log.

    The server prints ``TRANSFER_DONE_MARKER`` after it has written the
    received file. The watcher reads the server log from ``start_offset`` (the
    log is appended across configurations), and when the marker appears waits
    ``settle_seconds`` for the DNS collector to write the last queries and
    responses, then sets ``event``. Like ``PhaseTimer`` it must be cancelled
    when the window ends.

    Args:
        server_log: Server log on the host (bind-mounted from the container).
        start_offset: Byte offset of the log before this configuration's server started.
        event: Event to set once the transfer is complete.
        settle_seconds: Delay between the marker and setting ``event``.
        poll_interval: Seconds between reads of the server log.
    """

    TRANSFER_DONE_MARKER = "File saved successfully"

    def __init__(self, server_log: Path, start_offset: int, event: threading.Event,
                 settle_seconds: float = 2.0, poll_interval: float = 0.5):
        self._log = Path(server_log)
        self._offset = start_offset
        self._event = event
        self._settle = settle_seconds
        self._poll = poll_interval
        self._cancelled = threading.Event()
        self._started_at = None
        self.completed_after = None  # seconds from start() to the marker
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "TransferWatcher":
        """Start watching and return self."""
        self._started_at = time.monotonic()
        self._thread.start()
        return self

    def cancel(self) -> None:
        """Stop watching; a no-op once the event has been set."""
        self._cancelled.set()

    def _run(self) -> None:
        pending = b""
        while not self._cancelled.is_set():
            try:
                with open(self._log, "rb") as f:
                    f.seek(self._offset)
                    chunk = f.read()
            except OSError:
                chunk = b""
            if chunk:
                self._offset += len(chunk)
                pending += chunk
                *lines, pending = pending.split(b"\n")
                if any(self.TRANSFER_DONE_MARKER.encode() in line for line in lines):
                    self.completed_after = time.monotonic() - self._started_at
                    logger.info(f"[+] Transfer complete after {self.completed_after:.1f}s "
                                f"(server saved the file); ending the window once the log is caught up")
                    if not self._cancelled.wait(self._settle):
                        self._event.set()
                    return
            self._cancelled.wait(self._poll)


def wartime_end_info(counts: dict, watcher: "TransferWatcher" = None) -> dict:
    """Describe how a wartime window ended, for the results metadata.

    ``transfer_completed`` and ``transfer_seconds`` are ``None`` when no
    transfer was watched (replay mode or ``stop_on_transfer_complete: false``).
    """
    return {
        "reason": counts.get("stop_reason"),
        "transfer_completed": (watcher.completed_after is not None) if watcher else None,
        "transfer_seconds": round(watcher.completed_after, 3) if watcher and watcher.completed_after is not None else None,
    }


BENIGN_WINDOW = "benign_only"  # name of the benign-only window and its results file


def benign_window_duration(cfg: dict) -> float:
    """Length of the benign-only window in seconds; 0 means no such window.

    The benign-only window (``timing.benign_only_duration``, minutes) runs
    between peacetime and the tunnel windows. It is a wartime window without
    tunnel traffic: only the benign and wildcard replays run, so every alarm
    is a false positive and it measures the FPR without adversarial load.

    Raises:
        ValueError: If the duration is negative.
    """
    minutes = float(cfg_safe_get(cfg, ["timing", "benign_only_duration"], 0) or 0)
    if minutes < 0:
        raise ValueError("timing.benign_only_duration must be >= 0")
    return minutes * 60


def tunnel_windows_planned(cfg: dict) -> bool:
    """Whether tunnel windows follow peacetime (and the benign-only window).

    False only for a benign-only run: a benign-only window and neither tunnel
    replay nor DNSExfiltrator. Without a benign-only window the wartime window
    always runs, since tunnel traffic may also come from a tool started by hand.
    """
    if not benign_window_duration(cfg):
        return True
    return bool(cfg_safe_get(cfg, ["traffic", "tunnel", "replay"], False)
                or cfg_safe_get(cfg, ["dnsexfiltrator", "enabled"], False))


def add_false_alarm_rates(results: list, window_seconds: float) -> None:
    """Add ``fp_domains_per_hour``: falsely flagged domains per hour of the window."""
    hours = (window_seconds or 0) / 3600
    for result in results or []:
        result["fp_domains_per_hour"] = (result.get("fp") or 0) / hours if hours > 0 else None


def add_leak_shares(results: list, counts: dict) -> None:
    """Add ULV% and DLV% to every detector result.

    ``ulv_percent`` is how much of the exfiltrated file left before the
    detector's alarm. In DNSExfiltrator mode it is exact: ``net_up_bytes`` (file
    bytes of the data chunks before the alarm) over the file size the tool
    announced (``ulv_basis: "file"``). Otherwise, or if the size is unknown, it
    is the share of the window's raw tunnel uplink payload (query names) that
    passed before the alarm (``ulv_basis: "tunnel_payload"``). ``dlv_percent``
    is the raw share for the downlink (answer records). Allowlisted tunnel
    traffic never raises an alarm, so it counts as leaked. ``None`` when there
    is nothing to relate to.
    """
    up, down = counts.get("tunnel_up_bytes", 0), counts.get("tunnel_down_bytes", 0)
    file_bytes = counts.get("exfil_file_bytes") or counts.get("exfil_file_bytes_server")
    for result in results or []:
        lv_up = (result.get("traffic_volume_up_bytes") or 0) + (result.get("allowlisted_tunnel_up_bytes") or 0)
        lv_down = (result.get("traffic_volume_down_bytes") or 0) + (result.get("allowlisted_tunnel_down_bytes") or 0)
        if result.get("net_up_bytes") is not None and file_bytes:
            result["ulv_percent"] = min(100.0, 100.0 * result["net_up_bytes"] / file_bytes)
            result["ulv_basis"] = "file"
        else:
            result["ulv_percent"] = min(100.0, 100.0 * lv_up / up) if up else None
            result["ulv_basis"] = "tunnel_payload"
        result["dlv_percent"] = min(100.0, 100.0 * lv_down / down) if down else None


def net_volume_check(counts: dict, transfer_completed) -> str:
    """Compare the decoded data of a window with the file size the tools report.

    Returns ``"match"`` (the unique data chunks add up to the announced size),
    ``"mismatch"``, ``"incomplete"`` (the transfer did not finish in the
    window) or ``"unknown"`` (no decoded volume or no size).
    """
    net, size = counts.get("tunnel_net_up_bytes"), counts.get("exfil_file_bytes") or counts.get("exfil_file_bytes_server")
    if net is None or not size:
        return "unknown"
    if net == size:
        return "match"
    return "incomplete" if transfer_completed is False or net < size else "mismatch"


def exfil_payload_for(config: dict):
    """``DNSExfilPayload`` for a configuration, or ``None`` (with a warning) for an unknown encoding."""
    try:
        return DNSExfilPayload(config.get('encoding'))
    except ValueError as e:
        logger.warning(f"[!] {e}: net exfiltration volume falls back to the expansion-factor estimate")
        return None


_SERVER_FILE_SIZE = re.compile(rb"File size: ([0-9]+) bytes")


def server_reported_file_size(start_offset: int):
    """File size the DNSExfiltrator server reported for this configuration (server log from ``start_offset``)."""
    try:
        with open(SERVER_LOG, "rb") as f:
            f.seek(start_offset)
            sizes = _SERVER_FILE_SIZE.findall(re.sub(rb"\x1b\[[0-9;]*m", b"", f.read()))
    except OSError:
        return None
    return int(sizes[-1]) if sizes else None


def build_and_save_metadata(
    results_file: Path,
    results: list,
    logcount: int,
    tunnel_count: int,
    seen_tunnels: set,
    alldomains: set,
    start_timestamp: datetime,
    end_timestamp: datetime,
    wartime_duration: float,
    peacetime_duration: float,
    tunneling_domains_set: set,
    tunneling_enabled: bool,
    tunneling_pcap: str,
    tunneling_pps,
    server_ip: str,
    public_resolver: str,
    cfg: dict,
    counts: dict = None,
    status: str = "completed",
    status_reason: str = "",
    dnsexfil_config: dict = None,
    config_name: str = "wartime",
    wartime_end: dict = None,
):
    """Build metadata, save the results file and record it in the run report.

    ``tunnel_percentage`` is the share of tunneling queries among all queries;
    responses are counted separately in ``counts``.
    """
    counts = counts or {}
    add_leak_shares(results, counts)
    total_queries = counts.get("total_queries", 0)
    tunnel_queries = counts.get("tunnel_queries", 0)
    tunnel_percentage = (tunnel_queries / total_queries * 100) if total_queries > 0 else 0
    
    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])
    
    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    wildcard_pcap = cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
    wildcard_pps = cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])
    
    metadata = {
        "experiment": {
            "name": cfg_safe_get(cfg, ['global', 'name'], 'unknown'),
            "description": cfg_safe_get(cfg, ['global', 'description']),
            "start_timestamp": start_timestamp.isoformat(),
            "end_timestamp": end_timestamp.isoformat(),
            "wartime_duration": format_duration(wartime_duration),
            "peacetime_duration": format_duration(peacetime_duration),
            "actual_runtime": format_duration((end_timestamp - start_timestamp).total_seconds()),
        },
        "traffic_config": {
            "benign": {
                "enabled": benign_enabled,
                "pcap": benign_pcap,
                "pps": benign_pps,
            },
            "wildcard": {
                "enabled": wildcard_enabled,
                "pcap": wildcard_pcap,
                "pps": wildcard_pps,
            },
            "tunnel": {
                "replay_enabled": tunneling_enabled,
                "pcap": tunneling_pcap,
                "pps": tunneling_pps,
                "tunneling_domains": list(tunneling_domains_set),
                "tunneling_domains_seen": list(seen_tunnels),
                "tunnel_server_ip": server_ip,
            },
            "pcap_path": cfg_safe_get(cfg, ['traffic', 'pcap_path'], ''),
        },
        "dataset_statistics": {
            "total_loglines": logcount,
            "tunnel_loglines": tunnel_count,
            "total_queries": total_queries,
            "total_responses": counts.get("total_responses", 0),
            "tunnel_queries": tunnel_queries,
            "tunnel_responses": counts.get("tunnel_responses", 0),
            "tunnel_percentage": tunnel_percentage,
            "tunnel_up_bytes": counts.get("tunnel_up_bytes", 0),
            "tunnel_down_bytes": counts.get("tunnel_down_bytes", 0),
            **{key: counts[key] for key in (
                "tunnel_net_up_bytes", "tunnel_data_queries", "tunnel_init_queries", "tunnel_dilution_queries",
                "tunnel_retried_queries", "exfil_file_bytes", "exfil_file_bytes_server", "init_encoding",
                "source_file_bytes", "net_volume_check", "window_seconds") if key in counts},
            "unique_domains": len(alldomains),
            "logfile": str(LOGFILE)
        },
        "global_config": {
            "public_resolver": public_resolver,
            "detector_path": str(DETECTOR_PATH)
        },
        "complete_config": cfg,
        "window_type": "benign_only" if config_name == BENIGN_WINDOW else "tunnel",
        "dnsexfiltrator_config": dnsexfil_config,
        "run_info": get_run_info(),
        "run_status": {"status": status, "reason": status_reason},
        "wartime_end": wartime_end,
    }
    save_results(str(results_file), results, metadata)
    get_report(cfg).record_config(
        config_name, status, status_reason, results_file, results=results,
        dataset_statistics=metadata["dataset_statistics"], dnsexfil_config=dnsexfil_config,
        started=start_timestamp, finished=end_timestamp, wartime_end=wartime_end,
    )


_RUN_INFO = None


def _command_output(cmd: list) -> str:
    """Return the stripped stdout of a command, or an empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=PROJECT_ROOT)
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def get_run_info() -> dict:
    """Collect code and tool versions for reproducibility (cached per run).

    Returns:
        dict: git commit and dirty flag, Python version, versions of the Python
        libraries the harness depends on, and Docker / Docker Compose versions.
        Unavailable values are empty strings.
    """
    global _RUN_INFO
    if _RUN_INFO is None:
        try:
            from importlib.metadata import version as _pkg_version
        except ImportError:  # pragma: no cover
            _pkg_version = None
        libraries = {}
        for package in ("tldextract", "fqdn", "PyYAML"):
            try:
                libraries[package] = _pkg_version(package) if _pkg_version else ""
            except Exception:
                libraries[package] = ""
        _RUN_INFO = {
            "git_commit": _command_output(["git", "rev-parse", "HEAD"]),
            "git_dirty": bool(_command_output(["git", "status", "--porcelain", "--untracked-files=no"])),
            "python_version": sys.version.split()[0],
            "libraries": libraries,
            "docker_version": _command_output(["docker", "--version"]),
            "docker_compose_version": _command_output(["docker", "compose", "version", "--short"]),
        }
    return _RUN_INFO


def save_status_result(cfg: dict, config_name: str, status: str, reason: str, dnsexfil_config: dict = None) -> Path:
    """Write a results file for a configuration that produced no measurements.

    Every requested configuration leaves a results file, so gaps in a sweep
    are visible in the data and not only in the console log.

    Args:
        cfg: Complete experiment configuration.
        config_name: Name of the DNSExfiltrator configuration (or "wartime").
        status: "skipped" (never started) or "failed" (error while starting).
        reason: Human-readable reason.
        dnsexfil_config: The DNSExfiltrator configuration, if any.

    Returns:
        Path: The written results file.
    """
    report = get_report(cfg)
    name = cfg_safe_get(cfg, ['global', 'name'], 'experiment')
    results_file = report.config_file(config_name)
    metadata = {
        "experiment": {
            "name": name,
            "description": cfg_safe_get(cfg, ['global', 'description']),
            "config_name": config_name,
            "timestamp": datetime.now().isoformat(),
        },
        "complete_config": cfg,
        "dnsexfiltrator_config": dnsexfil_config,
        "run_info": get_run_info(),
        "run_status": {"status": status, "reason": reason},
    }
    logger.warning(f"[!] Configuration {config_name} {status}: {reason}")
    save_results(str(results_file), [], metadata)
    report.record_config(config_name, status, reason, results_file, dnsexfil_config=dnsexfil_config)
    return results_file


def start_run_report(cfg: dict) -> RunReport:
    """Create the run directory in ``RESULTS_DIR`` and mirror the console log into it."""
    global REPORT
    close_run_report()
    REPORT = RunReport(
        RESULTS_DIR,
        name=cfg_safe_get(cfg, ['global', 'name'], 'experiment'),
        description=cfg_safe_get(cfg, ['global', 'description']),
        run_info=get_run_info(),
        complete_config=cfg,
    )
    logger.addHandler(ReportLogHandler(REPORT))
    return REPORT


def get_report(cfg: dict) -> RunReport:
    """Return the current run report, creating one if none is active."""
    return REPORT or start_run_report(cfg)


def close_run_report() -> None:
    """Stop mirroring the console log into the run directory."""
    for handler in list(logger.handlers):
        if isinstance(handler, ReportLogHandler):
            logger.removeHandler(handler)
            handler.close()


def set_phase(phase: str, detail: str = "") -> None:
    """Record the current phase in the run report, if there is one."""
    if REPORT is not None:
        REPORT.set_phase(phase, detail)


def set_current(**fields) -> None:
    """Merge ``fields`` into run.json's ``current`` (the running configuration); no fields clears it."""
    if REPORT is None:
        return
    current = dict(REPORT.state.get("current") or {}, **fields) if fields else None
    REPORT.update(current=current)


class RunControl:
    """Requests from the dashboard: skip the running configuration or stop the run.

    A request that arrives while no wartime window is open (server start,
    peacetime) is applied when the next window opens; a stop also ends
    peacetime and skips every remaining configuration.
    """

    def __init__(self):
        self.stop_requested = threading.Event()
        self._skip_pending = threading.Event()
        self._window_open = False

    def handle(self, action: str) -> None:
        if action == "stop_run":
            logger.warning("[!] Dashboard: stop requested - evaluating the current window, then ending the run")
            self.stop_requested.set()
            peacetime_stop_event.set()
            if self._window_open:
                request_wartime_stop("user_stop")
        elif action == "skip_config":
            if REPORT is not None and REPORT.state.get("phase") == "wartime":
                logger.warning("[!] Dashboard: skipping the running configuration")
                if self._window_open:
                    request_wartime_stop("user_skip")
                else:
                    self._skip_pending.set()
            else:
                logger.info("[i] Dashboard: skip ignored - no wartime window is running")

    def open_window(self) -> None:
        """Arm a new wartime window and apply requests made before it opened."""
        reset_wartime_stop()
        self._window_open = True
        if self.stop_requested.is_set():
            request_wartime_stop("user_stop")
        elif self._skip_pending.is_set():
            self._skip_pending.clear()
            request_wartime_stop("user_skip")

    def close_window(self) -> None:
        self._window_open = False
        self._skip_pending.clear()


RUN_CONTROL = RunControl()
MONITORS = []  # MetricsSampler, ControlWatcher of the current run
USER_END_REASONS = {"user_skip": "skipped from the dashboard", "user_stop": "run stopped from the dashboard"}


def start_monitoring(tunneling_domains) -> None:
    """Start the metrics sampler and the dashboard control watcher for the run."""
    stop_monitoring()
    sampler = MetricsSampler(REPORT, LOGFILE, {normalize_name(d) for d in tunneling_domains},
                             MONITORED_CONTAINERS).start()
    MONITORS[:] = [sampler, ControlWatcher(REPORT, RUN_CONTROL.handle).start()]


def stop_monitoring() -> None:
    for monitor in MONITORS:
        monitor.stop()
    MONITORS.clear()


def watch_exfil(server_log_offset=None) -> None:
    """Follow the transfer progress of the running configuration in the metrics."""
    if MONITORS:
        MONITORS[0].watch_exfil(SERVER_LOG if server_log_offset is not None else None, server_log_offset or 0)


# Default values for every DNSExfiltrator configuration.
DNSEXFIL_DEFAULTS = {
    'file': '/data/synthetic_cc_data_100.csv',
    'password': 'tunframe',
    'throttle': 10,
    'throttle_random': 0,
    'label_max_size': 63,
    'encoding': 'base32',
    'dilution': 0,
    'domains': [],
    'expansion_factor': None,  # None: derive from 'encoding'
}
# Sweep-only parameters that set real parameters. domain_count: the first N
# domains of the sweep's ``domains`` pool (default: the baseline's domains).
VIRTUAL_SWEEP_PARAMETERS = ('domain_count',)


def _check_dnsexfil_keys(where: str, keys) -> None:
    """Raise ValueError if a DNSExfiltrator config block uses unknown parameters."""
    unknown = sorted(set(keys) - set(DNSEXFIL_DEFAULTS) - {'name'})
    if unknown:
        raise ValueError(
            f"Unknown DNSExfiltrator parameter(s) in {where}: {unknown}. "
            f"Valid parameters: {sorted(DNSEXFIL_DEFAULTS)}"
        )


# Keys that older docs or configs used but the code does not read.
# Renamed keys abort the run because ignoring them would silently change it.
RENAMED_CONFIG_KEYS = {
    ('timing', 'duration'): "use timing.wartime_duration (minutes)",
    ('detector', 'names'): "use detectors.active (list of detector directory names)",
}
IGNORED_CONFIG_KEYS = {
    ('traffic', 'tunnel', 'docker'): "live tunneling is configured in the dnsexfiltrator section",
    ('traffic', 'tunnel', 'toolname'): "not used",
    ('allowlist', 'local_allowlist_dir'): "saved per-detector allowlists are not supported; use a peacetime phase",
}


def check_config_keys(cfg: dict) -> None:
    """Reject renamed configuration keys and warn about ignored ones.

    Args:
        cfg: Configuration dictionary.

    Raises:
        ValueError: If a renamed key (for example ``timing.duration``) is set.
    """
    _missing = object()
    errors = []
    for path, hint in RENAMED_CONFIG_KEYS.items():
        if cfg_safe_get(cfg, list(path), _missing) is not _missing:
            errors.append(f"'{'.'.join(path)}' is not supported: {hint}")
    if errors:
        raise ValueError("Invalid configuration:\n  " + "\n  ".join(errors))
    for path, hint in IGNORED_CONFIG_KEYS.items():
        if cfg_safe_get(cfg, list(path), _missing) is not _missing:
            logger.warning(f"[!] Config key '{'.'.join(path)}' is ignored: {hint}")


def resolve_results_dir(cfg: dict) -> Path:
    """Return the results directory from ``output.logdir`` (default ``results``).

    Relative paths are resolved against the directory of ``config.yaml``.
    """
    logdir = Path(cfg_safe_get(cfg, ['output', 'logdir'], 'results') or 'results')
    return logdir if logdir.is_absolute() else (CONFIG_PATH.parent / logdir).resolve()


def validate_dnsexfil_domains(configs: list) -> list:
    """Check the domains of every DNSExfiltrator config; return all of them.

    These domains (and only these) are routed to the tunnel server in the
    BIND configs of resolver, root and TLD, and each configuration's domains
    are its ground truth. ``traffic.tunnel.tunneling_domains`` is not used
    here: it only declares the tunnel domains of the replayed pcap.

    Args:
        configs: Filled DNSExfiltrator configurations.

    Returns:
        list: Every domain used by a configuration, normalised, in first-use order.

    Raises:
        ValueError: If a config has no domains or a domain is not a registered
            domain (eTLD+1).
    """
    routed, problems = [], []
    for config in configs:
        name = config.get('name', 'config')
        try:
            domains = normalize_tunneling_domains(config.get('domains') or [])
        except ValueError as e:
            problems.append(f"{name}: {e}")
            continue
        if not domains:
            problems.append(f"{name}: no domains configured")
        routed.extend(d for d in domains if d not in routed)
    if problems:
        raise ValueError("Invalid DNSExfiltrator domains:\n  " + "\n  ".join(problems))
    return routed


def get_dnsexfiltrator_configs(cfg: dict):
    """Get DNSExfiltrator configurations from config file.

    Builds the baseline, one config per sweep value and the predefined
    profiles. Sweeps and profiles inherit every value they do not set from the
    filled baseline; the baseline inherits from ``DNSEXFIL_DEFAULTS``.
    Unknown parameter names in the baseline, a sweep or a profile raise
    ValueError at startup.

    Args:
        cfg: Configuration dictionary

    Returns:
        list: List of dnsexfiltrator configurations

    Raises:
        ValueError: If a block uses an unknown parameter name.
    """
    dnsexfil_enabled = cfg_safe_get(cfg, ['dnsexfiltrator', 'enabled'], False)
    if not dnsexfil_enabled:
        logger.info("[+] DNSExfiltrator disabled")
        return []

    banner("DNSExfiltrator Configurations")

    def with_base(base: dict, overrides: dict) -> dict:
        """Deep-copy ``base`` and apply ``overrides`` on top."""
        filled = copy.deepcopy(base)
        filled.update(copy.deepcopy(overrides or {}))
        return filled

    configs = []

    # 1. Baseline (inherits DNSEXFIL_DEFAULTS)
    baseline_cfg = cfg_safe_get(cfg, ['dnsexfiltrator', 'baseline'], None) or {}
    _check_dnsexfil_keys("baseline", baseline_cfg)
    base_cfg = with_base(DNSEXFIL_DEFAULTS, baseline_cfg)
    base_cfg.pop('name', None)
    if baseline_cfg:
        logger.info("[+] Processing baseline configuration")
        configs.append(with_base(base_cfg, {'name': 'baseline', '_group': 'Baseline', '_kind': 'baseline'}))

    # 2. Sweeps (inherit the filled baseline)
    sweeps = cfg_safe_get(cfg, ['dnsexfiltrator', 'sweeps'], []) or []
    for sweep in sweeps:
        sweep_name = sweep.get('name', 'unnamed_sweep')
        parameter = sweep.get('parameter', '')
        if parameter not in DNSEXFIL_DEFAULTS and parameter not in VIRTUAL_SWEEP_PARAMETERS:
            raise ValueError(
                f"Unknown sweep parameter '{parameter}' in sweep '{sweep_name}'. "
                f"Valid parameters: {sorted(DNSEXFIL_DEFAULTS) + list(VIRTUAL_SWEEP_PARAMETERS)}"
            )
        pool = list(sweep.get('domains') or base_cfg.get('domains') or [])
        for value in sweep.get('values', []):
            if parameter == 'domain_count':
                if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= len(pool):
                    raise ValueError(
                        f"Sweep '{sweep_name}': domain_count {value!r} needs an integer between 1 and "
                        f"{len(pool)} (the number of domains in its 'domains' pool)"
                    )
                sweep_config = with_base(base_cfg, {'domains': pool[:value]})
            else:
                sweep_config = with_base(base_cfg, {parameter: value})
            sweep_config['name'] = f"{sweep_name}_{parameter}_{value}"
            sweep_config['_group'] = sweep_name
            sweep_config['_kind'] = 'sweep'
            sweep_config['_parameter'] = parameter
            sweep_config['_value'] = value
            configs.append(sweep_config)
            logger.info(f"[+] Added sweep config: {sweep_config['name']} ({parameter}={value})")

    # 3. Profiles (inherit the filled baseline)
    profiles = cfg_safe_get(cfg, ['dnsexfiltrator', 'profiles'], []) or []
    for profile in profiles:
        profile_name = profile.get('name', 'unnamed_profile')
        _check_dnsexfil_keys(f"profile '{profile_name}'", profile)
        filled_profile = with_base(base_cfg, profile)
        filled_profile['name'] = profile_name
        filled_profile['_group'] = 'Profiles'
        filled_profile['_kind'] = 'profile'
        configs.append(filled_profile)
        logger.info(f"[+] Added profile: {profile_name}")

    # If no configurations were found, run the baseline values once
    if not configs:
        configs.append(with_base(base_cfg, {'name': 'default', '_group': 'Baseline', '_kind': 'baseline'}))
        logger.info("[+] Created default configuration")

    logger.info(f"[+] Total DNSExfiltrator configurations: {len(configs)}")
    logger.info("="*60)

    return configs


def run_setup(cfg: dict):
    """Setup phase: Load config, clean state, start docker containers.
    
    Returns:
        tuple: (wartime_duration, peacetime_duration, tunneling_domains, server_ip,
                public_resolver, global_allowlist_path, active_detectors_list, results_file,
                dnsexfil_configs)
    """
    global RESULTS_DIR
    check_config_keys(cfg)
    RESULTS_DIR = resolve_results_dir(cfg)
    report = start_run_report(cfg)
    logger.info(f"[+] Run directory: {report.dir}")

    # Load timing configuration (minutes)
    wartime_duration_config = cfg_safe_get(cfg, ["timing", "wartime_duration"], 60)
    peacetime_duration_config = cfg_safe_get(cfg, ["timing", "peacetime_duration"], None)
    
    # Convert from minutes to seconds
    wartime_duration = float(wartime_duration_config) * 60
    
    if peacetime_duration_config is None:
        # Default to wartime_duration / 3
        peacetime_duration = (float(wartime_duration_config) / 3) * 60
    else:
        peacetime_duration = float(peacetime_duration_config) * 60

    # traffic.tunnel.tunneling_domains only declares the tunnel domains of the
    # replayed pcap (its ground truth); it is read only when the replay runs
    # (replay mode, i.e. traffic.tunnel.replay without DNSExfiltrator).
    # Fail fast (before DNS configs are generated) unless every entry is an eTLD+1.
    replay_active = (bool(cfg_safe_get(cfg, ["traffic", "tunnel", "replay"], False))
                     and not cfg_safe_get(cfg, ["dnsexfiltrator", "enabled"], False))
    configured_replay_domains = cfg_safe_get(cfg, ["traffic", "tunnel", "tunneling_domains"], []) or []
    if replay_active:
        replay_domains = normalize_tunneling_domains(configured_replay_domains)
        if not replay_domains:
            raise ValueError("traffic.tunnel.replay needs traffic.tunnel.tunneling_domains "
                             "(the tunnel domains in the replayed pcap)")
    else:
        replay_domains = []
        if configured_replay_domains:
            logger.info("[i] traffic.tunnel.tunneling_domains ignored: it is only used for the tunnel pcap replay")
    server_ip = cfg_safe_get(cfg, ['traffic', 'tunnel', 'tunnel_server_ip'], '192.168.4.4')
    public_resolver = cfg_safe_get(cfg, ['global', 'public_resolver'], '1.1.1.1')
    global_allowlist_path = cfg_safe_get(cfg, ['allowlist', 'global_allowlist_path'])
    active_detectors_list = cfg_safe_get(cfg, ['detectors', 'active'], None)
    
    if global_allowlist_path is None:
        global_allowlist_path = ""
    
    # Get DNSExfiltrator configurations to calculate total duration, and make
    # sure every config domain is routed to the simulated DNS hierarchy.
    # Optional benign-only window between peacetime and the tunnel windows.
    benign_seconds = benign_window_duration(cfg)
    tunnel_windows = tunnel_windows_planned(cfg)
    dnsexfil_configs = get_dnsexfiltrator_configs(cfg)
    # Only DNSExfiltrator domains are routed to the tunnel server (BIND configs).
    routed_domains = validate_dnsexfil_domains(dnsexfil_configs)
    # Every known tunnel domain: ground truth of the replay window, peacetime and
    # benign-only warnings, tunnel marking in the live metrics.
    tunneling_domains = replay_domains + [d for d in routed_domains if d not in replay_domains]
    if benign_seconds and any(c['name'] == BENIGN_WINDOW for c in dnsexfil_configs):
        raise ValueError(f"DNSExfiltrator configuration name '{BENIGN_WINDOW}' is reserved for the benign-only window")
    tunnel_names = [c['name'] for c in dnsexfil_configs] or (["wartime"] if tunnel_windows else [])
    report.set_planned_configs(([BENIGN_WINDOW] if benign_seconds else []) + tunnel_names)
    benign_group = [{"name": BENIGN_WINDOW, "group": "Benign-only", "kind": "benign_only",
                     "parameter": None, "value": None}] if benign_seconds else []
    report.update(mode="tunnel" if tunnel_windows else "benign_only", config_groups=benign_group + [
        {"name": c['name'], "group": c.get('_group', 'Baseline'), "kind": c.get('_kind', 'baseline'),
         "parameter": c.get('_parameter'), "value": c.get('_value')}
        for c in dnsexfil_configs
    ])
    report.update(timing={"wartime_duration": wartime_duration, "peacetime_duration": peacetime_duration,
                          "benign_only_duration": benign_seconds})
    
    # Calculate total estimated duration
    if dnsexfil_configs:
        total_estimated_duration = peacetime_duration + (wartime_duration * len(dnsexfil_configs))
    else:
        total_estimated_duration = peacetime_duration + (wartime_duration if tunnel_windows else 0)
    total_estimated_duration += benign_seconds
    
    banner("EXPERIMENT SETUP")
    logger.info(f"[+] Experiment: {cfg_safe_get(cfg, ['global', 'name'], '')}")
    logger.info(f"[+] Peacetime Duration: {format_duration(peacetime_duration)}")
    if benign_seconds:
        logger.info(f"[+] Benign-only window: {format_duration(benign_seconds)} "
                    + ("(before the tunnel windows)" if tunnel_windows else "(benign-only run: no tunnel windows)"))
        if not (cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False)
                or cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False)):
            logger.warning("[!] Benign-only window without benign or wildcard replay: only external DNS traffic is evaluated")
    
    if dnsexfil_configs:
        logger.info(f"[+] Wartime Duration (per config): {format_duration(wartime_duration)}")
        logger.info(f"[+] Number of DNSExfiltrator configs: {len(dnsexfil_configs)}")
    elif tunnel_windows:
        logger.info(f"[+] Wartime Duration: {format_duration(wartime_duration)}")
    
    logger.info(f"[+] Total Estimated Duration: {format_duration(total_estimated_duration)}")
    logger.info("="*60)

    results_file = report.config_file("wartime")
    
    # Ensure docker is stopped before cleaning up
    logger.info("[+] Ensuring clean state...")
    compose_down()
    
    # Clear old logfile. This is the only truncation: the collector container
    # is stopped at this point. During a run, phases read from byte offsets.
    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    if LOGFILE.exists():
        file_size = LOGFILE.stat().st_size / (1024*1024)
        logger.info(f"[+] Clearing old logfile ({file_size:.1f} MB)")
        LOGFILE.write_text("")
    else:
        LOGFILE.touch()

    write_docker_env(PROJECT_ROOT / (cfg_safe_get(cfg, ['traffic', 'pcap_path']) or './pcaps'))
    generate_all_configs(routed_domains, server_ip, public_resolver, CONFIG_TEMPLATE_DIR, DOCKER_PATH)
    
    logger.info("[+] Starting docker compose")
    compose_up("essential")
    time.sleep(5)
    start_monitoring(tunneling_domains)

    return (
        wartime_duration, peacetime_duration, tunneling_domains, server_ip,
        public_resolver, global_allowlist_path, active_detectors_list, results_file,
        dnsexfil_configs
    )


def run_peacetime_phase(
    peacetime_duration: float,
    tunneling_domains_set: set,
    global_allowlist_path: str,
    active_detectors_list: list,
    log_generator,
    cfg: dict,
):
    """Peacetime phase: Load detectors, run peacetime, generate allowlists.
    
    Returns:
        tuple: (active_detectors, global_allowlist, tunneling_domains_set, 
                alldomains, peace_logcount, start_timestamp)
    """
    # Load detectors and setup
    logger.info("[+] Loading detectors...")
    active_detectors = load_detectors(DETECTOR_PATH, active_detectors_list)
    logger.info(f"\n{len(active_detectors)} detectors loaded: {[type(d).__name__ for d in active_detectors]}\n")
    global_allowlist = load_global_allowlist(global_allowlist_path, base_dir=CONFIG_PATH.parent)
    
    start_timestamp = datetime.now()

    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])

    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    wildcard_pcap = cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
    wildcard_pps = cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])

    # Background replays start here only if there is a peacetime phase; with
    # peacetime disabled they are started by the wartime phase.
    if peacetime_duration:
        if benign_enabled:
            managed_replay_start("benign", benign_pcap, benign_pps)
        if wildcard_enabled:
            managed_replay_start("wildcard", wildcard_pcap, wildcard_pps)

        if wildcard_enabled or benign_enabled:
            logger.info(f"[+] Benign traffic started - running for {format_duration(peacetime_duration)}...")
        else:
            logger.info("[+] No benign traffic - waiting for external DNS traffic or wartime...")

    alldomains = set()
    peace_logcount = 0

    # PEACETIME
    if peacetime_duration:
        banner("PEACETIME PHASE - Building Allowlist")
        logger.info(f"[+] Peacetime started: Running for {format_duration(peacetime_duration)}...")
        set_phase("peacetime")
        
        peacetime_stop_event.clear()
        peacetime_done.clear()
        
        # Start timer that will signal peacetime to stop
        peace_timer = PhaseTimer(peacetime_stop_event, peacetime_duration).start()
        try:
            # Run peacetime (will block until stop event is set)
            peace_logcount, alldomains = run_peacetime(active_detectors, log_generator, tunneling_domains_set)
        finally:
            peace_timer.cancel()
        
        # run_peacetime() sets peacetime_done itself when it returns.
        if peacetime_done.is_set():
            logger.info("[+] Peacetime done!")

        logger.info("[+] Generating allowlists...")

    # Stop the peacetime replays and remember how far each pcap was replayed, so
    # wartime can resume right after the last peacetime packet (see
    # prepare_wartime_segment). Empty when there was no peacetime phase -> P=0 ->
    # wartime replays each pcap from packet 0.
    peacetime_packets = {}
    if peacetime_duration:
        managed_replay_stop_all()
        time.sleep(1)  # let tcpreplay flush its final "Actual: N packets" stats
        if benign_enabled:
            peacetime_packets["benign"] = managed_replay_packets_sent("benign")
        if wildcard_enabled:
            peacetime_packets["wildcard"] = managed_replay_packets_sent("wildcard")
        logger.info(f"[+] Peacetime replay stopped at (packets sent): {peacetime_packets}")

    return (
        active_detectors, global_allowlist, tunneling_domains_set,
        alldomains, peace_logcount, start_timestamp, peacetime_packets
    )


def _short_list(items, limit: int = 5) -> str:
    """Return up to ``limit`` items of a list, with a count of the rest."""
    items = sorted(items)
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


STOP_REASON_LABELS = {
    "transfer_complete": "ended: transfer complete",
    "all_detected": "ended: all tunnels detected",
    "timer": "ended: timer",
    "log_ended": "ended: log ended",
    "interrupted": "ended: interrupted",
    "user_skip": "ended: skipped from the dashboard",
    "user_stop": "ended: run stopped from the dashboard",
}


def show_results(results, config_name=None, peacetime_logcount=0, wartime_duration=None, stop_reason=None,
                 benign_only=False):
    """Log a compact results table for one wartime window.

    Full per-detector results (alarm lists, leakage, timing) are in the
    window's file under ``configs/``; the console shows the headline numbers
    and up to five missed and falsely flagged domains per detector. A
    benign-only window (``benign_only``) shows false-positive figures only.
    """
    if not results:
        logger.info("\n[!] No results to display")
        return

    title = f"RESULTS - {config_name}" if config_name else "RESULTS"
    details = []
    if peacetime_logcount > 0:
        details.append(f"peacetime lines: {peacetime_logcount}")
    if wartime_duration:
        details.append(f"wartime: {format_duration(wartime_duration)}")
    if stop_reason:
        details.append(STOP_REASON_LABELS.get(stop_reason, f"ended: {stop_reason}"))
    banner(title + (f"  ({', '.join(details)})" if details else ""), width=96)

    if benign_only:
        logger.info(f"{'Detector':<18} {'FPR':>10} {'FP':>6} {'TN':>8} {'FP/h':>8} {'Allowlist':>10} {'Runtime':>8}")
        logger.info("-" * 96)
        sorted_results = sorted(results, key=lambda r: (r.get('fpr', 0), r.get('detector_name', '')))
        for r in sorted_results:
            per_hour = r.get('fp_domains_per_hour')
            logger.info(
                f"{r.get('detector_name', 'Unknown')[:18]:<18} {r.get('fpr', 0):>10.6f} {r.get('fp', 0):>6} "
                f"{r.get('tn', 0):>8} {(f'{per_hour:.1f}' if per_hour is not None else '-'):>8} "
                f"{r.get('allowlist_size', 0):>10} {r.get('runtime', 0):>7.1f}s"
            )
        for r in sorted_results:
            if r.get('false_positives_list'):
                logger.info(f"  {r.get('detector_name')}: false alarms {_short_list(r['false_positives_list'])}")
        logger.info("(benign-only window: no tunnel traffic, every alarm is a false positive)")
        logger.info("")
        return

    logger.info(f"{'Detector':<18} {'Prec':>6} {'Recall':>6} {'F1':>6} {'FPR':>8} "
                f"{'TP':>4} {'FP':>5} {'FN':>4} {'Leak up':>11} {'Leak down':>11} {'Runtime':>8}")
    logger.info("-" * 96)
    sorted_results = sorted(results, key=lambda r: r.get('f1', 0), reverse=True)
    for r in sorted_results:
        logger.info(
            f"{r.get('detector_name', 'Unknown')[:18]:<18} {r.get('precision', 0):>6.3f} {r.get('recall', 0):>6.3f} "
            f"{r.get('f1', 0):>6.3f} {r.get('fpr', 0):>8.5f} {r.get('tp', 0):>4} {r.get('fp', 0):>5} {r.get('fn', 0):>4} "
            f"{fmt_bytes(r.get('traffic_volume_up_bytes', 0)):>11} {fmt_bytes(r.get('traffic_volume_down_bytes', 0)):>11} "
            f"{r.get('runtime', 0):>7.1f}s"
        )
    for r in sorted_results:
        missed = r.get('false_negatives_list') or []
        false_alarms = r.get('false_positives_list') or []
        if missed:
            logger.info(f"  {r.get('detector_name')}: missed {_short_list(missed)}")
        if false_alarms:
            logger.info(f"  {r.get('detector_name')}: false alarms {_short_list(false_alarms)}")
    logger.info("")


def log_run_summary(report) -> None:
    """Log one line per configuration with each detector's F1 score (FPR for the benign-only window)."""
    configs = report.state.get("configs", [])
    detectors = []
    for config in configs:
        for row in config.get("detectors", []):
            if row["detector"] not in detectors:
                detectors.append(row["detector"])
    state = report.state
    banner(f"RUN SUMMARY - {state.get('name')} ({state.get('status')})", width=96)
    if not configs:
        logger.info("No configuration finished.")
        return
    logger.info(f"{'Configuration':<28} {'Status':<12}" + "".join(f" {d[:10]:>10}" for d in detectors))
    logger.info("-" * 96)
    for config in configs:
        # The benign-only window has no tunnel traffic: its F1 is meaningless, show its FPR.
        key, fmt = ("fpr", ">10.6f") if config["name"] == BENIGN_WINDOW else ("f1", ">10.3f")
        values = {row["detector"]: row.get(key) for row in config.get("detectors", [])}
        cells = "".join(f" {values[d]:{fmt}}" if values.get(d) is not None else f" {'-':>10}" for d in detectors)
        logger.info(f"{config['name'][:28]:<28} {config['status']:<12}{cells}")
        if config.get("reason") and config["status"] != "completed":
            logger.info(f"  {config['reason']}")
    if detectors:
        logger.info(f"(values: F1 per detector; FPR for {BENIGN_WINDOW})"
                    if any(c["name"] == BENIGN_WINDOW for c in configs) else "(values: F1 per detector)")


def run_wartime_phase(
    wartime_duration: float,
    peacetime_duration: float,
    tunneling_domains_set: set,
    global_allowlist: set,
    active_detectors: list,
    alldomains: set,
    start_timestamp: datetime,
    server_ip: str,
    public_resolver: str,
    cfg: dict,
    results_file: Path,
    dnsexfil_configs: list = None,
    results_sink: list = None,
    peacetime_packets: dict = None
):
    """Wartime phase: Start tunnel traffic, run wartime, build and save results.

    Completed windows are appended to ``results_sink`` as soon as they finish,
    so the caller still has them after an interrupt. A window ended by Ctrl+C
    is evaluated, saved with status ``interrupted``, and the interrupt is then
    re-raised.
    """
    benign_seconds = benign_window_duration(cfg)
    tunnel_windows = tunnel_windows_planned(cfg)
    if not benign_seconds:
        banner("WARTIME PHASE")

    tunneling_enabled = bool(cfg_safe_get(cfg, ["traffic", "tunnel", "replay"], False))
    tunneling_pcap = cfg_safe_get(cfg, ["traffic", "tunnel", "pcap"], "")
    tunneling_pps = cfg_safe_get(cfg, ["traffic", "tunnel", "pps"])
    dnsexfil_enabled = cfg_safe_get(cfg, ['dnsexfiltrator', 'enabled'], False)
    stop_on_transfer = bool(cfg_safe_get(cfg, ['dnsexfiltrator', 'stop_on_transfer_complete'], True))

    all_results = results_sink if results_sink is not None else []

    # Benign/wildcard background traffic. These are started and stopped per
    # wartime window (managed_replay_*), each beginning at the packet after the
    # one peacetime stopped on: prepare_wartime_segment slices the already-shown
    # peacetime packets off the front once, here, and the window replays the
    # remaining segment. With no peacetime the segment is the whole pcap.
    peacetime_packets = peacetime_packets or {}
    host_pcap_dir = PROJECT_ROOT / (cfg_safe_get(cfg, ['traffic', 'pcap_path']) or './pcaps')

    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])
    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    wildcard_pcap = cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
    wildcard_pps = cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])

    benign_wartime_pcap = (
        prepare_wartime_segment("benign", benign_pcap, peacetime_packets.get("benign", 0), host_pcap_dir)
        if benign_enabled else benign_pcap
    )
    wildcard_wartime_pcap = (
        prepare_wartime_segment("wildcard", wildcard_pcap, peacetime_packets.get("wildcard", 0), host_pcap_dir)
        if wildcard_enabled else wildcard_pcap
    )

    def start_background_replays():
        """Start benign/wildcard for one wartime window, from the segment start."""
        if benign_enabled:
            managed_replay_start("benign", benign_wartime_pcap, benign_pps)
        if wildcard_enabled:
            managed_replay_start("wildcard", wildcard_wartime_pcap, wildcard_pps)

    # Window numbering for the dashboard: the benign-only window comes first.
    index_offset = 1 if benign_seconds else 0
    tunnel_window_count = (len(dnsexfil_configs) if dnsexfil_enabled and dnsexfil_configs
                           else (1 if tunnel_windows else 0))
    total_windows = index_offset + tunnel_window_count

    def run_single_window(name: str, duration: float, window_file: Path, benign: bool,
                          log_offset: int, index: int):
        """Run and save one window outside the DNSExfiltrator loop.

        Used for the benign-only window (``benign``: no tunnel traffic, every
        alarm is a false positive) and for the wartime window of replay mode
        or external tunnel traffic. Both see the same benign/wildcard segment.
        """
        if benign:
            logger.info(f"[+] Benign-only window started (no tunnel traffic): running for {format_duration(duration)}...")
        else:
            logger.info(f"[+] Wartime started: Running for {format_duration(duration)}...")
        set_phase("wartime", "benign only" if benign else "")

        # Fresh generator, starting where this window began in the log
        window_log_generator = readjson(str(LOGFILE), start_offset=log_offset)

        RUN_CONTROL.open_window()
        war_timer = PhaseTimer(wartime_stop_event, duration).start()
        REPORT.update(current={"name": name, "index": index, "total": total_windows,
                               "started": datetime.now().isoformat(timespec="seconds"),
                               "window_started": datetime.now().isoformat(timespec="seconds"),
                               **({"parameters": {"traffic": "benign and wildcard only (no tunnel)"}} if benign else {})})

        # Start benign/wildcard for this window, from the wartime segment start.
        start_background_replays()
        window_start = datetime.now()

        # Run the window (blocks until its stop event is set or all tunnels are
        # detected). The TN/FPR universe is the set of domains seen in this window only.
        try:
            results, logcount, tunnel_count, seen_tunnels, window_domains, counts = run_wartime(
                active_detectors, window_log_generator, tunneling_domains_set, global_allowlist,
                expansion_factor=float(cfg_safe_get(cfg, ['traffic', 'tunnel', 'expansion_factor'], 1) or 1),
            )
        finally:
            war_timer.cancel()
            RUN_CONTROL.close_window()
            managed_replay_stop_all()
        set_current()
        alldomains.update(window_domains)

        end_timestamp = datetime.now()
        counts["window_seconds"] = round((end_timestamp - window_start).total_seconds(), 1)
        if benign:
            add_false_alarm_rates(results, counts["window_seconds"])
            if counts.get("tunnel_queries"):
                logger.warning(f"[!] Benign-only window saw {counts['tunnel_queries']} queries to tunneling domains; "
                               "they are evaluated as tunnel traffic")

        all_results.append({
            'config_name': name if benign else None,
            'results': results,
            'logcount': logcount,
            'tunnel_count': tunnel_count
        })
        show_results(results, config_name=name if benign else None, wartime_duration=duration,
                     stop_reason=counts.get("stop_reason"), benign_only=benign)
        build_and_save_metadata(
            results_file=window_file,
            results=results,
            logcount=logcount,
            tunnel_count=tunnel_count,
            seen_tunnels=seen_tunnels,
            alldomains=window_domains,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            wartime_duration=duration,
            peacetime_duration=peacetime_duration,
            tunneling_domains_set=tunneling_domains_set,
            tunneling_enabled=tunneling_enabled and not benign,
            tunneling_pcap=tunneling_pcap,
            tunneling_pps=tunneling_pps,
            server_ip=server_ip,
            public_resolver=public_resolver,
            cfg=cfg,
            counts=counts,
            config_name=name,
            wartime_end=wartime_end_info(counts),
            status="interrupted" if counts.get("interrupted") or counts.get("stop_reason") in USER_END_REASONS else "completed",
            status_reason=("Ctrl+C during wartime; partial window" if counts.get("interrupted")
                           else USER_END_REASONS.get(counts.get("stop_reason"), ""))
        )
        if counts.get("interrupted"):
            raise KeyboardInterrupt

    # Benign-only window (optional): peacetime -> benign-only -> tunnel windows.
    if benign_seconds:
        banner("BENIGN-ONLY WINDOW")
        if RUN_CONTROL.stop_requested.is_set():
            save_status_result(cfg, BENIGN_WINDOW, "skipped", USER_END_REASONS["user_stop"])
        else:
            # Behave like the tunnel windows that follow: every DNSExfiltrator
            # configuration starts from a reset detector (allowlists kept), the
            # replay-mode window continues from peacetime.
            if dnsexfil_enabled and dnsexfil_configs:
                for detector in active_detectors:
                    detector.reset()
            run_single_window(BENIGN_WINDOW, benign_seconds, get_report(cfg).config_file(BENIGN_WINDOW),
                              True, log_end_offset(LOGFILE), 1)
            # Alarms and counters of the benign-only window must not carry over
            # into the tunnel window; detector state continues like live traffic.
            for detector in active_detectors:
                detector.reset(reset_state=False)
        if not tunnel_windows:
            return alldomains, all_results
        banner("WARTIME PHASE")

    # Never truncate the log while the collector writes to it: record where
    # wartime starts and read only from this offset.
    wartime_offset = log_end_offset(LOGFILE)

    # Start tunnel traffic if enabled and DNSExfiltrator is not
    if tunneling_enabled and not dnsexfil_enabled:
        if start_replay("tunnel", tunneling_pcap, tunneling_pps):
            logger.info(f"[+] Tunnel replay started - running for {format_duration(wartime_duration)}...")
    
    # Configurations requested by the user; each one gets a results file,
    # also when it is skipped.
    requested_configs = list(dnsexfil_configs or [])

    if RUN_CONTROL.stop_requested.is_set():
        for skipped in (requested_configs if dnsexfil_enabled and requested_configs else [{'name': 'wartime'}]):
            save_status_result(cfg, skipped.get('name', 'config'), "skipped", USER_END_REASONS["user_stop"],
                               dnsexfil_config=skipped if dnsexfil_enabled else None)
        return alldomains, all_results

    # Handle DNSExfiltrator configurations sequentially
    if dnsexfil_enabled and dnsexfil_configs:
        # Verify resolver is running and accessible before starting DNSExfiltrator
        # DNSExfiltrator client needs to connect to resolver at 172.16.0.2
        def container_exists(container_name: str) -> bool:
            """Check if a container exists (regardless of running state)."""
            try:
                subprocess.run(
                    ["docker", "inspect", container_name],
                    capture_output=True, text=True, check=True
                )
                return True
            except Exception:
                return False
        
        def container_is_running(container_name: str) -> bool:
            """Check if a container is running."""
            try:
                result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                    capture_output=True, text=True, check=True
                )
                return result.stdout.strip() == "true"
            except Exception as e:
                logger.debug(f"[!] Error checking container {container_name}: {e}")
                return False
        
        # Check resolver container
        if not container_is_running("resolver"):
            logger.error("[!] Resolver container is not running!")
            logger.error("[!] DNSExfiltrator needs the resolver at 172.16.0.2")
            logger.error("[!] Try running: docker compose -f docker-compose.yml --profile essential up -d")
            dnsexfil_configs = []
        else:
            # Check if resolver is listening on port 53 or if BIND9 is running
            # Use ps aux to check for BIND9 process (more reliable than netstat/ss which may not be installed)
            try:
                check_cmd = ["docker", "exec", "resolver", "ps", "aux"]
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, check=False)
                if check_result.returncode == 0:
                    if "named" not in check_result.stdout and "bind9" not in check_result.stdout.lower():
                        logger.warning("[!] BIND9 process not found in resolver, but continuing anyway")
                        # Don't fail here, the connectivity test will catch it
                else:
                    logger.warning("[!] Could not check resolver processes")
            except Exception as e:
                logger.warning(f"[!] Could not check resolver: {e}. Continuing with connectivity test.")
            
            # Start the dnsexfiltrator containers once
            logger.info("[+] Starting DNSExfiltrator containers...")
            try:
                logger.info(f"[+] Running: docker compose -f {DOCKER_COMPOSE_FILE} --profile dnsexfiltrator up -d")
                compose_up("dnsexfiltrator")
                time.sleep(5)
                
                # List containers to verify they were created
                try:
                    list_cmd = ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}"]
                    list_result = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
                    logger.info(f"[+] Containers after compose up:\n{list_result.stdout}")
                except Exception:
                    pass
                
                # Wait for containers to be fully ready
                logger.info("[+] Waiting for DNSExfiltrator containers to be ready...")
                for i in range(10):  # Try for 10 seconds
                    if container_exists("dnsexfiltrator-server") and container_exists("dnsexfiltrator-client"):
                        logger.info(f"[+] DNSExfiltrator containers are ready after {i+1}s")
                        break
                    time.sleep(1)
                else:
                    logger.error("[!] DNSExfiltrator containers did not start within 10 seconds")
                    dnsexfil_configs = []
            except Exception as e:
                logger.error(f"[!] Failed to start DNSExfiltrator containers: {e}")
                dnsexfil_configs = []
            
            # Verify containers exist and are running
            server_exists = container_exists("dnsexfiltrator-server")
            client_exists = container_exists("dnsexfiltrator-client")
            server_running = container_is_running("dnsexfiltrator-server") if server_exists else False
            client_running = container_is_running("dnsexfiltrator-client") if client_exists else False
            
            # If containers don't exist, try to list all containers for debugging
            if not server_exists or not client_exists:
                try:
                    list_cmd = ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}"]
                    list_result = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
                    logger.error(f"[!] Current containers:\n{list_result.stdout}")
                except Exception:
                    pass
            
            if not server_exists or not client_exists:
                logger.error("[!] DNSExfiltrator containers do not exist!")
                logger.error(f"[!] Server exists: {server_exists}, Client exists: {client_exists}")
                dnsexfil_configs = []
            elif not server_running or not client_running:
                logger.error("[!] DNSExfiltrator containers not running!")
                logger.error(f"[!] Server running: {server_running}, Client running: {client_running}")
                dnsexfil_configs = []
            else:
                logger.info("[+] DNSExfiltrator containers are running")
                
                # Check if client can reach resolver
                connectivity_ok = True
                try:
                    # Try to resolve via the resolver from the client container
                    test_cmd = ["docker", "exec", "dnsexfiltrator-client", "dig", "@172.16.0.2", "example.com", "+timeout=2", "+tries=1"]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, check=False, timeout=5)
                    if "connection timed out" in test_result.stdout or "no servers could be reached" in test_result.stdout:
                        logger.error("[!] DNSExfiltrator client cannot reach resolver at 172.16.0.2!")
                        logger.error(f"[!] Dig output: {test_result.stdout[-200:]}")
                        connectivity_ok = False
                    else:
                        logger.info("[+] Connectivity check: DNSExfiltrator client can reach resolver")
                except Exception as e:
                    logger.warning(f"[!] Could not verify connectivity: {e}")
                    connectivity_ok = True  # Assume ok if we can't check
                
                if not connectivity_ok:
                    dnsexfil_configs = []
        # Track domains seen across all configs (initialized before conditional to avoid UnboundLocalError)
        all_seen_domains = set()

        if not dnsexfil_configs:
            logger.warning("[!] No DNSExfiltrator configurations will be run")
            for skipped in requested_configs:
                save_status_result(cfg, skipped.get('name', 'config'), "skipped",
                                   "DNSExfiltrator readiness checks failed (resolver, containers or connectivity); see console log",
                                   dnsexfil_config=skipped)
        else:
            logger.info(f"[+] Running {len(dnsexfil_configs)} DNSExfiltrator configurations sequentially")
            logger.info("[+] Windows end early once the file has arrived" if stop_on_transfer
                        else "[+] Windows run their full duration (stop_on_transfer_complete: false)")
            
            # Prepare directories
            server_volume_dir = PROJECT_ROOT / "docker/dnsexfiltrator-server/volume"
            server_volume_dir.mkdir(parents=True, exist_ok=True)
            client_data_dir = PROJECT_ROOT / "docker/dnsexfiltrator-client/data"
            client_data_dir.mkdir(parents=True, exist_ok=True)
            
            
            # Run each configuration sequentially
        for config_idx, config in enumerate(dnsexfil_configs):
            config_name = config.get('name', f'config_{config_idx}')
            if RUN_CONTROL.stop_requested.is_set():
                save_status_result(cfg, config_name, "skipped", USER_END_REASONS["user_stop"], dnsexfil_config=config)
                continue
            
            # Check if containers still exist at the start of each config
            server_exists_at_start = container_exists("dnsexfiltrator-server")
            client_exists_at_start = container_exists("dnsexfiltrator-client")
            if not server_exists_at_start or not client_exists_at_start:
                logger.warning(f"[!] WARNING: Containers missing at start of config {config_name}!")
                logger.warning(f"[!] Server exists: {server_exists_at_start}, Client exists: {client_exists_at_start}")
                # Try to recreate containers
                try:
                    logger.info("[+] Attempting to recreate DNSExfiltrator containers...")
                    compose_up("dnsexfiltrator")
                    time.sleep(5)
                except Exception as e:
                    logger.error(f"[!] Failed to recreate containers: {e}")
                    save_status_result(cfg, config_name, "failed", f"could not recreate DNSExfiltrator containers: {e}", dnsexfil_config=config)
                    continue
            
            domains = config.get('domains', [])
            password = config.get('password', 'tunframe')
            filepath = config.get('file', '/data/synthetic_cc_data_100.csv')
            
            logger.info(f"\n[+] --- Running DNSExfiltrator configuration: {config_name} ({config_idx + 1}/{len(dnsexfil_configs)}) ---")
            set_phase("wartime", config_name)
            parameters = {k: v for k, v in config.items() if k != 'name' and not k.startswith('_')}
            # Show the factor actually used; None in the config means "derive from encoding".
            factor = round(config_expansion_factor(config), 3)
            parameters['expansion_factor'] = (factor if config.get('expansion_factor') is not None
                                              else f"{factor:g} (from {config.get('encoding', '')})")
            REPORT.update(current={"name": config_name, "index": index_offset + config_idx + 1, "total": total_windows,
                                   "started": datetime.now().isoformat(timespec="seconds"), "window_started": None,
                                   "parameters": parameters})
            
            # The configuration's own domains are its ground truth (validated non-empty at setup)
            config_tunneling_domains_set = {normalize_name(d) for d in domains}
            
            # Update domain file for this configuration (single file)
            domains_file = server_volume_dir / "domains.txt"
            domains_file.write_text("\n".join(domains))
            
            # Update client domains file
            client_domains_file = client_data_dir / "domains.txt"
            client_domains_file.write_text("\n".join(domains))
            
            # Stop any existing server and client processes (if containers exist)
            if container_exists("dnsexfiltrator-server"):
                docker_exec("dnsexfiltrator-server", "pkill", "-f", "dnsExfiltrator.py", check=False)
            else:
                logger.warning("[!] dnsexfiltrator-server container does not exist, skipping pkill")
            
            if container_exists("dnsexfiltrator-client"):
                docker_exec("dnsexfiltrator-client", "pkill", "-f", "DNSExfiltrator.exe", check=False)
            else:
                logger.warning("[!] dnsexfiltrator-client container does not exist, skipping pkill")
            
            time.sleep(1)

            # Every configuration must reach its own server: drop answers the
            # resolver chain cached for the previous configuration's queries.
            if flush_tunnel_cache(domains):
                logger.info(f"[+] Flushed cached answers for {', '.join(domains)}")

            # Record where this configuration starts in the log BEFORE starting
            # DNSExfiltrator; the log is never truncated while the collector runs.
            config_offset = log_end_offset(LOGFILE)
            server_log_offset = log_end_offset(SERVER_LOG)
            set_current(server_log_offset=server_log_offset, client_log_offset=log_end_offset(CLIENT_LOG))
            watch_exfil(server_log_offset)
            
            # Reset state for this configuration - create fresh log generator
            config_start_timestamp = datetime.now()
            config_log_generator = readjson(str(LOGFILE), start_offset=config_offset)
            
            # Start server for this configuration
            logger.info(f"[+] Starting DNSExfiltrator server with {len(domains)} domains")
            result = docker_exec_bg_logged(
                "dnsexfiltrator-server", "/app/logs/server.log",
                "python3", "-u", "/app/dnsExfiltrator.py",
                "-f", "/app/domains.txt",
                "-p", password,
                "-o", "/app/outputfile",
            )
            if result.returncode != 0:
                logger.error(f"[!] Failed to start server: {result.stderr}")
                if result.stdout:
                    logger.error(f"[!] Stdout: {result.stdout}")
                # Try running without -d to see the error
                try:
                    test_cmd = [
                        "docker", "exec", "dnsexfiltrator-server",
                        "python3", "-u", "/app/dnsExfiltrator.py",
                        "-f", "/app/domains.txt",
                        "-p", password,
                        "-o", "/app/outputfile",
                    ]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    logger.error(f"[!] Server test output: {test_result.stdout}")
                    logger.error(f"[!] Server test error: {test_result.stderr}")
                except Exception as e:
                    logger.error(f"[!] Server test failed: {e}")
            else:
                # Get the actual process PID from the container
                try:
                    pid_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-server", "pgrep", "-f", "dnsExfiltrator.py"],
                        capture_output=True, text=True, check=False
                    )
                    pid = pid_check.stdout.strip() if pid_check.stdout.strip() else "unknown"
                except Exception:
                    pid = "unknown"
                logger.info(f"  Server started (PID: {pid})")
            
            # Verify server is running
            time.sleep(1)
            if not check_process_running("dnsexfiltrator-server", "dnsExfiltrator.py"):
                logger.error("[!] DNSExfiltrator server failed to start or crashed!")
                logger.error(f"[!] Skipping configuration: {config_name}")
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator server failed to start or crashed", dnsexfil_config=config)
                continue
            
            # The window (timer and background traffic) starts before the
            # one-shot client, so benign/wildcard traffic overlaps the
            # exfiltration instead of following it.
            RUN_CONTROL.open_window()
            war_timer = PhaseTimer(wartime_stop_event, wartime_duration).start()
            set_current(window_started=datetime.now().isoformat(timespec="seconds"))
            transfer_complete_event.clear()
            transfer_watcher = (
                TransferWatcher(SERVER_LOG, server_log_offset, transfer_complete_event).start()
                if stop_on_transfer else None
            )
            start_background_replays()

            logger.info(f"[+] Starting DNSExfiltrator client: {filepath}")
            
            throttle = config.get('throttle')
            throttle_random = config.get('throttle_random')
            label_size = config.get('label_max_size')
            encoding = config.get('encoding')
            dil = config.get('dilution')
            
            # Ensure the data file is in the client data directory
            # filepath can be absolute or just a filename
            if filepath.startswith('/data/'):
                # Absolute path in container's /data directory - use as-is
                client_filepath = filepath[6:]  # Remove '/data/' prefix for relative path in container
            elif filepath.startswith('/'):
                # Absolute path on host - copy to client data dir
                src_path = Path(filepath)
                if src_path.exists():
                    dest_path = client_data_dir / src_path.name
                    if not dest_path.exists():
                        shutil.copy2(src_path, dest_path)
                        logger.info(f"[+] Copied {src_path.name} to client data directory")
                    client_filepath = src_path.name
                else:
                    logger.warning(f"[!] File not found on host: {filepath}")
                    client_filepath = Path(filepath).name
            else:
                # Relative path - assume it's already in data directory or will be handled
                client_filepath = filepath
            
            # Use absolute paths in container
            # DNSExfiltrator.exe is built in /app by Dockerfile
            cmd = [
                "mono", "/app/DNSExfiltrator.exe",
                f"/data/{client_filepath}",
                "/data/domains.txt",
                password,
                "s=172.16.0.2",
            ]
            
            if throttle is not None:
                cmd.append(f"t={throttle}")
            if throttle_random is not None:
                cmd.append(f"tr={throttle_random}")
            if label_size is not None:
                cmd.append(f"l={label_size}")
            if encoding is not None:
                cmd.append(f"e={encoding}")
            if dil is not None:
                cmd.append(f"dil={dil}")
            

            result = docker_exec_bg_logged(
                "dnsexfiltrator-client", "/data/logs/client.log", *cmd, pty=True,
            )
            if result.returncode != 0:
                logger.error(f"[!] Failed to start client: {result.stderr}")
                if result.stdout:
                    logger.error(f"[!] Stdout: {result.stdout}")
                
                # Check if executable exists
                try:
                    exe_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", "/app/DNSExfiltrator.exe"],
                        capture_output=True, text=True, check=False
                    )
                    if exe_check.returncode != 0:
                        logger.error("[!] DNSExfiltrator.exe not found at /app/DNSExfiltrator.exe")
                        logger.error(f"[!] Executable check: {exe_check.stderr}")
                    else:
                        logger.info(f"[+] DNSExfiltrator.exe exists: {exe_check.stdout.strip()}")
                except Exception:
                    pass
                
                # Check if file exists in container
                try:
                    file_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", f"/data/{client_filepath}"],
                        capture_output=True, text=True, check=False
                    )
                    if file_check.returncode != 0:
                        logger.error(f"[!] File /data/{client_filepath} not found in container!")
                        logger.error(f"[!] Container file check: {file_check.stderr}")
                        # List what IS in /data
                        try:
                            ls_result = subprocess.run(
                                ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", "/data/"],
                                capture_output=True, text=True, check=False
                            )
                            if ls_result.returncode == 0:
                                logger.error(f"[!] Files in /data/: {ls_result.stdout}")
                        except Exception:
                            pass
                except Exception:
                    pass
                
                # Try running without -d to see the error
                try:
                    test_cmd = [
                        "docker", "exec", "dnsexfiltrator-client",
                        "mono", "/app/DNSExfiltrator.exe",
                        f"/data/{client_filepath}",
                        "/data/domains.txt",
                        password,
                        "s=172.16.0.2",
                    ]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    logger.error(f"[!] Client test output: {test_result.stdout[:500]}")
                    logger.error(f"[!] Client test error: {test_result.stderr[:500]}")
                except Exception as e:
                    logger.error(f"[!] Client test failed: {e}")
            else:
                # Get the actual process PID from the container
                try:
                    pid_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "pgrep", "-f", "DNSExfiltrator.exe"],
                        capture_output=True, text=True, check=False
                    )
                    pid = pid_check.stdout.strip() if pid_check.stdout.strip() else "unknown"
                except Exception:
                    pid = "unknown"
                logger.info(f"  Client started (PID: {pid})")
            
            # Verify the configuration actually produced tunnel traffic.
            #
            # The client is a one-shot exfiltration: for a small input file it
            # finishes in ~1s, before this gate runs. "Client no longer running"
            # therefore does NOT mean it crashed, so we must not skip on that
            # alone. A config is healthy if the client is still sending OR it
            # already put tunnel traffic in the log; it is genuinely broken only
            # when the client is gone AND no tunnel traffic appeared (bad exe,
            # unreachable resolver, server not answering, ...).
            time.sleep(1)
            client_running = check_process_running(
                "dnsexfiltrator-client", "DNSExfiltrator.exe", expect_running=False
            )
            if not client_running:
                # Not running: confirm it finished successfully rather than
                # crashing by looking for its tunnel traffic in the log. This
                # also makes the gate robust when the client container lacks
                # procps (no `ps`), where the liveness check can never succeed.
                if not tunnel_traffic_seen(config_offset, config_tunneling_domains_set, settle_seconds=3.0):
                    logger.error("[!] DNSExfiltrator client is not running and produced no tunnel traffic!")
                    logger.error(f"[!] Skipping configuration: {config_name}")
                    war_timer.cancel()
                    RUN_CONTROL.close_window()
                    if transfer_watcher:
                        transfer_watcher.cancel()
                    managed_replay_stop_all()
                    save_status_result(cfg, config_name, "skipped", "DNSExfiltrator client produced no tunnel traffic", dnsexfil_config=config)
                    continue
                logger.info("[+] Client already finished; tunnel traffic captured in log")
            else:
                logger.info("[+] DNSExfiltrator client is running")

            # The server must stay up to ACK the exfiltration. Unlike the
            # client it is not one-shot, so its liveness is a valid check.
            if not check_process_running("dnsexfiltrator-server", "dnsExfiltrator.py"):
                logger.error(f"[!] DNSExfiltrator server is not running! Skipping config: {config_name}")
                war_timer.cancel()
                RUN_CONTROL.close_window()
                if transfer_watcher:
                    transfer_watcher.cancel()
                managed_replay_stop_all()
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator server stopped before wartime", dnsexfil_config=config)
                continue

            logger.info("[+] DNSExfiltrator server and client started; tunnel traffic reached the resolver")
            
            # Start every configuration from a clean detector state: alarms,
            # counters, runtime and leakage of earlier configs must not carry
            # over (the allowlist from peacetime is kept).
            for detector in active_detectors:
                detector.reset()

            logger.info(f"[+] Wartime started for config {config_name}: Running for {format_duration(wartime_duration)}...")

            # Run wartime detection for this specific configuration with clean state
            try:
                results, logcount, tunnel_count, seen_tunnels, config_alldomains, counts = run_wartime(
                    active_detectors, config_log_generator, config_tunneling_domains_set, global_allowlist,
                    expansion_factor=config_expansion_factor(config),
                    transfer_event=transfer_complete_event if stop_on_transfer else None,
                    payload=exfil_payload_for(config),
                )
            finally:
                war_timer.cancel()
                RUN_CONTROL.close_window()
                if transfer_watcher:
                    transfer_watcher.cancel()
                # Stop this window's background replay so the next config starts
                # it again from the same segment packet.
                managed_replay_stop_all()
            
            # Store results for this configuration
            all_results.append({
                'config_name': config_name,
                'results': results,
                'logcount': logcount,
                'tunnel_count': tunnel_count
            })
            
            # Update all seen domains
            all_seen_domains.update(config_alldomains)
            
            # Show results for this configuration
            show_results(results, config_name=config_name, wartime_duration=wartime_duration,
                         stop_reason=counts.get("stop_reason"))
            
            # Build metadata and save results for this configuration
            config_end_timestamp = datetime.now()
            user_end = USER_END_REASONS.get(counts.get("stop_reason"))
            transfer_incomplete = bool(transfer_watcher) and transfer_watcher.completed_after is None and not user_end
            if transfer_incomplete and not counts.get("interrupted"):
                logger.warning(f"[!] {config_name}: the server never reported the file as saved - "
                               "the exfiltration did not complete (see the server and client logs)")
            
            # Net volume: the tools' own numbers next to the decoded DNS traffic.
            counts["exfil_file_bytes_server"] = server_reported_file_size(server_log_offset)
            source = client_data_dir / Path(client_filepath).name
            if source.is_file():
                counts["source_file_bytes"] = source.stat().st_size
            counts["net_volume_check"] = net_volume_check(
                counts, transfer_watcher.completed_after is not None if transfer_watcher else None)
            if counts["net_volume_check"] == "mismatch":
                logger.warning(f"[!] {config_name}: decoded tunnel data ({counts.get('tunnel_net_up_bytes')} B) does not "
                               f"match the file size the tool reported ({counts.get('exfil_file_bytes') or counts.get('exfil_file_bytes_server')} B)")

            # Save per-config results
            config_results_file = REPORT.config_file(config_name)
            build_and_save_metadata(
                results_file=config_results_file,
                results=results,
                logcount=logcount,
                tunnel_count=tunnel_count,
                seen_tunnels=seen_tunnels,
                alldomains=config_alldomains,
                start_timestamp=config_start_timestamp,
                end_timestamp=config_end_timestamp,
                wartime_duration=wartime_duration,
                peacetime_duration=peacetime_duration,
                tunneling_domains_set=config_tunneling_domains_set,
                tunneling_enabled=tunneling_enabled,
                tunneling_pcap=tunneling_pcap,
                tunneling_pps=tunneling_pps,
                server_ip=server_ip,
                public_resolver=public_resolver,
                cfg=cfg,
                counts=counts,
                dnsexfil_config=dict(config, expansion_factor_used=config_expansion_factor(config)),
                config_name=config_name,
                wartime_end=wartime_end_info(counts, transfer_watcher),
                status="interrupted" if counts.get("interrupted") or user_end else "completed",
                status_reason=("Ctrl+C during wartime; partial window" if counts.get("interrupted")
                               else user_end if user_end
                               else "exfiltration did not complete within the window" if transfer_incomplete
                               else "")
            )
            if counts.get("interrupted"):
                raise KeyboardInterrupt
            
            logger.info(f"[+] Completed configuration: {config_name}")
            
            # Check if traffic was detected
            if logcount == 0:
                logger.warning(f"[!] WARNING: No DNS traffic detected for config {config_name}!")
                logger.warning("[!] This likely means DNSExfiltrator failed to generate traffic")
                logger.warning("[!] Check: DNSExfiltrator processes, network connectivity, DNS resolver")
            elif tunnel_count == 0:
                logger.warning(f"[!] WARNING: No tunneling traffic detected for config {config_name}!")
                logger.warning(f"[!] DNS traffic was seen ({logcount} lines) but no tunneling domains were detected")
                logger.warning(f"[!] Expected tunneling domains: {config_tunneling_domains_set}")
                logger.warning(f"[!] Detected domains: {seen_tunnels}")
            
            # Stop client and server for this configuration
            docker_exec("dnsexfiltrator-server", "pkill", "-f", "dnsExfiltrator.py", check=False)
            docker_exec("dnsexfiltrator-client", "pkill", "-f", "DNSExfiltrator.exe", check=False)
            time.sleep(1)
        
        watch_exfil(None)
        set_current()

        # Update the alldomains with all domains seen across all configs
        alldomains.update(all_seen_domains)
        
        logger.info(f"[+] Completed all {len(dnsexfil_configs)} DNSExfiltrator configurations")
    else:
        # Standard wartime without DNSExfiltrator (replay mode or external traffic)
        run_single_window("wartime", wartime_duration, results_file, False, wartime_offset, index_offset + 1)

    return alldomains, all_results


def finalize_run_report(status: str, reason: str = "") -> None:
    """Close the run report: final status, summary, charts and report.html."""
    if REPORT is None:
        return
    stop_monitoring()
    REPORT.finish(status, reason)
    log_run_summary(REPORT)
    try:
        report_html = build_report(REPORT.dir)
        logger.info(f"[+] Report: {report_html}")
    except Exception as e:
        logger.warning(f"[!] Could not build report.html: {e}")
    logger.info(f"[+] Run directory: {REPORT.dir}")
    close_run_report()


def _show_partial_results(all_experiment_results: list, peace_logcount: int, wartime_duration) -> None:
    """Print the windows that finished before the run was aborted."""
    if not all_experiment_results:
        return
    logger.info("\n[+] Showing partial results before exit:")
    for result_entry in all_experiment_results:
        show_results(
            result_entry['results'],
            config_name=result_entry.get('config_name'),
            peacetime_logcount=peace_logcount,
            wartime_duration=wartime_duration,
            benign_only=result_entry.get('config_name') == BENIGN_WINDOW,
        )


def main():
    global RUN_CONTROL
    cfg = load_config(CONFIG_PATH)
    RUN_CONTROL = RunControl()
    
    # Reset events
    peacetime_stop_event.clear()
    peacetime_done.clear()
    wartime_stop_event.clear()
    
    all_experiment_results = []
    peace_logcount = 0
    wartime_duration = None
    run_status, run_reason = "failed", "aborted"
    
    try:
        # Run setup phase
        (
            wartime_duration, peacetime_duration, tunneling_domains, server_ip,
            public_resolver, global_allowlist_path, active_detectors_list, results_file,
            dnsexfil_configs
        ) = run_setup(cfg)
        
        tunneling_domains_set = {normalize_name(d) for d in tunneling_domains}
        
        # Create log generator
        log_generator = readjson(str(LOGFILE), start_offset=log_end_offset(LOGFILE))
        
        # Run peacetime phase
        (
            active_detectors, global_allowlist, tunneling_domains_set,
            alldomains, peace_logcount, start_timestamp, peacetime_packets
        ) = run_peacetime_phase(
            peacetime_duration, tunneling_domains_set, global_allowlist_path,
            active_detectors_list, log_generator, cfg
        )

        generate_allowlists(active_detectors, global_allowlist)


        # Run wartime phase(s)
        alldomains, _ = run_wartime_phase(
            wartime_duration, peacetime_duration, tunneling_domains_set, global_allowlist,
            active_detectors, alldomains, start_timestamp,
            server_ip, public_resolver, cfg, results_file, dnsexfil_configs,
            results_sink=all_experiment_results, peacetime_packets=peacetime_packets
        )
        run_status, run_reason = (("interrupted", "stopped from the dashboard")
                                  if RUN_CONTROL.stop_requested.is_set() else ("completed", ""))

    except KeyboardInterrupt:
        logger.info("\n[!] Interrupted by user - shutting down...")
        _show_partial_results(all_experiment_results, peace_logcount, wartime_duration)
        run_status, run_reason = "interrupted", "Ctrl+C"

    except Exception as e:
        logger.error(f"[!] Error: {e}", exc_info=True)
        _show_partial_results(all_experiment_results, peace_logcount, wartime_duration)
        run_status, run_reason = "failed", str(e)

    finally:
        peacetime_stop_event.set()
        wartime_stop_event.set()
        compose_down()
        finalize_run_report(run_status, run_reason)


if __name__ == "__main__":
    main()
